"""Explicit hosted-Linux real browser gate; imports perform no I/O.

Only generated credentials and two owned tmpfs PostgreSQL containers are used.
Production launchers, credential discovery and their fixed DB targets are unused.
"""

import argparse
from contextlib import contextmanager, ExitStack
from dataclasses import dataclass
from datetime import timedelta
import hashlib
import json
import logging
import os
from pathlib import Path
import queue
import re
import secrets
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from urllib.request import build_opener, ProxyHandler
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import psycopg
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from pydantic import SecretStr
import uvicorn

from backend.crypto.credential_protocol import b64decode, b64encode, canonical_manifest, verify_manifest
from backend.ra.credential_recovery import CredentialRecovery
from backend.ra.credential_runtime import create_credential_app
from backend.ra.credential_service import CredentialIssuanceService
from backend.ra.credential_signer import LocalCIRCLSigner
from backend.ra.election_catalogue import ElectionCatalogue
from backend.ra.postgres_credential_store import PostgreSQLCredentialStore
from backend.voting.ballot_service import BallotService
from backend.voting.local_launcher import create_voting_app
from backend.voting.postgres_ballot_store import PostgreSQLBallotStore
from scripts import ra_gate2_ci as ra_ci, voting_postgres_ci as vote_ci
from scripts import ra_credential_disposable_integration as ra_db
from scripts import voting_disposable_integration as vote_db
from scripts.ra_demo_db_test_support import database_factory, synthetic_environment, check

SCENARIOS = ("accepted", "response_loss", "closed_first")
EVENTS = frozenset({"catalogue", "prepared", "issuance_response_lost", "issued",
    "before_submit_close", "committed_response_lost", "accepted", "recovered",
    "security_checks", "close_after_accept", "closed_recovery", "rejected_closed"})
BROWSER_DIAGNOSTICS = frozenset({"anonymous_navigation", "anonymous_ready", "submission_triggered",
    "voting_request_intercepted", "voting_forward_completed", "voting_response_loss_injected"})
HTTP_STATUSES = frozenset({200,201,204,400,401,403,404,409,413,415,422,429,500,502,503,504})
STAGES = EVENTS | BROWSER_DIAGNOSTICS | {"preflight", "provision", "migrations", "seed", "services", "browser", "acl", "cleanup", "teardown"}


def require_ci():
    # Existing gate checks reject local platforms, remote Docker endpoints and PG*.
    directory = ra_ci.require_ci()
    vote_ci.require_ci()
    check(not any(k.startswith(("RA_DEMO_", "VOTING_DEMO_", "VITE_")) for k in os.environ),
          "Inherited service configuration refused")
    check(not directory.is_relative_to(ROOT) and not ROOT.is_relative_to(directory),
          "Runner temp must be separate from source checkout")
    return directory


def failure(stage, error):
    stage = stage if stage in STAGES else "preflight"
    category = "database_error" if isinstance(error, psycopg.Error) else (
        "assertion_error" if isinstance(error, AssertionError) else
        "timeout_error" if isinstance(error, (TimeoutError, queue.Empty)) else "unexpected_error")
    root = getattr(error, "orig", None) or error
    state = getattr(root, "sqlstate", None)
    state = state if isinstance(state, str) and re.fullmatch(r"[0-9A-Z]{5}", state) else "unavailable"
    status = getattr(error,"http_status",None)
    suffix = (" http_status="+str(status) if stage in BROWSER_DIAGNOSTICS
        and (type(status) is int and status in HTTP_STATUSES or status == "unavailable") else "")
    return f"FAIL: real_voting_e2e stage={stage} category={category} sqlstate={state}"+suffix


def guarded(factory, target, owner, login, *, fixture=False):
    """Recheck independent marker, owner, exact identities and server on EVERY use."""
    def connect():
        require_ci()
        target.validate()
        conn = factory()
        try:
            row = conn.execute("""SELECT current_database(),session_user,current_user,
                pg_catalog.pg_get_userbyid(d.datdba),pg_catalog.shobj_description(d.oid,'pg_database'),
                current_setting('server_version_num')::integer
                FROM pg_catalog.pg_database d WHERE d.datname=current_database()""").fetchone()
            check(row[:5] == (target.database, login, owner if fixture else login,
                  owner, "secure-evoting-disposable:"+target.marker) and 180000 <= row[5] < 190000,
                  "Real E2E database ownership or identity mismatch")
            return conn
        except BaseException:
            conn.close()
            raise
    return connect


@dataclass(frozen=True)
class Connections:
    ra_fixture: object
    ra_auth: object
    ra_issue: object
    voting_fixture: object
    voting_runtime: object


def connections(ra, voting, passwords):
    def secret(role): return passwords[role]
    return Connections(
        guarded(database_factory(secret("ra_migrator_login"), database=ra.database, port=ra.port,
            fixture=True, disposable_marker=ra.marker), ra, "ra_owner", "ra_migrator_login", fixture=True),
        guarded(database_factory(secret("ra_auth_login"), database=ra.database, port=ra.port,
            disposable_marker=ra.marker), ra, "ra_owner", "ra_auth_login"),
        guarded(ra_db.issuance_factory(secret("ra_issuance_login"), database=ra.database,
            marker=ra.marker, port=ra.port), ra, "ra_owner", "ra_issuance_login"),
        guarded(vote_db.factory(voting.database, voting.marker, voting.port,
            secret("voting_migrator_login"), fixture=True), voting, "voting_owner", "voting_migrator_login", fixture=True),
        guarded(vote_db.factory(voting.database, voting.marker, voting.port,
            secret("voting_ballot_login")), voting, "voting_owner", "voting_ballot_login"))


def public(key):
    return key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def seed(db, directory):
    voter, election, actor = uuid4(), uuid4(), uuid4()
    signing = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    tally = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    authority = ed25519.Ed25519PrivateKey.generate()
    pin = authority.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    def key(value, name):
        raw = public(value)
        return {"key_id": name, "spki": b64encode(raw), "fingerprint": hashlib.sha256(raw).hexdigest()}
    with db.ra_fixture() as conn:
        now = conn.execute("SELECT clock_timestamp()").fetchone()[0].replace(microsecond=0)
        manifest = {"domain": "secure-evoting-election-manifest-v1", "version": 1, "election_id": str(election),
            "opens_at": (now-timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "closes_at": (now+timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "candidates": sorted([{"candidate_id": str(uuid4()), "candidate_name": "Synthetic E2E candidate "+name}
                                  for name in ("A", "B")], key=lambda c: c["candidate_id"]),
            "ra_key": key(signing, "e2e-ra-"+election.hex), "tally_key": key(tally, "e2e-tally-"+election.hex),
            "profile": "RSABSSA-SHA384-PSS-Randomized"}
        raw = canonical_manifest(manifest)
        signature = authority.sign(b"EVOTE-MANIFEST-v1\0"+raw)
        verify_manifest({"manifest": manifest, "signature": b64encode(signature)}, pin, str(election))
        check(conn.execute("SELECT 1 FROM ra.voters WHERE auth_provider='demo-local' AND auth_subject='demo-voter-001'").fetchone() is None,
              "Existing demo identity refused")
        conn.execute("INSERT INTO ra.voters(voter_id,auth_provider,auth_subject,is_active) VALUES(%s,'demo-local','demo-voter-001',true)", (voter,))
        check(conn.execute("SELECT ra.set_voter_eligibility(%s,%s,true,%s)", (voter,election,actor)).fetchone() == (True,), "Eligibility seed failed")
        conn.execute("""INSERT INTO ra.ra_signing_keys(ra_key_id,election_id,public_key_spki_der,
            public_key_fingerprint,private_key_reference,key_state,activated_at)
            VALUES(%s,%s,%s,%s,'ephemeral-encrypted-e2e-test-key','ACTIVE',%s)""",
            (manifest["ra_key"]["key_id"],election,public(signing),hashlib.sha256(public(signing)).digest(),now))
        conn.execute("""INSERT INTO ra.credential_policies(election_id,ra_key_id,manifest_bytes,manifest_signature,
            config_hash,key_fingerprint,opens_at,closes_at,issuance_enabled) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,true)""",
            (election,manifest["ra_key"]["key_id"],raw,signature,hashlib.sha256(raw).digest(),
             hashlib.sha256(public(signing)).digest(),now-timedelta(hours=1),now+timedelta(hours=1)))
    with db.voting_fixture() as conn:
        vote_now = conn.execute("SELECT clock_timestamp()").fetchone()[0]
        check(now-timedelta(hours=1) < vote_now < now+timedelta(hours=1), "Voting clock outside signed window")
        conn.execute("""INSERT INTO voting.elections(election_id,title,status,opens_at,closes_at,election_config_digest)
            VALUES(%s,'Synthetic real-service E2E','OPEN',%s,%s,%s)""",
            (election,now-timedelta(hours=1),now+timedelta(hours=1),hashlib.sha256(raw).digest()))
        conn.execute("""INSERT INTO voting.election_configs(election_id,config_bytes,config_digest,config_signature,
            config_signing_key_id,config_signing_key_fingerprint,evidence_reference)
            VALUES(%s,%s,%s,%s,'e2e-authority',%s,'ephemeral-real-service-e2e')""",
            (election,raw,hashlib.sha256(raw).digest(),signature,hashlib.sha256(public(authority)).digest()))
        for candidate in manifest["candidates"]:
            conn.execute("INSERT INTO voting.candidates(election_id,candidate_id,candidate_name) VALUES(%s,%s,%s)",
                (election,candidate["candidate_id"],candidate["candidate_name"]))
    unlock = SecretStr(secrets.token_urlsafe(48))
    encrypted = directory / "test-ra-key.encrypted.pem"
    with open(encrypted, "xb", opener=lambda p, f: os.open(p, f, 0o600)) as stream:
        stream.write(signing.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(unlock.get_secret_value().encode())))
    del signing, tally, authority
    return voter, election, manifest, pin, encrypted, unlock


@contextmanager
def http_service(app):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(128)
    server = uvicorn.Server(uvicorn.Config(app, log_config=None, access_log=False, log_level="critical",
        proxy_headers=False, forwarded_allow_ips="", server_header=False, timeout_graceful_shutdown=5))
    failed = threading.Event()
    def serve():
        try: server.run(sockets=[listener])
        except BaseException: failed.set()  # No arbitrary thread exception/traceback output.
    worker = threading.Thread(target=serve, daemon=True)
    worker.start()
    try:
        deadline = time.monotonic()+15
        while not server.started:
            check(worker.is_alive() and time.monotonic() < deadline, "Real HTTP service startup failed")
            time.sleep(.05)
        yield "http://127.0.0.1:"+str(listener.getsockname()[1])
    finally:
        server.should_exit = True
        worker.join(timeout=10)
        listener.close()
        check(not worker.is_alive() and not failed.is_set(), "Real HTTP service teardown failed")


@contextmanager
def child(command, *, env=None, cwd=None):
    process = subprocess.Popen(command, cwd=cwd, env=env, stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    try:
        yield process
    finally:
        if process.poll() is None: process.terminate()
        try: process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill(); process.wait(timeout=5)
        for stream in (process.stdin, process.stdout): stream.close()


def service_configuration(role, config):
    """Reject cross-service secrets before constructing a runtime application."""
    expected = ({"target","pin","auth_config","auth_password","issuance_password",
        "encrypted_key","unlock","signer","election_id"} if role == "ra" else {"target","pin","password"})
    check(role in {"ra","voting"} and type(config) is dict and set(config) == expected,
          "Invalid isolated service configuration")
    check(type(config["target"]) is dict and set(config["target"]) == {"database","marker","port"},
          "Invalid isolated service target")
    target = (ra_ci.Target if role == "ra" else vote_ci.Target)(**config["target"])
    target.validate()
    return target, b64decode(config["pin"],32)


def serve(role):
    require_ci()
    line = sys.stdin.readline(32769)
    check(0 < len(line) <= 32768, "Bounded private service configuration required")
    config = json.loads(line)
    target, pin = service_configuration(role,config)
    with ExitStack() as resources:
        if role == "ra":
            auth = guarded(database_factory(SecretStr(config["auth_password"]),database=target.database,
                port=target.port,disposable_marker=target.marker),target,"ra_owner","ra_auth_login")
            issue = guarded(ra_db.issuance_factory(SecretStr(config["issuance_password"]),database=target.database,
                marker=target.marker,port=target.port),target,"ra_owner","ra_issuance_login")
            encrypted = Path(config["encrypted_key"])
            check(not encrypted.is_symlink() and encrypted.resolve().is_relative_to(require_ci())
                and encrypted.name == "test-ra-key.encrypted.pem", "Private test key target required")
            private = serialization.load_pem_private_key(encrypted.read_bytes(),password=config["unlock"].encode())
            # Match metadata using the actual reviewed key identifier, not a client request.
            key_id = "e2e-ra-"+config["election_id"].replace("-","")
            signer = LocalCIRCLSigner(Path(config["signer"]),private,key_id)
            resources.callback(signer.close)
            del private
            service = CredentialIssuanceService(PostgreSQLCredentialStore(issue),signer,
                CredentialRecovery({"e2e":secrets.token_bytes(32)},"e2e"),pin)
            app = create_credential_app(config["auth_config"],service,auth_connection_factory=auth,
                catalogue=ElectionCatalogue(service.store,pin,[config["election_id"]]))
        else:
            runtime = guarded(vote_db.factory(target.database,target.marker,target.port,SecretStr(config["password"])),
                target,"voting_owner","voting_ballot_login")
            app = create_voting_app(BallotService(PostgreSQLBallotStore(runtime),pin))
        origin = resources.enter_context(http_service(app))
        del config
        sys.stdout.write(json.dumps({"origin":origin})+"\n");sys.stdout.flush()
        check(sys.stdin.readline(128) == '{"stop":true}\n', "Explicit service shutdown required")


@contextmanager
def service_process(role, config):
    # A new interpreter receives only its role-specific config over a private pipe.
    with child([sys.executable,str(Path(__file__).resolve()),"--allow-ephemeral-ci-databases",
                "--serve-role",role]) as process:
        process.stdin.write(json.dumps(config)+"\n");process.stdin.flush()
        ready = queue.Queue(maxsize=1)
        def read_ready():
            try: ready.put(process.stdout.readline(1025))
            except Exception: ready.put("")
        threading.Thread(target=read_ready,daemon=True).start()
        line = ready.get(timeout=20)
        check(0 < len(line) <= 1024, "Isolated service readiness failed")
        response = json.loads(line)
        check(type(response) is dict and set(response) == {"origin"} and
              re.fullmatch(r"http://127\.0\.0\.1:[0-9]{1,5}",response["origin"]), "Unsafe service origin")
        try: yield response["origin"]
        finally:
            process.stdin.write('{"stop":true}\n');process.stdin.flush()
            check(process.wait(timeout=25) == 0, "Isolated service shutdown failed")


@contextmanager
def frontend(node, ra, voting, pin):
    with socket.socket() as reserved:
        reserved.bind(("127.0.0.1", 0)); port = reserved.getsockname()[1]
    env = dict(os.environ, RA_DEMO_TARGET=ra, VOTING_DEMO_TARGET=voting,
        VITE_ENABLE_VOTING="true", VITE_MANIFEST_AUTHORITY_PIN=b64encode(pin))
    with child([str(node),str(ROOT/"frontend/node_modules/vite/bin/vite.js"),"--mode","local-demo",
                "--host","127.0.0.1","--port",str(port),"--strictPort"],env=env,cwd=ROOT/"frontend") as process:
        origin = "http://127.0.0.1:"+str(port)
        opener = build_opener(ProxyHandler({}))
        deadline = time.monotonic()+30
        while True:
            check(process.poll() is None and time.monotonic() < deadline, "Real frontend startup failed")
            try:
                with opener.open(origin, timeout=1) as response:
                    check(response.status == 200, "Frontend readiness failed")
                break
            except OSError: time.sleep(.1)
        yield origin


def assert_database(db, voter, election, *, issued, ballots, receipt=None):
    with db.ra_fixture() as conn:
        for table in ("credential_reservations", "blind_issuances"):
            # Fixed allowlisted table identifiers, no browser-controlled SQL.
            check(conn.execute(f"SELECT count(*) FROM ra.{table} WHERE voter_id=%s AND election_id=%s",
                (voter,election)).fetchone() == (issued,), "RA durable issuance count mismatch")
        check(conn.execute("SELECT count(*) FROM ra.ra_audit_events WHERE voter_id=%s AND election_id=%s AND event_type='BLIND_ISSUANCE_ISSUED'",
            (voter,election)).fetchone() == (issued,), "RA issuance audit count mismatch")
        check(conn.execute("SELECT count(*) FROM ra.ra_sessions WHERE voter_id=%s", (voter,)).fetchone()[0] >= 1,
              "Real authentication did not create a session")
    with db.voting_fixture() as conn:
        rows = conn.execute("SELECT receipt_hash FROM voting.accepted_ballots WHERE election_id=%s", (election,)).fetchall()
        check(len(rows) == ballots, "Voting committed ballot count mismatch")
        if receipt is not None:
            check(len(rows) == 1 and bytes(rows[0][0]).hex() == receipt, "Committed receipt mismatch")


def close_election(db, election):
    with db.voting_fixture() as conn:
        check(conn.execute("UPDATE voting.elections SET status='CLOSED' WHERE election_id=%s AND status='OPEN' RETURNING election_id",
            (election,)).fetchone() is not None, "Fixture close failed")


def browser(node, configuration, db, voter, election, stage, *, close=None, checkpoint=None):
    with child([str(node),str(ROOT/"frontend/tests/real-voting.mjs"),"--real-services-only"],cwd=ROOT/"frontend") as process:
        process.stdin.write(json.dumps(configuration)+"\n"); process.stdin.flush()
        lines = queue.Queue(maxsize=32)
        def read():
            try:
                for line in iter(lambda: process.stdout.readline(4097), ""):
                    lines.put(line, timeout=5)
            except Exception: pass  # Signal EOF/failure through the bounded protocol only.
            finally:
                try: lines.put_nowait(None)
                except queue.Full: pass
        threading.Thread(target=read,daemon=True).start()
        seen = []
        diagnostic_stages = set()
        while True:
            line = lines.get(timeout=90)
            check(line is not None and len(line) <= 4096, "Browser protocol ended unexpectedly")
            message = json.loads(line)
            check(type(message) is dict and set(message) <= {"event", "receipt_hash", "stage", "http_status"}, "Unexpected browser diagnostic")
            event = message.get("event")
            if event in {"diagnostic","failure"}:
                status = message.get("http_status")
                check(status is None or (type(status) is int and status in HTTP_STATUSES)
                      or status == "unavailable", "Unallowlisted browser HTTP status")
            if event == "diagnostic":
                check(configuration["scenario"] == "response_loss" and message.get("stage") in BROWSER_DIAGNOSTICS
                    and set(message) <= {"event","stage","http_status"}, "Unallowlisted browser progress")
                stage[0] = message["stage"]
                diagnostic_stages.add(stage[0])
                print("INFO: real_voting_e2e stage="+stage[0]+(" http_status="+str(status) if status is not None else ""))
                continue  # Progress only: no ACK, database assertion or checkpoint replacement.
            if event == "failure":
                stage[0] = message.get("stage") if message.get("stage") in STAGES else "browser"
                error = AssertionError("Real browser assertion failed; details withheld")
                if status is not None: error.http_status = status
                raise error
            if event == "done": break
            check(event in EVENTS, "Browser assertion failed; details withheld")
            stage[0] = event
            check(event not in seen, "Repeated browser checkpoint")
            seen.append(event)
            receipt = message.get("receipt_hash")
            check(receipt is None or (isinstance(receipt,str) and re.fullmatch(r"[0-9a-f]{64}",receipt)), "Invalid private checkpoint receipt")
            if event in {"before_submit_close", "close_after_accept"}:
                if close is None: close_election(db,election)
                else: close(event)
            issued = int(event not in {"catalogue", "prepared"})
            ballots = int(event in {"committed_response_lost","accepted","recovered","security_checks","close_after_accept","closed_recovery"})
            assert_database(db,voter,election,issued=issued,ballots=ballots,receipt=receipt)
            if checkpoint is not None: checkpoint(event)
            process.stdin.write('{"ok":true}\n'); process.stdin.flush()
            print("PASS: real_voting_e2e checkpoint="+event)
        check(process.wait(timeout=10) == 0, "Real browser process failed")
        expected = {"catalogue","prepared","issued"}
        expected |= ({"before_submit_close","rejected_closed"} if configuration["scenario"] == "closed_first" else
                     {"accepted","security_checks","close_after_accept","closed_recovery"})
        if configuration["scenario"] == "response_loss":
            expected |= {"issuance_response_lost","committed_response_lost","recovered"}
            check(diagnostic_stages == BROWSER_DIAGNOSTICS, "Required browser diagnostics missing")
        check(set(seen) == expected, "Required real browser checkpoint missing")


def deny(factory, query):
    denied = None
    try:
        with factory() as conn:
            try: conn.execute(query)
            except psycopg.errors.InsufficientPrivilege as error:
                denied = error
                raise
            # Roll back even an unexpected successful DELETE; never commit it.
            raise AssertionError("Unauthorized runtime SQL succeeded")
    except psycopg.errors.InsufficientPrivilege as error:
        check(error is denied and error.sqlstate == "42501", "Unexpected ACL denial source")


def acl(db):
    from scripts.voting_integration_diagnostics import IntegrationDiagnostics
    vote_db.run_acl_probes(db.voting_runtime, IntegrationDiagnostics())
    for factory in (db.ra_auth, db.ra_issue):
        for query in ("SELECT * FROM ra.voters", "DELETE FROM ra.blind_issuances", "SET ROLE ra_owner", "SET ROLE ra_migrator_login"):
            deny(factory, query)
        with factory() as conn:
            login = conn.execute("SELECT current_user").fetchone()[0]
            expected = ({("ra_demo",name) for name in ("issue_demo_session","find_active_demo_voter_id",
                "find_active_demo_session","revoke_demo_session")} if login == "ra_auth_login" else
                {("ra_credential",name) for name in ra_db.EXPORTED})
            rows = conn.execute("""SELECT n.nspname,p.proname FROM pg_proc p
                JOIN pg_namespace n ON n.oid=p.pronamespace
                WHERE n.nspname IN ('ra','ra_demo','ra_credential')
                AND has_function_privilege(current_user,p.oid,'EXECUTE')""").fetchall()
            check(set(rows) == expected, "Unexpected RA runtime EXECUTE surface")
            check(conn.execute("""SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
                WHERE n.nspname='ra' AND CASE WHEN c.relkind IN ('r','p') THEN
                (has_table_privilege(current_user,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
                 OR has_any_column_privilege(current_user,c.oid,'SELECT,INSERT,UPDATE,REFERENCES'))
                ELSE false END""").fetchone() == (0,), "RA direct table privileges allowed")
    for query in ("SET ROLE voting_owner", "SET ROLE voting_migrator_login"):
        deny(db.voting_runtime, query)
    with db.ra_issue() as conn:
        check(conn.execute("""SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
            CROSS JOIN LATERAL aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a
            WHERE n.nspname='ra_credential' AND a.grantee NOT IN
            (p.proowner,(SELECT oid FROM pg_roles WHERE rolname='ra_issuance_login'))""").fetchone() == (0,), "RA PUBLIC execute allowed")
    with db.voting_fixture() as conn:
        rows = conn.execute("""SELECT p.proname,r.rolname,p.prosecdef,p.proconfig,
            has_function_privilege('voting_ballot_login',p.oid,'EXECUTE')
            FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
            JOIN pg_roles r ON r.oid=p.proowner WHERE n.nspname='voting'""").fetchall()
        expected = {"ballot_policy","accept_anonymous_ballot","recover_ballot_receipt"}
        check(len(rows) == 5 and all(owner == "voting_owner" and definer and
            any(item.replace(" ","") == "search_path=pg_catalog,voting,pg_temp" for item in config)
            and executable == (name in expected) for name,owner,definer,config,executable in rows), "Unsafe Voting function surface")
        check(conn.execute("""SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
            CROSS JOIN (VALUES ('voting_admin_service'),('voting_snapshot_worker'),('voting_tally_worker'),
              ('voting_publication_service'),('voting_board_reader'),('voting_audit_reader')) worker(name)
            WHERE n.nspname='voting' AND has_function_privilege(worker.name,p.oid,'EXECUTE')""").fetchone() == (0,), "Unrelated worker EXECUTE allowed")
        check(conn.execute("""SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace,
            LATERAL aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a
            WHERE n.nspname='voting' AND a.grantee=0 AND a.privilege_type='EXECUTE'""").fetchone() == (0,), "Voting PUBLIC EXECUTE allowed")
        check(conn.execute("""SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
            WHERE n.nspname='voting' AND CASE WHEN c.relkind IN ('r','p') THEN
            (has_table_privilege('voting_ballot_login',c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
             OR has_any_column_privilege('voting_ballot_login',c.oid,'SELECT,INSERT,UPDATE,REFERENCES'))
            ELSE false END""").fetchone() == (0,), "Voting direct table privileges allowed")


def cleanup(db, voter, election):
    with db.ra_fixture() as conn:
        ra_db.cleanup(conn,[voter],election)
        check(all(not rows for rows in ra_ci.snapshot(conn).values()), "RA fixture cleanup failed")
    with db.voting_fixture() as conn:
        for table in ("accepted_ballots","candidates","election_configs","elections"):
            conn.execute(f"DELETE FROM voting.{table} WHERE election_id=%s", (election,))
        check(all(not rows for rows in vote_ci.snapshot(conn).values()), "Voting fixture cleanup failed")
    # A separate transaction verifies committed cleanup, not only uncommitted deletes.
    with db.ra_fixture() as conn: check(all(not rows for rows in ra_ci.snapshot(conn).values()), "RA cleanup commit failed")
    with db.voting_fixture() as conn: check(all(not rows for rows in vote_ci.snapshot(conn).values()), "Voting cleanup commit failed")


def run(node, signer_binary, stage):
    directory = require_ci()
    screenshots = directory / "real-voting-preview"
    screenshots.mkdir(mode=0o700)  # Refuse reuse or an inherited output destination.
    with ExitStack() as resources:
        stage[0] = "provision"
        ra_container, ra_bootstrap = resources.enter_context(vote_ci.ephemeral_postgres())
        voting, voting_bootstrap = resources.enter_context(vote_ci.ephemeral_postgres())
        ra = ra_ci.Target("ra_demo_test_ci_"+uuid4().hex,ra_container.marker,ra_container.port)
        passwords = {role:SecretStr(secrets.token_urlsafe(48)) for role in (*ra_ci.LOGINS,*vote_ci.LOGINS)}
        ra_ci.bootstrap_database(ra,ra_bootstrap,{r:passwords[r] for r in ra_ci.LOGINS})
        vote_ci.bootstrap_database(voting,voting_bootstrap,{r:passwords[r] for r in vote_ci.LOGINS})
        db = connections(ra,voting,passwords)
        # Verify independent designation AND expected ownership before migration DDL.
        for factory in (db.ra_fixture,db.voting_fixture):
            with factory(): pass
        stage[0] = "migrations"
        ra_ci.migrate(ra,passwords["ra_migrator_login"])
        vote_ci.migrate(voting,passwords["voting_migrator_login"])
        for scenario in SCENARIOS:
            stage[0] = "seed"
            with tempfile.TemporaryDirectory(prefix="evote-real-e2e-",dir=directory) as scratch:
                check(Path(scratch).resolve().is_relative_to(directory), "Unsafe E2E scratch target")
                voter, election, manifest, pin, encrypted, unlock = seed(db,Path(scratch))
                try:
                    with ExitStack() as services:
                        password, env = synthetic_environment(passwords["ra_auth_login"])
                        stage[0] = "services"
                        ra_origin = services.enter_context(service_process("ra",{
                            "target":vars(ra),"pin":b64encode(pin),"auth_config":env,
                            "auth_password":passwords["ra_auth_login"].get_secret_value(),
                            "issuance_password":passwords["ra_issuance_login"].get_secret_value(),
                            "encrypted_key":str(encrypted),"unlock":unlock.get_secret_value(),
                            "signer":str(signer_binary),"election_id":str(election)}))
                        del unlock
                        vote_origin = services.enter_context(service_process("voting",{
                            "target":vars(voting),"pin":b64encode(pin),
                            "password":passwords["voting_ballot_login"].get_secret_value()}))
                        origin = services.enter_context(frontend(node,ra_origin,vote_origin,pin))
                        stage[0] = "browser"
                        browser(node,{"origin":origin,"scenario":scenario,"username":env["RA_DEMO_USERNAME"],
                            "password":password,"passphrase":secrets.token_urlsafe(48),"election_id":str(election),
                            "screenshots":str(screenshots)},db,voter,election,stage)
                        stage[0] = "acl"; acl(db)
                finally:
                    prior_stage, failed = stage[0], sys.exc_info()[0] is not None
                    stage[0] = "cleanup"
                    cleanup(db,voter,election)
                    print("PASS: real_voting_e2e scenario="+scenario+" fixture_cleanup=committed")
                    if failed: stage[0] = prior_stage
        stage[0] = "teardown"
    check({p.name for p in screenshots.iterdir()} == {"catalogue.png","accepted-heading.png"}, "Unexpected screenshot artifact")
    for path in screenshots.iterdir():
        check(not path.is_symlink() and path.is_file() and path.read_bytes().startswith(b'\x89PNG\r\n\x1a\n'), "Invalid screenshot artifact")
    print("PASS: real_voting_e2e all_scenarios=3 owned_containers=removed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--allow-ephemeral-ci-databases",action="store_true",required=True)
    parser.add_argument("--node",type=Path)
    parser.add_argument("--signer-binary",type=Path)
    parser.add_argument("--serve-role",choices=("ra","voting"),help=argparse.SUPPRESS)
    args = parser.parse_args()
    stage = ["preflight"]
    try:
        require_ci()  # Before any file, child process, Docker or PostgreSQL operation.
        if not args.serve_role: vote_ci.verify_dependencies()
        logging.disable(logging.CRITICAL)
        def terminate(_number, _frame): raise KeyboardInterrupt()
        signal.signal(signal.SIGTERM,terminate)  # Unwind owned resources on normal CI cancellation.
        if args.serve_role:
            # Readiness stdout is a strict private protocol, not a version log.
            serve(args.serve_role)
        else:
            check(args.node is not None and args.signer_binary is not None
                and args.node.is_file() and args.signer_binary.is_file(), "Reviewed executable inputs required")
            run(args.node,args.signer_binary,stage)
    except BaseException as error:
        raise SystemExit(failure(stage[0],error)) from None


if __name__ == "__main__":
    main()
