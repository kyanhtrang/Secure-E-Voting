"""Hosted-only real Admin -> Chromium/RA/CIRCL -> Voting -> Tally composition gate.

Private configuration uses pipes. No database targets or credentials are accepted
from the command line/environment. Imports perform no provisioning or key reads.
"""
import argparse
from contextlib import contextmanager, ExitStack
import hashlib
import json
import logging
import os
from pathlib import Path
import queue
import re
import secrets
import signal
import sys
import tempfile
import threading
from uuid import UUID, uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import httpx
import rfc8785
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from pydantic import SecretStr

from backend.crypto.credential_protocol import b64decode, b64encode, strict_json, verify_manifest
from backend.tally.http import create_tally_app
from backend.tally.launcher import EncryptedTallyKey
from backend.tally.runtime import TallyAuthentication, TallyService, TallyStore
from backend.tally.verification import EvidenceVault
from scripts import admin_voter_e2e as guard, tally_postgres_ci as tally_ci, voting_tally_auth as e2e_auth

real, check = guard.real, guard.check
STAGES = {"preflight", "provision", "migrations", "auth_fixture", "keys", "admin_draft", "admin_finalize",
          "services", "open_interrupted", "open_reconciled", "open_tally_denied", "browser",
          "voter_a_authenticated", "voter_b_authenticated", "accepted_first", "accepted_second", "close_interrupted", "close_reconciled",
          "tally", "evidence", "idempotency", "configuration_rejected", "receipts", "acl", "cleanup"}
TALLY_FIELDS = {"target", "password", "operator", "username", "salt", "digest", "pin",
                "snapshot_pin", "snapshot_key", "snapshot_unlock", "tally_key", "tally_unlock",
                "tally_key_id", "evidence"}
KEY_FILES = {"tally": "test-tally-key.encrypted.pem", "snapshot": "test-snapshot-key.encrypted.pem"}
BROWSER_STAGES = {"preflight", "catalogue", "prepare", "issue", "submit", "security", "recovery"}


def require_ci():
    root = guard.require_ci()
    check(not any(k.startswith("TALLY_DEMO_") for k in os.environ), "Inherited Tally configuration refused")
    return root


def checkpoint(stage):
    check(stage in STAGES, "Unknown checkpoint")
    print("PASS: voting_tally_e2e checkpoint=" + stage, flush=True)


def failure(stage, error):
    label = stage if stage in STAGES else "preflight"
    return guard.failure("preflight", error).replace("admin_voter_e2e stage=preflight",
        "voting_tally_e2e stage=" + label)


def private_path(value, name):
    path = Path(value)
    check(path.name == name and not path.is_symlink() and path.resolve().is_relative_to(require_ci())
          and path.is_file() and path.stat().st_mode & 0o777 == 0o600, "Private ephemeral file required")
    return path


def tally_configuration(config):
    check(type(config) is dict and set(config) == TALLY_FIELDS, "Restricted Tally configuration required")
    owned = guard.designated("voting", config["target"])
    pin, snapshot_pin = b64decode(config["pin"], 32), b64decode(config["snapshot_pin"], 32)
    check(pin != snapshot_pin, "Independent authority required")
    UUID(config["operator"])
    b64decode(config["salt"], 16); b64decode(config["digest"], 32)
    for name in KEY_FILES: private_path(config[name + "_key"], KEY_FILES[name])
    path = Path(config["evidence"])
    check(not path.is_symlink() and path.resolve().is_relative_to(require_ci())
          and path.is_dir() and path.stat().st_mode & 0o777 == 0o700, "Private evidence directory required")
    return owned, pin, snapshot_pin


def serve_tally():
    require_ci()
    line = sys.stdin.readline(16385)
    check(0 < len(line) <= 16384, "Bounded private configuration required")
    config = strict_json(line.encode())
    owned, pin, snapshot_pin = tally_configuration(config)
    store = TallyStore(tally_ci.runtime(owned, SecretStr(config["password"])))
    auth = TallyAuthentication(store, UUID(config["operator"]), config["username"],
        b64decode(config["salt"], 16), b64decode(config["digest"], 32))
    snapshot_private = serialization.load_pem_private_key(
        private_path(config["snapshot_key"], KEY_FILES["snapshot"]).read_bytes(),
        password=config["snapshot_unlock"].encode())
    vault = EvidenceVault(Path(config["evidence"]), snapshot_private, snapshot_pin, "combined-test-snapshot")
    loader = EncryptedTallyKey(private_path(config["tally_key"], KEY_FILES["tally"]),
        SecretStr(config["tally_unlock"]), config["tally_key_id"])
    service = TallyService(auth, store, pin, vault, loader)
    del config, snapshot_private
    with real.http_service(create_tally_app(service)) as origin:
        print(json.dumps({"origin": origin}), flush=True)
        check(sys.stdin.readline(128) == '{"stop":true}\n', "Explicit shutdown required")


def ra_app(config, auth_connect, service, pin):
    """Hosted fixture identity injection; production launchers retain their fixed subject.

    Use the reviewed routers, authentication/session adapters and middleware.
    No service, database result or signature is replaced by a test response.
    """
    from fastapi import FastAPI
    from backend.ra.auth_service import RAAuthenticationService
    from backend.ra.auth_middleware import AuthNoStoreMiddleware
    from backend.ra.credential_runtime import CredentialNoStore
    from backend.ra.credential_router import router as credential_router, get_credential_service
    from backend.ra.demo_auth_config import load_demo_credential_verifier
    from backend.ra.demo_launcher import LocalDemoMiddleware
    from backend.ra.election_catalogue import router as catalogue_router, get_election_catalogue
    from backend.ra.login_rate_limit import LimitedDemoAuthentication
    from backend.ra.login_router import router as login_router, get_ra_auth_service
    from backend.ra.session_router import router as session_router, get_ra_session_service
    require_ci()
    env = config["auth_config"]
    check(env.get("RA_DEMO_PROVIDER") == "demo-local" and env.get("RA_DEMO_SUBJECT") in
          {"demo-voter-001", "demo-voter-002"}, "Trusted synthetic identity required")
    verifier = load_demo_credential_verifier(env)
    store = e2e_auth.SessionStore(auth_connect, UUID(config["voter_id"]), env["RA_DEMO_SUBJECT"])
    auth = LimitedDemoAuthentication(RAAuthenticationService(verifier, store, store))
    sessions = e2e_auth.BoundSessions(store)
    issuance = e2e_auth.BoundIssuance(service, sessions)
    catalogue = real.ElectionCatalogue(service.store, pin, [config["election_id"]])
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    for router in (login_router, session_router, credential_router, catalogue_router): app.include_router(router)
    app.dependency_overrides.update({get_ra_auth_service: lambda: auth, get_ra_session_service: lambda: sessions,
        get_credential_service: lambda: issuance, get_election_catalogue: lambda: catalogue})
    for middleware in (LocalDemoMiddleware, AuthNoStoreMiddleware, CredentialNoStore): app.add_middleware(middleware)
    return app


def ra_configuration(config):
    check(type(config) is dict and set(config) == guard.ROLE_FIELDS["ra"] | {"voter_id"}, "Bound RA fixture required")
    check(str(UUID(config["voter_id"])) == config["voter_id"], "Canonical trusted voter required")
    return guard.configuration("ra", {k:v for k,v in config.items() if k != "voter_id"})


def serve_ra():
    require_ci()
    line = sys.stdin.readline(16385)
    check(0 < len(line) <= 16384, "Bounded private configuration required")
    config = strict_json(line.encode())
    owned, = ra_configuration(config)
    pin = b64decode(config["pin"], 32)
    auth = guard.connection(owned, "ra_auth_login", SecretStr(config["auth_password"]))
    issue = guard.connection(owned, "ra_issuance_login", SecretStr(config["issuance_password"]))
    private = guard.encrypted_key(config["encrypted_key"], config["unlock"])
    signer_path = Path(config["signer"])
    check(signer_path.is_file() and not signer_path.is_symlink() and signer_path.resolve().is_relative_to(require_ci()), "Native test signer required")
    with ExitStack() as resources:
        signer = real.LocalCIRCLSigner(signer_path, private, config["key_id"])
        resources.callback(signer.close)
        del private
        service = real.CredentialIssuanceService(real.PostgreSQLCredentialStore(issue), signer,
            real.CredentialRecovery({"combined-test": secrets.token_bytes(32)}, "combined-test"), pin)
        app = ra_app(config, auth, service, pin)
        origin = resources.enter_context(real.http_service(app))
        del config
        print(json.dumps({"origin": origin}), flush=True)
        check(sys.stdin.readline(128) == '{"stop":true}\n', "Explicit shutdown required")


def read_line(process, limit=2048, timeout=90):
    result = queue.Queue(maxsize=1)
    def read():
        try: result.put(process.stdout.readline(limit + 1))
        except Exception: result.put("")
    threading.Thread(target=read, daemon=True).start()
    line = result.get(timeout=timeout)
    check(0 < len(line) <= limit, "Bounded service response required")
    return strict_json(line.encode())


def send(process, value):
    raw = json.dumps(value, separators=(",", ":"))
    check(len(raw) <= 16384, "Bounded private control required")
    process.stdin.write(raw + "\n"); process.stdin.flush()


def browser_event(process, timeout=90):
    event = read_line(process, timeout=timeout)
    if type(event) is dict and set(event) == {"event", "stage"} and event["event"] == "failure" and event["stage"] in BROWSER_STAGES:
        print("FAIL: voting_tally_e2e browser_stage=" + event["stage"], flush=True)
        raise AssertionError("Real browser failed")
    return event


@contextmanager
def isolated_process(role, config):
    check(role in {"tally", "ra"}, "Restricted process role required")
    if role == "tally": tally_configuration(config)
    else: ra_configuration(config)
    with real.child([sys.executable, str(Path(__file__).resolve()),
        "--allow-ephemeral-ci-databases", "--serve-" + role]) as process:
        send(process, config)
        ready = read_line(process, timeout=25)
        check(type(ready) is dict and set(ready) == {"origin"} and
              re.fullmatch(r"http://127\.0\.0\.1:[0-9]{1,5}", ready["origin"]), "Unsafe readiness")
        try: yield ready["origin"]
        finally:
            send(process, {"stop": True})
            check(process.wait(timeout=25) == 0, "Isolated runtime shutdown failed")


def tally_process(config): return isolated_process("tally", config)
def ra_process(config): return isolated_process("ra", config)


def tally_http(origin, path, status, *, token=None, body=None, error_code=None):
    check(re.fullmatch(r"http://127\.0\.0\.1:[0-9]{1,5}", origin) and
          re.fullmatch(r"(?:auth/(?:login|me|logout)|elections(?:/[a-f0-9-]{36}/(?:run|report))?)", path), "Restricted loopback API required")
    with httpx.Client(base_url=origin, trust_env=False, follow_redirects=False, timeout=45) as client:
        response = client.request("GET" if body is None else "POST", "/api/v1/tally/" + path,
            json=body, headers={} if token is None else {"Authorization": "Bearer " + token})
        if response.status_code != status:
            error = AssertionError("Unexpected Tally status")
            error.http_status = response.status_code if response.status_code in real.HTTP_STATUSES else "unavailable"
            raise error
        check(response.headers.get("Cache-Control") == "no-store", "Missing no-store")
        if error_code is not None:
            check(error_code in {"AUTHENTICATION", "CONFLICT", "INTEGRITY"} and status >= 400
                  and len(response.content) <= 8192 and strict_json(response.content).get("code") == error_code,
                  "Unexpected restricted error classification")
        if status >= 400 or status == 204: return None
        check(len(response.content) <= 131072, "Bounded aggregate required")
        return strict_json(response.content)


def keys(directory):
    """Provision once; retain the matching RSA key encrypted for Tally alone."""
    authority = ed25519.Ed25519PrivateKey.generate()
    snapshot = ed25519.Ed25519PrivateKey.generate()
    pin = authority.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    snapshot_pin = snapshot.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    ra, tally = (rsa.generate_private_key(public_exponent=65537, key_size=3072) for _ in range(2))
    def public(private, prefix):
        raw = real.public(private)
        return {"key_id": prefix + uuid4().hex, "spki": b64encode(raw), "fingerprint": hashlib.sha256(raw).hexdigest()}
    keyset = {"ra_key": public(ra, "combined-ra-"), "tally_key": public(tally, "combined-tally-"),
              "private_key_reference": "ephemeral-combined-test-only"}
    files = {}
    for name, filename, private in (("authority", "admin-authority.encrypted.pem", authority),
        ("ra", "test-ra-key.encrypted.pem", ra), ("tally", KEY_FILES["tally"], tally),
        ("snapshot", KEY_FILES["snapshot"], snapshot)):
        path = directory / filename
        files[name] = (path, guard.write_key(path, private))
    return pin, snapshot_pin, {"accepted": keyset}, files


@contextmanager
def browser(node, config):
    with real.child([str(node), "--experimental-strip-types", str(ROOT / "frontend/tests/real-voting-tally.mjs"),
                     "--real-services-only"], cwd=ROOT / "frontend") as process:
        send(process, config)
        event = browser_event(process, timeout=150)
        check(type(event) is dict and set(event) == {"event", "receipt_hash"}
              and event["event"] == "accepted" and re.fullmatch(r"[0-9a-f]{64}", event["receipt_hash"]), "Real browser acceptance failed")
        yield event["receipt_hash"]
        send(process, {"ok": True})  # Only after Admin closure and committed Tally.
        check(browser_event(process) == {"event": "recovered"}, "Post-Tally receipt recovery failed")
        check(process.wait(timeout=20) == 0, "Real browser failed")


def assert_ballots(db, election, voters, receipts):
    with db.voting_fixture() as conn:
        rows = conn.execute("SELECT encode(receipt_hash,'hex') FROM voting.accepted_ballots WHERE election_id=%s", (election,)).fetchall()
        check({r[0] for r in rows} == set(receipts) and len(rows) == len(receipts), "Committed receipts mismatch")
    with db.ra_fixture() as conn:
        for voter in voters:
            for table in ("credential_reservations", "blind_issuances"):
                check(conn.execute(f"SELECT count(*) FROM ra.{table} WHERE voter_id=%s AND election_id=%s", (voter, election)).fetchone() == (1,), "Durable issuance missing")
            check(conn.execute("SELECT count(*) FROM ra.ra_audit_events WHERE voter_id=%s AND election_id=%s AND event_type='BLIND_ISSUANCE_ISSUED'", (voter,election)).fetchone() == (1,), "Issuance audit missing")


def verify_report(result, election, config_hash, candidates, pin):
    check(set(result) == {"report", "report_digest", "signature", "signing_key_id", "candidates"}, "Unexpected HTTP report fields")
    report = result["report"]
    raw = rfc8785.dumps(report)
    ed25519.Ed25519PublicKey.from_public_bytes(pin).verify(b64decode(result["signature"], 64), b"EVOTE-TALLY-REPORT-v1\0" + raw)
    check(hashlib.sha256(raw).hexdigest() == result["report_digest"]
          and result["signing_key_id"] == "combined-test-snapshot", "Aggregate signature binding mismatch")
    check(report["election_id"] == str(election) and report["election_config_digest"] == config_hash
          and result["candidates"] == candidates, "Aggregate configuration mismatch")
    check(type(report["report_version"]) is int and report["report_version"] == 1
          and report["algorithm_version"] == "evote-tally-v1", "Aggregate version mismatch")
    check(report["accepted_total"] == report["valid_total"] == report["counted_total"] == 2
          and report["invalid_total"] == 0 and report["invalid_reasons"] == {"KEY_WRAP":0,"AEAD":0,"PLAINTEXT":0}
          and report["candidate_counts"] == [{"candidate_id": c["candidate_id"], "vote_count": 1} for c in candidates], "Aggregate counts incorrect")
    check(set(report) == {"report_version", "election_id", "election_config_digest", "snapshot_digest", "algorithm_version",
          "accepted_total", "valid_total", "invalid_total", "counted_total", "candidate_counts", "invalid_reasons"}, "Nonaggregate HTTP data")


def run(node, signer, stage, *, publication=None):
    root = require_ci()
    with ExitStack() as resources:
        stage[0] = "provision"
        rt, rb = resources.enter_context(real.vote_ci.ephemeral_postgres())
        vt, vb = resources.enter_context(real.vote_ci.ephemeral_postgres())
        rt = real.ra_ci.Target("ra_demo_test_ci_" + uuid4().hex, rt.marker, rt.port)
        ra, voting = guard.discover("ra", rt), guard.discover("voting", vt)
        passwords = {r: SecretStr(secrets.token_urlsafe(48)) for r in
            (*real.ra_ci.LOGINS, *real.vote_ci.LOGINS, "voting_admin_login", "ra_election_publisher_login", "voting_tally_login")}
        real.ra_ci.bootstrap_database(rt, rb, {r: passwords[r] for r in real.ra_ci.LOGINS})
        real.vote_ci.bootstrap_database(vt, vb, {r: passwords[r] for r in real.vote_ci.LOGINS})
        stage[0] = "migrations"
        real.ra_ci.migrate(rt, passwords["ra_migrator_login"])
        real.vote_ci.migrate(vt, passwords["voting_migrator_login"])
        for module, target, bootstrap, role in ((real.ra_ci, rt, rb, "ra_election_publisher_login"),
            (real.vote_ci, vt, vb, "voting_admin_login"), (real.vote_ci, vt, vb, "voting_tally_login")):
            guard.admin_ci.provision_role(module, target, bootstrap, role, passwords[role])
        guard.admin_ci.migrate(real.ra_ci, rt, passwords["ra_migrator_login"], "ra", "bf932d0f8702")
        guard.admin_ci.migrate(real.vote_ci, vt, passwords["voting_migrator_login"], "voting", "af821c9e7601")
        tally_ci.migrate(vt, passwords["voting_migrator_login"])
        if publication is not None:
            publication.provision(voting, vb, passwords)
        checkpoint("migrations")
        def connect(owned, role, fixture=False): return guard.connection(owned, role, passwords[role], fixture=fixture)
        db = real.Connections(connect(ra,"ra_migrator_login",True),connect(ra,"ra_auth_login"),connect(ra,"ra_issuance_login"),
            connect(voting,"voting_migrator_login",True),connect(voting,"voting_ballot_login"))
        principal, first = guard.identities(db)
        second, operator = uuid4(), uuid4()
        with db.ra_fixture() as conn:
            conn.execute("INSERT INTO ra.voters(voter_id,auth_provider,auth_subject,is_active) VALUES(%s,'demo-local','demo-voter-002',true)", (second,))
        with db.voting_fixture() as conn:
            conn.execute("INSERT INTO voting_tally.principals(operator_id,role,is_active) VALUES(%s,'TALLY_OPERATOR',true)", (operator,))
        stage[0] = "auth_fixture"
        e2e_auth.install(ra,db.ra_fixture,dict(zip(e2e_auth.SUBJECTS,(first,second))))
        directory = Path(resources.enter_context(tempfile.TemporaryDirectory(prefix="evote-voting-tally-", dir=root)))
        stage[0] = "keys"
        pin, snapshot_pin, catalogue, files = keys(directory)
        evidence = directory / "evidence"; evidence.mkdir(mode=0o700)
        admin_password, tally_password = secrets.token_urlsafe(48), secrets.token_urlsafe(48)
        def verifier(password):
            salt = secrets.token_bytes(16)
            return dict(salt=b64encode(salt), digest=b64encode(hashlib.scrypt(password.encode(), salt=salt, n=2**14,r=8,p=1,dklen=32)))
        admin_config = dict(
            voting=voting.wire(), ra=ra.wire(), voting_password=passwords["voting_admin_login"].get_secret_value(),
            publisher_password=passwords["ra_election_publisher_login"].get_secret_value(), principal=str(principal), username="synthetic-admin-tally",
            authority_key=str(files["authority"][0]), unlock=files["authority"][1].get_secret_value(), pin=b64encode(pin), keysets=catalogue, **verifier(admin_password))
        origin = resources.enter_context(guard.service_process("admin", admin_config))
        token = guard.http(origin,"/api/v1/admin/auth/login",200,method="POST",data={"username":"synthetic-admin-tally","password":admin_password})["access_token"]
        stage[0] = "admin_draft"
        election, base = guard.create_election(origin,token,db,principal,first,"accepted",pin,catalogue,stage)
        with db.ra_fixture() as conn:
            check(conn.execute("SELECT ra.set_voter_eligibility(%s,%s,true,%s)",(second,election,principal)).fetchone() == (True,), "Eligibility setup failed")
        status = guard.http(origin,base,200,token=token)
        manifest, config_hash = verify_manifest(status["bundle"],pin,str(election))
        check(manifest["tally_key"] == catalogue["accepted"]["tally_key"], "Provisioned Tally key mismatch")
        tally_config = dict(target=voting.wire(), password=passwords["voting_tally_login"].get_secret_value(), operator=str(operator),
            username="synthetic-tally", pin=b64encode(pin), snapshot_pin=b64encode(snapshot_pin), evidence=str(evidence),
            tally_key=str(files["tally"][0]), tally_unlock=files["tally"][1].get_secret_value(), tally_key_id=manifest["tally_key"]["key_id"],
            snapshot_key=str(files["snapshot"][0]), snapshot_unlock=files["snapshot"][1].get_secret_value(), **verifier(tally_password))
        tally_origin = resources.enter_context(tally_process(tally_config))
        tally_token = tally_http(tally_origin,"auth/login",200,body={"username":"synthetic-tally","password":tally_password})["access_token"]
        check(tally_http(tally_origin,"auth/me",200,token=tally_token) == {"operator_id":str(operator),"role":"TALLY_OPERATOR"}, "Separate operator required")
        tally_http(tally_origin,"auth/me",401,token=token)
        path = "elections/" + str(election)
        stage[0] = "open_interrupted"
        with guard.publisher_denied(db):
            guard.http(origin,base+"/open",503,method="POST",data={},token=token)
            guard.policy_state(db,election,"OPEN",False,None)
        stage[0] = "open_reconciled"
        guard.http(origin,base+"/open",200,method="POST",data={},token=token)
        guard.policy_state(db,election,"OPEN",True,True)
        stage[0] = "open_tally_denied"
        tally_http(tally_origin,path+"/run",409,token=tally_token,body={},error_code="CONFLICT")
        checkpoint("open_tally_denied")
        published = None
        if publication is not None:
            published = resources.enter_context(publication.services(voting, passwords, db, directory, evidence,
                pin, snapshot_pin, principal, origin, admin_config, admin_password, election, tally_token))
        vote_origin = resources.enter_context(guard.service_process("voting", dict(target=voting.wire(),pin=b64encode(pin),password=passwords["voting_ballot_login"].get_secret_value())))
        receipts, voter_services = [], []
        with ExitStack() as browsers:
            for index, voter in enumerate((first,second)):
                stage[0] = "browser"
                password, env = real.synthetic_environment(passwords["ra_auth_login"])
                env.update(RA_DEMO_SUBJECT="demo-voter-00"+str(index+1),RA_DEMO_USERNAME="synthetic-voter-"+str(index+1))
                ra_origin = resources.enter_context(ra_process(dict(target=ra.wire(),pin=b64encode(pin),auth_config=env,
                    auth_password=passwords["ra_auth_login"].get_secret_value(),issuance_password=passwords["ra_issuance_login"].get_secret_value(),
                    encrypted_key=str(files["ra"][0]),unlock=files["ra"][1].get_secret_value(),signer=str(signer),
                    key_id=manifest["ra_key"]["key_id"],election_id=str(election),voter_id=str(voter))))
                stage[0] = "voter_a_authenticated" if index == 0 else "voter_b_authenticated"
                voter_token = guard.http(ra_origin,"/api/v1/ra/auth/login",200,method="POST",data={"username":env["RA_DEMO_USERNAME"],"password":password})["access_token"]
                check(guard.http(ra_origin,"/api/v1/ra/auth/me",200,token=voter_token) == {"voter_id":str(voter)},"Authenticated voter mismatch")
                checkpoint(stage[0])
                voter_services.append((ra_origin,voter_token,voter,env["RA_DEMO_USERNAME"],password))
                e2e_auth.check_session(db.ra_fixture,voter,voter_token)
                if index == 1: e2e_auth.check_authentication(voter_services,db.ra_fixture,db.ra_auth,election)
                tally_http(tally_origin,"auth/me",401,token=voter_token)
                if published is not None:
                    published.reject_voter(voter_token)
                guard.http(origin,"/api/v1/admin/elections",401,token=voter_token)
                front = resources.enter_context(real.frontend(node,ra_origin,vote_origin,pin))
                stage[0] = "browser"
                receipt = browsers.enter_context(browser(node,dict(origin=front,username=env["RA_DEMO_USERNAME"],password=password,
                    passphrase=secrets.token_urlsafe(48),election_id=str(election),candidate="AB"[index])))
                check(receipt not in receipts,"Duplicate committed receipt")
                receipts.append(receipt)
                assert_ballots(db,election,(first,second)[:index+1],receipts)
                stage[0] = "accepted_first" if index == 0 else "accepted_second"
                checkpoint(stage[0])
            stage[0] = "close_interrupted"
            with guard.publisher_denied(db):
                guard.http(origin,base+"/close",503,method="POST",data={},token=token)
                guard.policy_state(db,election,"CLOSED",False,True)
                tally_http(tally_origin,path+"/run",409,token=tally_token,body={},error_code="CONFLICT")
            with db.voting_fixture() as conn:
                check(conn.execute("SELECT count(*) FROM voting.tally_jobs WHERE election_id=%s",(election,)).fetchone() == (0,), "Denied tally allocated a job")
            checkpoint("close_interrupted")
            stage[0] = "close_reconciled"
            guard.http(origin,base+"/close",200,method="POST",data={},token=token)
            guard.policy_state(db,election,"CLOSED",True,False)
            checkpoint("close_reconciled")
            stage[0] = "tally"
            result = tally_http(tally_origin,path+"/run",200,token=tally_token,body={})
            verify_report(result,election,config_hash,manifest["candidates"],snapshot_pin)
            checkpoint("tally")
            stage[0] = "evidence"
            verify_database(db,election,result,snapshot_pin,evidence)
            checkpoint("evidence")
            stage[0] = "idempotency"
            check(tally_http(tally_origin,path+"/run",200,token=tally_token,body={}) == result
                  and tally_http(tally_origin,path+"/report",200,token=tally_token) == result, "Idempotent report changed")
            verify_database(db,election,result,snapshot_pin,evidence)
            checkpoint("idempotency")
            stage[0] = "configuration_rejected"
            # Independent wrong authority; no database/config/key mutation or forged ballot.
            with tally_process(dict(tally_config,pin=b64encode(ed25519.Ed25519PrivateKey.generate().public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)))) as wrong:
                wrong_token = tally_http(wrong,"auth/login",200,body={"username":"synthetic-tally","password":tally_password})["access_token"]
                tally_http(wrong,path+"/report",503,token=wrong_token,error_code="INTEGRITY")
                tally_http(wrong,"auth/logout",204,token=wrong_token,body={})
            check(tally_http(tally_origin,path+"/report",200,token=tally_token) == result,"Failed verifier altered committed report")
            checkpoint("configuration_rejected")
            if published is not None:
                published.finish(result, receipts, voter_services, operator, tally_token)
            stage[0] = "receipts"
        assert_ballots(db,election,(first,second),receipts)
        checkpoint("receipts")
        stage[0] = "acl"
        guard.admin_acl(db,connect(voting,"voting_admin_login"),connect(ra,"ra_election_publisher_login"))
        e2e_auth.check_acl(db.ra_auth,(db.ra_issue,connect(ra,"ra_election_publisher_login")),db.ra_fixture)
        tally_ci.check_acl(tally_ci.runtime(voting,passwords["voting_tally_login"]),db.voting_runtime,db.voting_fixture)
        with connect(voting,"voting_admin_login")() as conn:
            check(conn.execute("SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='voting_tally' AND has_function_privilege(current_user,p.oid,'EXECUTE')").fetchone() == (0,),"Admin can execute Tally functions")
        with tally_ci.runtime(voting,passwords["voting_tally_login"])() as conn:
            check(conn.execute("SELECT NOT(rolsuper OR rolinherit OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls),NOT EXISTS(SELECT 1 FROM pg_auth_members WHERE member=r.oid) FROM pg_roles r WHERE rolname=current_user").fetchone() == (True,True),"Unsafe Tally runtime role")
            check(conn.execute("SELECT count(*) FROM pg_namespace n WHERE n.nspname IN ('voting','voting_admin','voting_tally','public') AND has_schema_privilege(current_user,n.oid,'CREATE')").fetchone() == (0,),"Tally schema CREATE allowed")
        for sql in ("UPDATE voting.accepted_ballots SET receipt_hash=receipt_hash", "INSERT INTO voting.accepted_ballots DEFAULT VALUES"):
            real.deny(tally_ci.runtime(voting,passwords["voting_tally_login"]),sql)
        audit = guard.http(origin,base+"/audit",200,token=token)["events"]
        check({"CONFIG_FROZEN","ELECTION_OPENED","ELECTION_CLOSED","ELECTION_TALLIED"} <= {x["event_type"] for x in audit},"Lifecycle audit missing")
        for event in ("ELECTION_OPENED","ELECTION_CLOSED","ELECTION_TALLIED"):
            rows = [row for row in audit if row["event_type"] == event]
            actor = operator if event == "ELECTION_TALLIED" else principal
            check(len(rows) == 1 and rows[0]["actor_principal_id"] == str(actor)
                  and rows[0]["actor_type"] == ("TALLY_OPERATOR" if event == "ELECTION_TALLIED" else "ADMIN"),"Audit actor mismatch")
        tally_http(tally_origin,"auth/logout",204,token=tally_token,body={})
        tally_http(tally_origin,"auth/me",401,token=tally_token)
        guard.http(origin,"/api/v1/admin/auth/logout",204,method="POST",data={},token=token)
        checkpoint("acl")
        stage[0] = "cleanup"
    ids = real.vote_ci.docker("ps","--all","--no-trunc","--format","{{.ID}}").splitlines()
    check(not directory.exists() and ra.container_id not in ids and voting.container_id not in ids,"Owned cleanup incomplete")
    checkpoint("cleanup")


def verify_database(db, election, result, pin, evidence):
    with db.voting_fixture() as conn:
        check(conn.execute("SELECT e.status,c.phase,c.ra_ready FROM voting.elections e JOIN voting_admin.controls c USING(election_id) WHERE election_id=%s",(election,)).fetchone() == ("TALLIED","TALLIED",True),"Tally lifecycle mismatch")
        check(conn.execute("SELECT count(*) FROM voting.tally_jobs WHERE election_id=%s AND status='SUCCEEDED'",(election,)).fetchone() == (1,),"Multiple successful jobs")
        check(conn.execute("SELECT count(*) FROM voting.tally_jobs WHERE election_id=%s",(election,)).fetchone() == (1,),"Unexpected extra tally jobs")
        check(conn.execute("SELECT count(*) FROM voting.final_snapshots WHERE election_id=%s",(election,)).fetchone() == (1,),"Unexpected extra snapshots")
        check(conn.execute("SELECT count(*) FROM voting.tally_reports WHERE election_id=%s",(election,)).fetchone() == (1,),"Multiple reports")
        check(conn.execute("SELECT count(*) FROM voting.voting_audit_events WHERE election_id=%s AND event_type IN ('SNAPSHOT_FINALIZED','ELECTION_TALLIED')",(election,)).fetchone() == (2,),"Tally audit missing")
        row = conn.execute("SELECT d.bytes,f.snapshot_digest,f.manifest_bytes,f.manifest_signature,f.signing_key_id FROM voting.final_snapshots f JOIN voting_tally.snapshot_data d USING(snapshot_id) WHERE f.election_id=%s AND f.status='FINALIZED'",(election,)).fetchone()
        check(row is not None,"Finalized snapshot missing")
        raw, unsigned, signature = bytes(row[0]), bytes(row[2]), bytes(row[3])
        snapshot, manifest = strict_json(raw), strict_json(unsigned)
        digest = hashlib.sha256(raw).hexdigest()
        ed25519.Ed25519PublicKey.from_public_bytes(pin).verify(signature,b"EVOTE-SNAPSHOT-v1\0" + unsigned)
        check(raw == rfc8785.dumps(snapshot) and unsigned == rfc8785.dumps(manifest)
              and bytes(row[1]).hex() == digest == result["report"]["snapshot_digest"]
              and manifest == {"manifest_version":1,"election_id":str(election),"election_config_digest":result["report"]["election_config_digest"],
                  "snapshot_schema_version":1,"snapshot_digest":digest,"ballot_count":2,"digest_algorithm":"SHA-256",
                  "signature_algorithm":"Ed25519","signing_key_id":"combined-test-snapshot"}
              and row[4] == "combined-test-snapshot" and len(snapshot["ballots"]) == 2,"Snapshot/report binding mismatch")
        check(snapshot["election_id"] == str(election) and snapshot["election_config_digest"] == result["report"]["election_config_digest"],"Snapshot configuration mismatch")
        check((evidence / (digest + ".json")).read_bytes() == rfc8785.dumps({"snapshot":snapshot,"manifest":manifest,"signature":b64encode(signature)}),"Independent evidence mismatch")
        receipts = conn.execute("SELECT encode(receipt_hash,'hex') FROM voting.accepted_ballots WHERE election_id=%s",(election,)).fetchall()
        check(sorted(b["receipt_hash"] for b in snapshot["ballots"]) == sorted(r[0] for r in receipts),"Snapshot committed set mismatch")
        row = conn.execute("SELECT r.report_bytes,r.report_digest,p.signature FROM voting.tally_reports r JOIN voting_tally.report_evidence p USING(tally_id) WHERE r.election_id=%s",(election,)).fetchone()
        check(row is not None and bytes(row[0]) == rfc8785.dumps(result["report"]) and bytes(row[1]).hex() == result["report_digest"] and bytes(row[2]) == b64decode(result["signature"],64),"Committed report evidence mismatch")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--allow-ephemeral-ci-databases",action="store_true",required=True)
    parser.add_argument("--node",type=Path)
    parser.add_argument("--signer-binary",type=Path)
    roles = parser.add_mutually_exclusive_group()
    roles.add_argument("--serve-tally",action="store_true",help=argparse.SUPPRESS)
    roles.add_argument("--serve-ra",action="store_true",help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    stage = ["preflight"]
    try:
        root = require_ci()
        logging.disable(logging.CRITICAL)
        def terminate(_signal,_frame): raise KeyboardInterrupt()
        signal.signal(signal.SIGTERM,terminate)
        if args.serve_tally: serve_tally()
        elif args.serve_ra: serve_ra()
        else:
            real.vote_ci.verify_dependencies()
            check(args.node is not None and args.node.is_file() and args.signer_binary is not None
                  and args.signer_binary.is_file() and not args.signer_binary.is_symlink()
                  and args.signer_binary.resolve().is_relative_to(root),"Reviewed native executables required")
            run(args.node,args.signer_binary,stage)
    except BaseException as error: raise SystemExit(failure(stage[0],error)) from None


if __name__ == "__main__": main()
