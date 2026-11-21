"""Hosted-only composition of reviewed real voting/Tally and publication services.

No selectable database targets, secret argv/env, seeded ballots or new crypto.
Child configuration is bounded and private; Board never receives private keys.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from copy import deepcopy
import hashlib
import json
import logging
import os
from pathlib import Path
import re
import secrets
import signal
import sys
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import httpx
import psycopg
import rfc8785
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from pydantic import SecretStr

from backend.admin.auth import token_digest
from backend.board.http import create_board_app, create_publication_app
from backend.board.launcher import EncryptedPublicationSigner
from backend.board.service import Board, Publisher, Store
from backend.board.verification import Trust, BoardError, MAX_BYTES, decode, from_input, publication_manifest, verify, receipt_status
from backend.crypto.credential_protocol import b64decode, b64encode, strict_json
from scripts import voting_tally_e2e as journey, board_postgres_ci as board_ci

guard, real, check = journey.guard, journey.real, journey.check
STAGES = journey.STAGES | {"publication_migration", "publisher_authorization", "publication_evidence",
    "publication_rollback", "publication_concurrent", "public_verification", "publication_immutable", "board_acl"}
COMMON = {"target", "password", "trust"}
FIELDS = {"board": COMMON, "publisher": COMMON | {"key", "unlock", "evidence"}}
TRUST_FIELDS = {"authority", "evidence", "evidence_key_id", "publication", "publication_key_id"}
ACL_CHECKS = {"board_acl_role_attributes", "board_acl_schema_create", "board_acl_function_execute",
    "board_acl_direct_sql", "board_acl_public_grants", "board_acl_function_metadata", "board_acl_audit_actor"}
ACL_SQLSTATES = {"42501", "25006", "42704", "42883", "3F000", "42P01", "40001", "40P01", "55P03", "57014"}


def require_ci():
    root = journey.require_ci()
    check(not any(k.startswith(("BOARD_DEMO_", "PUBLICATION_DEMO_")) for k in os.environ), "Inherited publication configuration refused")
    return root


def checkpoint(stage, state):
    check(stage in STAGES, "Unknown checkpoint")
    state[0] = stage
    print("PASS: full_election_e2e checkpoint=" + stage, flush=True)


def failure(stage, error):
    label = stage if stage in STAGES else "preflight"
    identifier = getattr(error, "board_acl_check", None)
    if label == "board_acl" and isinstance(identifier, str) and identifier in ACL_CHECKS:
        root = getattr(error, "orig", None) or error
        category = "database_error" if isinstance(root, psycopg.Error) else "assertion_error"
        state = getattr(root, "sqlstate", None)
        state = state if isinstance(state, str) and state in ACL_SQLSTATES else "unavailable"
        return f"FAIL: full_election_e2e stage=board_acl check={identifier} category={category} sqlstate={state}"
    return guard.failure("preflight", error).replace("admin_voter_e2e stage=preflight", "full_election_e2e stage=" + label)


@contextmanager
def acl_check(identifier):
    check(isinstance(identifier, str) and identifier in ACL_CHECKS, "Unknown ACL check")
    try: yield
    except Exception as error:
        existing = getattr(error, "board_acl_check", None)
        if not isinstance(existing, str) or existing not in ACL_CHECKS:
            error.board_acl_check = identifier
        raise  # Preserve the exception, SQL and transaction behavior; annotate only.


def runtime_role(conn, login):
    """Validate the exact reviewed login policy, including PG18 membership options."""
    ballot = login == "voting_ballot_login"
    check(conn.execute("SELECT current_user,rolcanlogin,NOT(rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls),rolinherit FROM pg_roles WHERE rolname=current_user").fetchone()
        == (login,True,True,ballot), "Unsafe runtime role")
    rows = conn.execute("SELECT parent.rolname,child.rolname,m.admin_option,m.inherit_option,m.set_option FROM pg_auth_members m JOIN pg_roles parent ON parent.oid=m.roleid JOIN pg_roles child ON child.oid=m.member WHERE m.member=(SELECT oid FROM pg_roles WHERE rolname=current_user) OR m.roleid=(SELECT oid FROM pg_roles WHERE rolname=current_user)").fetchall()
    expected = [("voting_ballot_service","voting_ballot_login",False,True,False)] if ballot else []
    check(rows == expected, "Unexpected runtime role membership")
    if ballot:
        # The inherited capability role must itself have no parents, elevated
        # attributes, login, or members other than this one reviewed login.
        check(conn.execute("SELECT NOT(rolcanlogin OR rolinherit OR rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls),NOT EXISTS(SELECT 1 FROM pg_auth_members WHERE member=r.oid OR (roleid=r.oid AND member<>(SELECT oid FROM pg_roles WHERE rolname=current_user))) FROM pg_roles r WHERE rolname='voting_ballot_service'").fetchone()
            == (True,True), "Unsafe inherited capability role")


def trust_value(value):
    check(type(value) is dict and set(value) == TRUST_FIELDS, "Explicit public trust set required")
    trust = Trust(b64decode(value["authority"],32), b64decode(value["evidence"],32), value["evidence_key_id"],
        b64decode(value["publication"],32), value["publication_key_id"])
    trust.validate()
    return trust


def configuration(role, value):
    require_ci()
    check(role in FIELDS and type(value) is dict and set(value) == FIELDS[role], "Restricted service configuration required")
    owned = guard.designated("voting", value["target"])
    trust = trust_value(value["trust"])
    check(type(value["password"]) is str and bool(value["password"]), "Explicit credential required")
    if role == "publisher":
        journey.private_path(value["key"], "test-publication.encrypted.pem")
        directory = Path(value["evidence"])
        check(not directory.is_symlink() and directory.resolve().is_relative_to(require_ci())
            and directory.is_dir() and directory.stat().st_mode & 0o777 == 0o700, "Private evidence directory required")
    return owned, trust


def serve(role):
    require_ci()
    line = sys.stdin.readline(16385)
    check(0 < len(line) <= 16384, "Bounded private configuration required")
    config = strict_json(line.encode())
    owned, trust = configuration(role, config)
    login = "voting_board_login" if role == "board" else "voting_publication_login"
    store = Store(board_ci.runtime(owned, login, SecretStr(config["password"])))
    if role == "publisher":
        signer = EncryptedPublicationSigner(config["key"], SecretStr(config["unlock"]), trust.publication)
        app = create_publication_app(Publisher(store, trust, signer, Path(config["evidence"])))
    else:
        app = create_board_app(Board(store, trust))
    del config
    with real.http_service(app) as origin:
        print(json.dumps({"origin": origin}), flush=True)
        check(sys.stdin.readline(128) == '{"stop":true}\n', "Explicit shutdown required")


@contextmanager
def service_process(role, config):
    configuration(role, config)
    with real.child([sys.executable, str(Path(__file__).resolve()), "--allow-ephemeral-ci-databases", "--serve-role", role]) as process:
        journey.send(process, config)
        response = journey.read_line(process, limit=1024, timeout=25)
        check(type(response) is dict and set(response) == {"origin"}
            and re.fullmatch(r"http://127\.0\.0\.1:[0-9]{1,5}", response["origin"]), "Loopback service required")
        try: yield response["origin"]
        finally:
            journey.send(process, {"stop": True})
            check(process.wait(timeout=25) == 0, "Service shutdown failed")


def http(origin, path, expected=200, *, method="GET", token=None, body=None):
    check(re.fullmatch(r"http://127\.0\.0\.1:[0-9]{1,5}", origin)
        and re.fullmatch(r"/api/v1/(board|publication)(?:[a-z0-9/?.=&_-]*)", path), "Restricted loopback API required")
    headers = {"Accept": "application/json"}
    if token is not None: headers["Authorization"] = "Bearer " + token
    # Each call has an independent cookie-free client; public requests carry no identity.
    with httpx.Client(trust_env=False, follow_redirects=False, timeout=60) as client:
        with client.stream(method, origin + path, headers=headers, json=body) as response:
            if response.status_code != expected:
                error = AssertionError("Unexpected service status")
                error.http_status = response.status_code if response.status_code in real.HTTP_STATUSES else "unavailable"
                raise error
            check(response.headers.get("Cache-Control") == "no-store", "Missing no-store")
            if expected >= 400: return None  # Never expose response text in diagnostics.
            raw = bytearray()
            for part in response.iter_bytes():
                raw.extend(part)
                check(len(raw) <= MAX_BYTES, "Bounded public response required")
            return decode(bytes(raw))


def expect_invalid(bundle, election, trust):
    try: verify(bundle, str(election), trust)
    except BoardError: return
    raise AssertionError("Invalid evidence accepted")


class Publication:
    """Trusted fixture extension; default voting/Tally gate has no extension."""
    def __init__(self, stage): self.stage = stage

    def provision(self, owned, bootstrap, passwords):
        self.stage[0] = "publication_migration"
        owned.verify()
        for role in ("voting_publication_login", "voting_board_login"):
            passwords[role] = SecretStr(secrets.token_urlsafe(48))
            guard.admin_ci.provision_role(real.vote_ci, owned.target, bootstrap, role, passwords[role])
        board_ci.migrate(owned.target, passwords["voting_migrator_login"])
        checkpoint("publication_migration", self.stage)

    @contextmanager
    def services(self, owned, passwords, db, directory, evidence, pin, snapshot_pin, principal,
                 admin_origin, admin_config, admin_password, election, tally_token):
        self.db, self.election, self.evidence, self.directory = db, election, evidence, directory
        self.passwords, self.principal = passwords, principal
        private = ed25519.Ed25519PrivateKey.generate()
        public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.trust_config = dict(authority=b64encode(pin), evidence=b64encode(snapshot_pin), evidence_key_id="combined-test-snapshot",
            publication=b64encode(public), publication_key_id="full-election-test-publication")
        self.trust = trust_value(self.trust_config)
        path = directory / "test-publication.encrypted.pem"
        unlock = guard.write_key(path, private)
        del private
        self.sign = EncryptedPublicationSigner(path, unlock, public)
        self.publisher = board_ci.runtime(owned, "voting_publication_login", passwords["voting_publication_login"])
        self.reader = board_ci.runtime(owned, "voting_board_login", passwords["voting_board_login"])
        self.admin = guard.connection(owned, "voting_admin_login", passwords["voting_admin_login"])
        self.tally = journey.tally_ci.runtime(owned, passwords["voting_tally_login"])
        with db.voting_fixture() as conn:
            conn.execute("INSERT INTO voting_board.publishers(admin_id,is_active) VALUES(%s,true)", (principal,))
            outsider = uuid4()
            conn.execute("INSERT INTO voting_admin.principals(admin_id,role,is_active) VALUES(%s,'ELECTION_ADMIN',true)", (outsider,))
        self.token = guard.http(admin_origin, "/api/v1/admin/auth/login", 200, method="POST",
            data={"username":admin_config["username"], "password":admin_password})["access_token"]
        self.admin_origin = admin_origin
        # A real separately authenticated Admin session, deliberately unenrolled as Publisher.
        other_password, salt = secrets.token_urlsafe(48), secrets.token_bytes(16)
        other_config = dict(admin_config, principal=str(outsider), username="synthetic-unenrolled-publisher", salt=b64encode(salt),
            digest=b64encode(hashlib.scrypt(other_password.encode(),salt=salt,n=2**14,r=8,p=1,dklen=32)))
        common = dict(target=owned.wire(), trust=self.trust_config)
        with service_process("publisher", dict(common, password=passwords["voting_publication_login"].get_secret_value(),
                key=str(path), unlock=unlock.get_secret_value(), evidence=str(evidence))) as self.pub_origin, \
            service_process("board", dict(common, password=passwords["voting_board_login"].get_secret_value())) as self.board_origin, \
            guard.service_process("admin", other_config) as other_origin:
            self.stage[0] = "publisher_authorization"
            other = guard.http(other_origin,"/api/v1/admin/auth/login",200,method="POST",
                data={"username":other_config["username"],"password":other_password})["access_token"]
            self.publish(403, other)
            self.publish(401, tally_token)
            self.publish(409)
            self.get("/results",404)
            guard.http(other_origin,"/api/v1/admin/auth/logout",204,method="POST",data={},token=other)
            self.secret_checks = [other, other_password, self.token, admin_password, str(principal), str(outsider),
                unlock.get_secret_value(), *(v.get_secret_value() for v in passwords.values())]
            checkpoint("publisher_authorization", self.stage)
            try: yield self
            finally: guard.http(admin_origin,"/api/v1/admin/auth/logout",204,method="POST",data={},token=self.token)

    def publish(self, status=200, token=None):
        return http(self.pub_origin, "/api/v1/publication/elections/"+str(self.election)+"/publish", status,
            method="POST", token=self.token if token is None else token, body={})

    def get(self, suffix, status=200, **kwargs):
        return http(self.board_origin, "/api/v1/board/"+str(self.election)+suffix, status, **kwargs)

    def reject_voter(self, token):
        self.publish(401, token)

    def finish(self, signed, receipts, voters, operator, tally_token):
        election = self.election
        self.stage[0] = "publication_evidence"
        board_ci.aggregate_rows(self.db.voting_fixture, election, "TALLIED")
        self.get("/evidence",404)
        original = self.evidence / (signed["report"]["snapshot_digest"]+".json")
        raw = original.read_bytes()
        hidden = self.evidence / "temporarily-unavailable.json"
        original.rename(hidden)
        try: self.publish(503); board_ci.aggregate_rows(self.db.voting_fixture,election,"TALLIED")
        finally: hidden.rename(original)
        try:
            original.write_bytes(b"{}")
            self.publish(503)
            board_ci.aggregate_rows(self.db.voting_fixture,election,"TALLIED")
        finally: original.write_bytes(raw)
        source = Store(self.publisher).call("input",token_digest(self.token),election)["input"]
        bundle = from_input(source,str(election))
        manifest = publication_manifest(bundle,self.trust)
        signature = self.sign(b"EVOTE-RESULTS-v1\0"+rfc8785.dumps(manifest))
        bundle["publication"] = dict(manifest=manifest,signature=b64encode(signature))
        verify(bundle,str(election),self.trust)
        raw_bundle = rfc8785.dumps(bundle)
        args = (token_digest(self.token),election,rfc8785.dumps(manifest),signature,raw_bundle)
        checkpoint("publication_evidence", self.stage)
        self.stage[0] = "publication_rollback"
        with self.publisher() as conn:
            check(bytes(conn.execute(Store.QUERIES["finish"],args).fetchone()[0]) == raw_bundle,"Pending publication mismatch")
            self.get("/results",404)
            conn.rollback()
        board_ci.aggregate_rows(self.db.voting_fixture,election,"TALLIED")
        checkpoint("publication_rollback", self.stage)
        self.stage[0] = "publication_concurrent"
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(lambda _:self.publish(),range(4)))
        check(all(r == results[0] for r in results) and self.publish() == results[0],"Publication retry changed evidence")
        board_ci.aggregate_rows(self.db.voting_fixture,election,"PUBLISHED")
        check(results[0]["bundle_digest"] == hashlib.sha256(raw_bundle).hexdigest(),"Committed bundle differs")
        checkpoint("publication_concurrent", self.stage)
        self.stage[0] = "public_verification"
        public = self.get("/evidence")
        verify(public,str(election),self.trust)
        check(rfc8785.dumps(public) == raw_bundle,"Published evidence differs")
        check(public["tally"] == {k:signed[k] for k in ("report","report_digest","signature","signing_key_id")},"Aggregate evidence changed")
        check(self.get("/results")["tally"] == public["tally"] and self.get("/configuration") == public["configuration"],"Public endpoint mismatch")
        check(self.get("/snapshots/final") == public["snapshot"] and self.get("/snapshots/final/manifest") == public["snapshot_evidence"],"Snapshot endpoint mismatch")
        check(set(receipts) == {r["receipt_hash"] for r in public["snapshot"]["ballots"]} and len(receipts) == 2,"Receipt set mismatch")
        for receipt in receipts:
            check(receipt_status(public,str(election),receipt,self.trust) == "VERIFIED","Independent receipt check failed")
            check(self.get("/receipts/"+receipt)["record"]["receipt_hash"] == receipt,"Receipt HTTP mismatch")
        unknown = "0"*64
        check(unknown not in receipts and receipt_status(public,str(election),unknown,self.trust) == "NOT_FOUND","Unknown receipt falsely verified")
        self.get("/receipts/"+unknown,404)
        page = self.get("/ballots?limit=1")
        next_page = self.get("/ballots?limit=1&cursor="+page["next_cursor"])
        check(page["records"]+next_page["records"] == public["snapshot"]["ballots"] and next_page["next_cursor"] is None,"Pagination mismatch")
        check(http(self.board_origin,"/api/v1/board")["elections"] == [{"election_id":str(election),"status":"PUBLISHED"}],"Published discovery mismatch")
        self.independent_checks(public, receipts)
        secret_values = self.secret_checks + [str(operator), tally_token]
        for _, token, voter, username, password in voters: secret_values.extend((token,str(voter),username,password))
        check(all(s not in raw_bundle.decode() for s in secret_values),"Public identity/secret leakage")
        for record in public["snapshot"]["ballots"]:
            check(set(record) == {"election_id","serial","envelope","prepared_msg","signature","receipt_hash"},"Unexpected public individual metadata")
        for method in ("POST","PUT","PATCH","DELETE"):
            self.get("/results",405,method=method,body={})
        self.get("/results",400,token=self.token)
        checkpoint("public_verification", self.stage)
        self.immutability(args, bundle)
        self.acl()
        with self.db.voting_fixture() as conn:
            check(conn.execute("SELECT e.status,c.phase,c.ra_ready FROM voting.elections e JOIN voting_admin.controls c USING(election_id) WHERE election_id=%s",(election,)).fetchone() == ("PUBLISHED","PUBLISHED",True),"Publication lifecycle mismatch")
        # Original browser contexts are acknowledged only after these checks; they
        # recover their original receipts and prove duplicate 409 in PUBLISHED.

    def independent_checks(self, public, receipts):
        for field in ("snapshot","snapshot_evidence","tally","publication"):
            bad = deepcopy(public)
            if field == "snapshot": bad[field]["ballots"] = []
            else: bad[field]["signature"] = "A"*86
            expect_invalid(bad,self.election,self.trust)
        missing = deepcopy(public); del missing["publication"]
        expect_invalid(missing,self.election,self.trust)
        expect_invalid(public,uuid4(),self.trust)
        for field in ("authority","evidence","publication"):
            wrong = dict(self.trust_config, **{field:b64encode(ed25519.Ed25519PrivateKey.generate().public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw))})
            expect_invalid(public,self.election,trust_value(wrong))
        # Execute the existing offline verifier as an independent process, using
        # only public data and independently provisioned pins, never API keys.
        bundle_path, trust_path = self.directory/"public-bundle.json", self.directory/"public-trust.json"
        bundle_path.write_bytes(rfc8785.dumps(public)); trust_path.write_bytes(rfc8785.dumps(self.trust_config))
        for receipt in receipts:
            result = real.subprocess.run([sys.executable,str(ROOT/"scripts/verify_publication.py"),"--bundle",str(bundle_path),
                "--trusted-keys",str(trust_path),"--election-id",str(self.election),"--receipt",receipt],
                capture_output=True,text=True,timeout=60,check=False)
            check(result.returncode == 0 and result.stdout.strip() == '{"status": "VERIFIED"}' and not result.stderr,"Offline verifier failed")

    def immutability(self, args, bundle):
        self.stage[0] = "publication_immutable"
        conflicting = deepcopy(bundle); conflicting["publication"]["signature"] = b64encode(bytes(64))
        try:
            with self.publisher() as conn: conn.execute(Store.QUERIES["finish"],(*args[:3],bytes(64),rfc8785.dumps(conflicting)))
        except psycopg.Error as error: check(error.sqlstate == "P6403","Unexpected conflict rejection")
        else: raise AssertionError("Conflicting publication accepted")
        for query,state in (("UPDATE voting.elections SET status='TALLIED' WHERE election_id=%s","P6403"),
            ("UPDATE voting.publications SET manifest_bytes=manifest_bytes WHERE election_id=%s","P6405"),
            ("UPDATE voting.final_snapshots SET manifest_bytes=manifest_bytes WHERE election_id=%s","P5303"),
            ("UPDATE voting.tally_reports SET report_bytes=report_bytes WHERE election_id=%s","P5303"),
            ("DELETE FROM voting.voting_audit_events WHERE election_id=%s AND event_type='ELECTION_PUBLISHED'","P6405")):
            try:
                with self.db.voting_fixture() as conn: conn.execute(query,(self.election,))
            except psycopg.Error as error: check(error.sqlstate == state,"Unexpected immutability rejection")
            else: raise AssertionError("Immutable evidence changed")
        check(self.publish()["bundle_digest"] == hashlib.sha256(rfc8785.dumps(bundle)).hexdigest(),"Immutable retry differs")
        checkpoint("publication_immutable", self.stage)

    def acl(self):
        self.stage[0] = "board_acl"
        for factory, login, expected in ((self.reader,"voting_board_login",{"read_public","catalogue"}),
            (self.publisher,"voting_publication_login",{"publication_input","finish"}), (self.admin,"voting_admin_login",set()),
            (self.tally,"voting_tally_login",set()),(self.db.voting_runtime,"voting_ballot_login",set())):
            with acl_check("board_acl_role_attributes"), factory() as conn:
                runtime_role(conn,login)
                with acl_check("board_acl_schema_create"):
                    check(conn.execute("SELECT count(*) FROM pg_namespace n WHERE n.nspname IN ('public','voting','voting_admin','voting_tally','voting_board') AND has_schema_privilege(current_user,n.oid,'CREATE')").fetchone() == (0,),"Runtime schema CREATE allowed")
                with acl_check("board_acl_function_execute"):
                    rows = conn.execute("SELECT p.proname FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='voting_board' AND has_function_privilege(current_user,p.oid,'EXECUTE')").fetchall()
                    check({r[0] for r in rows} == expected,"Unexpected Board execution surface")
            with acl_check("board_acl_direct_sql"):
                for query in ("SELECT * FROM voting.accepted_ballots","DELETE FROM voting.publications","SELECT * FROM voting_board.evidence","SET ROLE voting_owner"):
                    real.deny(factory,query)
        with acl_check("board_acl_public_grants"), self.db.voting_fixture() as conn:
            check(conn.execute("SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace CROSS JOIN LATERAL aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a WHERE n.nspname='voting_board' AND a.grantee=0").fetchone() == (0,),"PUBLIC EXECUTE allowed")
            paths = {
                '_actor':'pg_catalog, voting_board, voting_admin, pg_temp',
                '_input':'pg_catalog, voting_board, voting, voting_tally, voting_admin, pg_temp',
                'finish':'pg_catalog, voting_board, voting, voting_admin, voting_tally, pg_temp',
                **dict.fromkeys(('publication_input','read_public','catalogue'),'pg_catalog, voting_board, voting, pg_temp'),
                **dict.fromkeys(('immutable','terminal_state'),'pg_catalog, voting_board, pg_temp')}
            with acl_check("board_acl_function_metadata"):
                rows = conn.execute("SELECT p.proname,pg_get_userbyid(p.proowner),p.prosecdef,p.proconfig FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='voting_board'").fetchall()
                check(len(rows) == 8 and {row[0] for row in rows} == set(paths)
                    and all(owner == 'voting_owner' and secure and config == ['search_path='+paths[name]]
                        for name,owner,secure,config in rows),"Unsafe Board definer")
            with acl_check("board_acl_audit_actor"):
                check(conn.execute("SELECT actor_principal_id,actor_type FROM voting.voting_audit_events WHERE election_id=%s AND event_type='ELECTION_PUBLISHED'",(self.election,)).fetchall() == [(self.principal,'ADMIN')],"Publisher audit actor mismatch")
        checkpoint("board_acl", self.stage)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--allow-ephemeral-ci-databases",action="store_true",required=True)
    parser.add_argument("--node",type=Path)
    parser.add_argument("--signer-binary",type=Path)
    parser.add_argument("--serve-role",choices=tuple(FIELDS),help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    stage = ["preflight"]
    try:
        root = require_ci()
        logging.disable(logging.CRITICAL)
        def terminate(_signal,_frame): raise KeyboardInterrupt()
        signal.signal(signal.SIGTERM,terminate)
        if args.serve_role: serve(args.serve_role)
        else:
            real.vote_ci.verify_dependencies()
            check(args.node is not None and args.node.is_file() and args.signer_binary is not None
                and args.signer_binary.is_file() and not args.signer_binary.is_symlink()
                and args.signer_binary.resolve().is_relative_to(root),"Reviewed native executables required")
            journey.run(args.node,args.signer_binary,stage,publication=Publication(stage))
            checkpoint("cleanup",stage)
    except BaseException as error: raise SystemExit(failure(stage[0],error)) from None


if __name__ == "__main__": main()
