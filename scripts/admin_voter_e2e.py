"""Hosted-only real Admin -> RA/CIRCL -> Chromium -> Voting integration.

No production launcher/configuration discovery, service doubles, or selectable
database endpoints. Imports perform no I/O. Private control uses inherited pipes.
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
import sys
import tempfile
import threading
from urllib.error import HTTPError
from urllib.request import Request, build_opener, ProxyHandler, HTTPRedirectHandler
from uuid import UUID, uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import psycopg
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from pydantic import SecretStr

from backend.admin.auth import AdminAuthentication
from backend.admin.router import create_admin_app
from backend.admin.service import AdminService, ManifestAuthority
from backend.admin.store import VotingAdminStore, RAPublisherStore
from backend.crypto.credential_protocol import b64decode, b64encode, canonical_manifest, strict_json, verify_manifest
from scripts import admin_postgres_ci as admin_ci, real_voting_e2e as real

check = real.check
SCENARIOS = real.SCENARIOS
STAGES = real.STAGES | {"admin_migrations", "identities", "admin_login", "admin_draft",
    "admin_finalize", "open_interrupted", "open_reconciled", "close_interrupted",
    "close_reconciled", "admin_audit", "database_assertions"}
ROLE_FIELDS = {
    "admin": {"voting", "ra", "voting_password", "publisher_password", "principal", "username",
              "salt", "digest", "authority_key", "unlock", "pin", "keysets"},
    "ra": {"target", "pin", "auth_config", "auth_password", "issuance_password", "encrypted_key",
           "unlock", "signer", "key_id", "election_id"},
    "voting": {"target", "pin", "password"},
}


def require_ci():
    directory = real.require_ci()
    check(not any(k.startswith("ADMIN_DEMO_") for k in os.environ), "Inherited Admin configuration refused")
    check(sys.flags.optimize == 0, "Assertions must remain enabled")
    return directory


def failure(stage, error):
    stage = stage if stage in STAGES else "preflight"
    result = real.failure(stage if stage in real.STAGES else "preflight", error).replace(
        "real_voting_e2e stage=" + (stage if stage in real.STAGES else "preflight"),
        "admin_voter_e2e stage=" + stage)
    status = getattr(error, "http_status", None)
    if " http_status=" not in result and (type(status) is int and status in real.HTTP_STATUSES or status == "unavailable"):
        result += " http_status=" + str(status)
    return result


def checkpoint(stage, scenario=None):
    check(stage in STAGES and (scenario is None or scenario in SCENARIOS), "Invalid checkpoint")
    print("PASS: admin_voter_e2e checkpoint=" + stage + (" scenario=" + scenario if scenario else ""), flush=True)


@dataclass(frozen=True)
class OwnedDatabase:
    kind: str
    target: object
    container_id: str
    container_name: str

    def verify(self):
        require_ci()
        check(self.kind in {"ra", "voting"}, "Invalid database kind")
        self.target.validate()
        check(re.fullmatch(r"evote-voting-ci-[0-9a-f]{32}", self.container_name), "Invalid owned container name")
        info = real.vote_ci.owned_container(self.container_id, self.container_name, self.target.marker)
        ports = info["NetworkSettings"]["Ports"]["5432/tcp"]
        check(len(ports) == 1 and ports[0]["HostIp"] == "127.0.0.1"
              and int(ports[0]["HostPort"]) == self.target.port, "Container endpoint mismatch")

    def wire(self):
        return dict(vars(self.target), container_id=self.container_id, container_name=self.container_name)


def designated(kind, value):
    check(kind in {"ra", "voting"} and type(value) is dict and set(value) ==
          {"database", "marker", "port", "container_id", "container_name"}, "Invalid owned target")
    target = (real.ra_ci.Target if kind == "ra" else real.vote_ci.Target)(
        value["database"], value["marker"], value["port"])
    target.validate()
    check(re.fullmatch(r"[0-9a-f]{64}", value["container_id"]) is not None, "Invalid container identifier")
    check(re.fullmatch(r"evote-voting-ci-[0-9a-f]{32}", value["container_name"]) is not None, "Invalid container name")
    return OwnedDatabase(kind, target, value["container_id"], value["container_name"])


def discover(kind, target):
    require_ci()
    ids = real.vote_ci.docker("ps", "--all", "--no-trunc", "--filter",
        "label=secure-evoting-voting-ci=" + target.marker, "--format", "{{.ID}}").splitlines()
    check(len(ids) == 1 and re.fullmatch(r"[0-9a-f]{64}", ids[0]), "Owned container not unique")
    info = json.loads(real.vote_ci.docker("inspect", ids[0]))
    owned = designated(kind, dict(vars(target), container_id=ids[0], container_name=info[0]["Name"].removeprefix("/")))
    owned.verify()
    return owned


def connection(owned, login, password, *, fixture=False):
    allowed = {"ra": {"ra_migrator_login", "ra_auth_login", "ra_issuance_login", "ra_election_publisher_login"},
               "voting": {"voting_migrator_login", "voting_admin_login", "voting_ballot_login"}}
    check(login in allowed[owned.kind] and fixture == (login == owned.kind + "_migrator_login"), "Restricted connection required")
    check(isinstance(password, SecretStr) and password.get_secret_value(), "Explicit generated credential required")
    owner = owned.kind + "_owner"
    def connect():
        owned.verify()  # Verify container ID, image, tmpfs and loopback mapping on EVERY use.
        conn = psycopg.connect(host="127.0.0.1", port=owned.target.port, dbname=owned.target.database,
            user=login, password=password.get_secret_value(), connect_timeout=5, sslmode="disable",
            options="-c statement_timeout=10000 -c lock_timeout=3000")
        try:
            if fixture: conn.execute("SET LOCAL ROLE " + owner)  # Fixed allowlisted owner only.
            return conn
        except BaseException:
            conn.close()
            raise
    return real.guarded(connect, owned.target, owner, login, fixture=fixture)


def configuration(role, config):
    check(role in ROLE_FIELDS and type(config) is dict and set(config) == ROLE_FIELDS[role], "Invalid isolated service configuration")
    b64decode(config["pin"], 32)
    if role == "admin":
        return designated("voting", config["voting"]), designated("ra", config["ra"])
    return (designated("ra" if role == "ra" else "voting", config["target"]),)


def encrypted_key(path, unlock):
    root = require_ci()
    path = Path(path)
    check(path.name in {"admin-authority.encrypted.pem", "test-ra-key.encrypted.pem"}
          and not path.is_symlink() and path.resolve().is_relative_to(root)
          and path.is_file() and path.stat().st_mode & 0o777 == 0o600, "Private ephemeral key required")
    return serialization.load_pem_private_key(path.read_bytes(), password=unlock.encode())


class AnonymousWire:
    """Passive real upstream header assertion; no response or service replacement."""
    def __init__(self, app):
        self.app, self.requests, self.failed = app, 0, False

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http" and scope["path"].startswith("/api/v1/vote/"):
            forbidden = {b"authorization", b"cookie", b"proxy-authorization", b"x-voter-id",
                b"x-ra-token", b"x-username", b"x-request-id", b"x-admin-token", b"x-admin-id"}
            self.requests += 1
            self.failed |= any(name.lower() in forbidden for name, _ in scope["headers"])
        await self.app(scope, receive, send)


def serve(role):
    require_ci()
    line = sys.stdin.readline(65537)
    check(0 < len(line) <= 65536, "Bounded private service configuration required")
    config = strict_json(line.encode())
    targets = configuration(role, config)
    pin = b64decode(config["pin"], 32)
    with ExitStack() as resources:
        if role == "admin":
            voting, ra = targets
            store = VotingAdminStore(connection(voting, "voting_admin_login", SecretStr(config["voting_password"])))
            publisher = RAPublisherStore(connection(ra, "ra_election_publisher_login", SecretStr(config["publisher_password"])))
            auth = AdminAuthentication(store, UUID(config["principal"]), config["username"],
                b64decode(config["salt"]), b64decode(config["digest"], 32))
            authority = ManifestAuthority(encrypted_key(config["authority_key"], config["unlock"]), pin)
            app = create_admin_app(AdminService(auth, store, publisher, authority, config["keysets"]))
        elif role == "ra":
            ra, = targets
            auth = connection(ra, "ra_auth_login", SecretStr(config["auth_password"]))
            issue = connection(ra, "ra_issuance_login", SecretStr(config["issuance_password"]))
            private = encrypted_key(config["encrypted_key"], config["unlock"])
            signer = real.LocalCIRCLSigner(Path(config["signer"]), private, config["key_id"])
            resources.callback(signer.close)
            del private
            service = real.CredentialIssuanceService(real.PostgreSQLCredentialStore(issue), signer,
                real.CredentialRecovery({"admin-voter-ci": secrets.token_bytes(32)}, "admin-voter-ci"), pin)
            app = real.create_credential_app(config["auth_config"], service, auth_connection_factory=auth,
                catalogue=real.ElectionCatalogue(service.store, pin, [config["election_id"]]))
        else:
            voting, = targets
            runtime = connection(voting, "voting_ballot_login", SecretStr(config["password"]))
            app = AnonymousWire(real.create_voting_app(real.BallotService(real.PostgreSQLBallotStore(runtime), pin)))
        origin = resources.enter_context(real.http_service(app))
        del config
        sys.stdout.write(json.dumps({"origin": origin}) + "\n"); sys.stdout.flush()
        check(sys.stdin.readline(128) == '{"stop":true}\n', "Explicit service shutdown required")
        if role == "voting": check(app.requests > 0 and not app.failed, "Voting upstream identity leakage")


@contextmanager
def service_process(role, config):
    configuration(role, config)
    with real.child([sys.executable, str(Path(__file__).resolve()), "--allow-ephemeral-ci-databases", "--serve-role", role]) as process:
        payload = json.dumps(config)
        check(len(payload) < 65536, "Service configuration too large")
        process.stdin.write(payload + "\n"); process.stdin.flush()
        ready = queue.Queue(maxsize=1)
        def read_ready(): ready.put(process.stdout.readline(1025))
        threading.Thread(target=read_ready, daemon=True).start()
        response = strict_json(ready.get(timeout=25).encode())
        check(type(response) is dict and set(response) == {"origin"}
              and re.fullmatch(r"http://127\.0\.0\.1:[0-9]{1,5}", response["origin"]), "Unsafe service readiness")
        try: yield response["origin"]
        finally:
            process.stdin.write('{"stop":true}\n'); process.stdin.flush()
            check(process.wait(timeout=25) == 0, "Isolated service shutdown failed")


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args): return None


def http(origin, path, expected, *, method="GET", data=None, token=None):
    check(re.fullmatch(r"http://127\.0\.0\.1:[0-9]{1,5}", origin)
          and re.fullmatch(r"/api/v1/(admin|ra)/(?:[a-z0-9/-]+)", path), "Loopback API required")
    headers = {"Accept": "application/json", "Cache-Control": "no-store"}
    if token is not None: headers["Authorization"] = "Bearer " + token
    if data is not None: headers["Content-Type"] = "application/json"
    request = Request(origin + path, method=method, headers=headers,
        data=None if data is None else json.dumps(data).encode())
    try: response = build_opener(ProxyHandler({}), NoRedirect()).open(request, timeout=25)
    except HTTPError as error: response = error
    with response:
        if response.status != expected:
            error = AssertionError("Unexpected API status")
            error.http_status = response.status if response.status in real.HTTP_STATUSES else "unavailable"
            raise error
        check(response.headers.get("Cache-Control") == "no-store", "Missing no-store")
        # Error bodies never enter diagnostics or the private protocol.
        if response.status >= 400 or response.status == 204: return None
        raw = response.read(131073)
        return strict_json(raw)


def write_key(path, private):
    unlock = SecretStr(secrets.token_urlsafe(48))
    with open(path, "xb", opener=lambda p, flags: os.open(p, flags, 0o600)) as stream:
        stream.write(private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(unlock.get_secret_value().encode())))
    return unlock


def keys(directory):
    authority = ed25519.Ed25519PrivateKey.generate()
    pin = authority.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    authority_path = directory / "admin-authority.encrypted.pem"
    authority_unlock = write_key(authority_path, authority)
    catalogue, signing = {}, {}
    for scenario in SCENARIOS:
        folder = directory / scenario; folder.mkdir(mode=0o700)
        ra_private = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        tally_private = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        def public(private, name):
            raw = real.public(private)
            return {"key_id": name, "spki": b64encode(raw), "fingerprint": hashlib.sha256(raw).hexdigest()}
        catalogue[scenario] = {"ra_key": public(ra_private, "admin-voter-ra-" + uuid4().hex),
            "tally_key": public(tally_private, "admin-voter-tally-" + uuid4().hex),
            "private_key_reference": "ephemeral-admin-voter-" + scenario}
        path = folder / "test-ra-key.encrypted.pem"
        signing[scenario] = (path, write_key(path, ra_private))
    # No private RSA or Ed25519 objects are forwarded to other services.
    return pin, authority_path, authority_unlock, catalogue, signing


def identities(db):
    principal, voter = uuid4(), uuid4()
    with db.voting_fixture() as conn:
        conn.execute("INSERT INTO voting_admin.principals(admin_id,role,is_active) VALUES(%s,'ELECTION_ADMIN',true)", (principal,))
    with db.ra_fixture() as conn:
        check(conn.execute("SELECT 1 FROM ra.voters WHERE auth_provider='demo-local' AND auth_subject='demo-voter-001'").fetchone() is None, "Existing voter refused")
        conn.execute("INSERT INTO ra.voters(voter_id,auth_provider,auth_subject,is_active) VALUES(%s,'demo-local','demo-voter-001',true)", (voter,))
    return principal, voter


def policy_state(db, election, phase, ready, enabled):
    with db.voting_fixture() as conn:
        row = conn.execute("SELECT e.status,c.phase,c.ra_ready,encode(f.config_digest,'hex'),f.config_bytes,f.config_signature FROM voting.elections e JOIN voting_admin.controls c USING(election_id) JOIN voting.election_configs f USING(election_id) WHERE e.election_id=%s", (election,)).fetchone()
        check(row is not None and row[:3] == ("DRAFT" if phase == "FROZEN" else phase, phase, ready), "Voting lifecycle mismatch")
    with db.ra_fixture() as conn:
        publication = conn.execute("SELECT config_hash,manifest_bytes,signature,closed FROM ra_admin.publications WHERE election_id=%s", (election,)).fetchone()
        check(publication is not None and bytes(publication[0]).hex() == row[3]
              and bytes(publication[1]) == bytes(row[4]) and bytes(publication[2]) == bytes(row[5]), "Cross-database manifest mismatch")
        policy = conn.execute("SELECT encode(config_hash,'hex'),issuance_enabled FROM ra.credential_policies WHERE election_id=%s", (election,)).fetchone()
        check(policy is None if enabled is None else policy == (row[3], enabled), "RA policy state mismatch")
        check(publication[3] == (phase == "CLOSED" and ready), "Publication tombstone mismatch")


@contextmanager
def publisher_denied(db):
    # Actual permission failure at the second database commit, not a service double.
    signature = "ra_admin.reconcile(uuid,bytea,boolean,uuid)"
    with db.ra_fixture() as conn:
        check(conn.execute("""SELECT EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
            CROSS JOIN LATERAL aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a
            WHERE n.nspname='ra_admin' AND p.proname='reconcile' AND p.proowner='ra_owner'::regrole
            AND p.prosecdef AND a.grantee='ra_election_publisher_login'::regrole
            AND a.privilege_type='EXECUTE' AND NOT a.is_grantable)""").fetchone() == (True,), "Expected explicit publisher grant missing")
        conn.execute("REVOKE EXECUTE ON FUNCTION " + signature + " FROM ra_election_publisher_login")
    try: yield
    finally:
        with db.ra_fixture() as conn:
            conn.execute("GRANT EXECUTE ON FUNCTION " + signature + " TO ra_election_publisher_login")


def create_election(origin, token, db, principal, voter, scenario, pin, catalogue, stage):
    with db.voting_fixture() as conn: now = conn.execute("SELECT clock_timestamp()").fetchone()[0].replace(microsecond=0)
    fields = {"title": "Synthetic Admin-to-Voter " + scenario,
        "opens_at": (now - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "closes_at": (now + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")}
    draft = dict(fields, closes_at=(now + timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ"))
    row = http(origin, "/api/v1/admin/elections", 201, method="POST", data=draft, token=token)
    election = UUID(row["election_id"])
    base = "/api/v1/admin/elections/" + str(election)
    for name in ("A", "B"):
        row = http(origin, base + "/candidates", 200, method="POST", token=token,
            data={"revision": row["revision"], "candidate_name": "Synthetic E2E candidate " + name})
    row = http(origin, base, 200, method="PUT", token=token, data=dict(fields, revision=row["revision"]))
    check(row["opens_at"] == fields["opens_at"] and row["closes_at"] == fields["closes_at"], "Window update not applied")
    approved = http(origin, "/api/v1/admin/keysets", 200, token=token)
    check(next(k for k in approved["keysets"] if k["keyset_id"] == scenario) ==
          {"keyset_id": scenario, "ra_key": catalogue[scenario]["ra_key"], "tally_key": catalogue[scenario]["tally_key"]}, "Approved keyset mismatch")
    checkpoint("admin_draft", scenario)
    stage[0] = "admin_finalize"
    row = http(origin, base + "/finalize", 200, method="POST", token=token,
        data={"revision": row["revision"], "keyset_id": scenario})
    manifest, digest = verify_manifest(row["bundle"], pin, str(election))
    check(row["phase"] == "FROZEN" and not row["ra_ready"] and row["config_hash"] == digest
          and manifest["ra_key"] == catalogue[scenario]["ra_key"], "Finalized configuration invalid")
    with db.voting_fixture() as conn:
        check(conn.execute("SELECT config_bytes FROM voting.election_configs WHERE election_id=%s", (election,)).fetchone() == (canonical_manifest(manifest),), "Canonical manifest mismatch")
    policy_state(db, election, "FROZEN", False, None)
    http(origin, base, 409, method="PUT", data=dict(fields, revision=row["revision"]), token=token)
    http(origin, base + "/candidates", 409, method="POST", data={"revision": row["revision"], "candidate_name": "Forbidden late candidate"}, token=token)
    # Eligibility is the only per-election privileged fixture write.
    with db.ra_fixture() as conn:
        check(conn.execute("SELECT ra.set_voter_eligibility(%s,%s,true,%s)", (voter, election, principal)).fetchone() == (True,), "Eligibility setup failed")
    checkpoint("admin_finalize", scenario)
    return election, base


def admin_acl(db, voting_admin, publisher):
    real.acl(db)
    for connect, schema in ((voting_admin, "voting_admin"), (publisher, "ra_admin")):
        with connect() as conn:
            check(conn.execute("SELECT NOT(rolsuper OR rolinherit OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls) FROM pg_roles WHERE rolname=current_user").fetchone() == (True,), "Unsafe Admin runtime role")
            check(conn.execute("SELECT count(*) FROM pg_auth_members WHERE member=(SELECT oid FROM pg_roles WHERE rolname=current_user)").fetchone() == (0,), "Unexpected role membership")
            check(conn.execute("SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace CROSS JOIN LATERAL aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a WHERE n.nspname=%s AND a.grantee=0 AND a.privilege_type='EXECUTE'", (schema,)).fetchone() == (0,), "PUBLIC Admin execution allowed")
            baseline = schema.removesuffix("_admin")
            rows = conn.execute("SELECT n.nspname,p.proname FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname IN (%s,%s,%s,%s) AND has_function_privilege(current_user,p.oid,'EXECUTE')",
                (schema, baseline, baseline + "_demo", baseline + "_credential")).fetchall()
            expected = {"login_session", "session", "logout", "operation", "read_elections", "audit", "mutate"} if schema == "voting_admin" else {"prepare", "reconcile"}
            check(set(rows) == {(schema, name) for name in expected}, "Unexpected Admin EXECUTE surface")
            check(conn.execute("SELECT has_schema_privilege(current_user,%s,'CREATE') OR has_schema_privilege(current_user,%s,'CREATE') OR has_schema_privilege(current_user,'public','CREATE')", (schema, baseline)).fetchone() == (False,), "Admin schema CREATE allowed")
    for query in ("SELECT * FROM voting.accepted_ballots", "DELETE FROM voting.elections", "SET ROLE voting_owner"):
        real.deny(voting_admin, query)
    for query in ("SELECT * FROM ra.voters", "DELETE FROM ra.blind_issuances", "SET ROLE ra_owner"):
        real.deny(publisher, query)
    for factory, schema in ((db.ra_auth, "ra_admin"), (db.ra_issue, "ra_admin"), (db.voting_runtime, "voting_admin")):
        with factory() as conn:
            check(conn.execute("SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname=%s AND has_function_privilege(current_user,p.oid,'EXECUTE')", (schema,)).fetchone() == (0,), "Unrelated service can administer elections")


def run(node, signer, stage):
    root = require_ci()
    with ExitStack() as resources:
        stage[0] = "provision"
        ra_container, ra_bootstrap = resources.enter_context(real.vote_ci.ephemeral_postgres())
        voting_target, voting_bootstrap = resources.enter_context(real.vote_ci.ephemeral_postgres())
        ra_target = real.ra_ci.Target("ra_demo_test_ci_" + uuid4().hex, ra_container.marker, ra_container.port)
        ra, voting = discover("ra", ra_target), discover("voting", voting_target)
        passwords = {role: SecretStr(secrets.token_urlsafe(48)) for role in
            (*real.ra_ci.LOGINS, *real.vote_ci.LOGINS, "voting_admin_login", "ra_election_publisher_login")}
        real.ra_ci.bootstrap_database(ra_target, ra_bootstrap, {r: passwords[r] for r in real.ra_ci.LOGINS})
        real.vote_ci.bootstrap_database(voting_target, voting_bootstrap, {r: passwords[r] for r in real.vote_ci.LOGINS})
        stage[0] = "migrations"
        ra.verify(); voting.verify()
        real.ra_ci.migrate(ra_target, passwords["ra_migrator_login"])
        real.vote_ci.migrate(voting_target, passwords["voting_migrator_login"])
        stage[0] = "admin_migrations"
        admin_ci.provision_role(real.ra_ci, ra_target, ra_bootstrap, "ra_election_publisher_login", passwords["ra_election_publisher_login"])
        admin_ci.provision_role(real.vote_ci, voting_target, voting_bootstrap, "voting_admin_login", passwords["voting_admin_login"])
        admin_ci.migrate(real.ra_ci, ra_target, passwords["ra_migrator_login"], "ra", "bf932d0f8702")
        admin_ci.migrate(real.vote_ci, voting_target, passwords["voting_migrator_login"], "voting", "af821c9e7601")
        db = real.Connections(connection(ra, "ra_migrator_login", passwords["ra_migrator_login"], fixture=True),
            connection(ra, "ra_auth_login", passwords["ra_auth_login"]), connection(ra, "ra_issuance_login", passwords["ra_issuance_login"]),
            connection(voting, "voting_migrator_login", passwords["voting_migrator_login"], fixture=True),
            connection(voting, "voting_ballot_login", passwords["voting_ballot_login"]))
        voting_admin = connection(voting, "voting_admin_login", passwords["voting_admin_login"])
        publisher = connection(ra, "ra_election_publisher_login", passwords["ra_election_publisher_login"])
        stage[0] = "identities"
        principal, voter = identities(db)
        directory = Path(resources.enter_context(tempfile.TemporaryDirectory(prefix="evote-admin-voter-", dir=root)))
        pin, authority_path, authority_unlock, catalogue, signing = keys(directory)
        admin_password, salt = secrets.token_urlsafe(48), secrets.token_bytes(16)
        origin = resources.enter_context(service_process("admin", {"voting": voting.wire(), "ra": ra.wire(),
            "voting_password": passwords["voting_admin_login"].get_secret_value(),
            "publisher_password": passwords["ra_election_publisher_login"].get_secret_value(),
            "principal": str(principal), "username": "synthetic-admin-voter", "salt": b64encode(salt),
            "digest": b64encode(hashlib.scrypt(admin_password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)),
            "authority_key": str(authority_path), "unlock": authority_unlock.get_secret_value(), "pin": b64encode(pin), "keysets": catalogue}))
        stage[0] = "admin_login"
        http(origin, "/api/v1/admin/elections", 401)
        token = http(origin, "/api/v1/admin/auth/login", 200, method="POST",
            data={"username": "synthetic-admin-voter", "password": admin_password})["access_token"]
        identity = http(origin, "/api/v1/admin/auth/me", 200, token=token)
        check(identity == {"admin_id": str(principal), "role": "ELECTION_ADMIN"}, "Admin authorization mismatch")
        checkpoint("admin_login")
        for scenario in SCENARIOS:
            stage[0] = "admin_draft"
            election, base = create_election(origin, token, db, principal, voter, scenario, pin, catalogue, stage)
            with ExitStack() as services:
                stage[0] = "services"
                password, env = real.synthetic_environment(passwords["ra_auth_login"])
                path, unlock = signing[scenario]
                ra_origin = services.enter_context(service_process("ra", {"target": ra.wire(), "pin": b64encode(pin),
                    "auth_config": env, "auth_password": passwords["ra_auth_login"].get_secret_value(),
                    "issuance_password": passwords["ra_issuance_login"].get_secret_value(), "encrypted_key": str(path),
                    "unlock": unlock.get_secret_value(), "signer": str(signer), "key_id": catalogue[scenario]["ra_key"]["key_id"], "election_id": str(election)}))
                vote_origin = services.enter_context(service_process("voting", {"target": voting.wire(),
                    "pin": b64encode(pin), "password": passwords["voting_ballot_login"].get_secret_value()}))
                voter_token = http(ra_origin, "/api/v1/ra/auth/login", 200, method="POST",
                    data={"username": env["RA_DEMO_USERNAME"], "password": password})["access_token"]
                http(origin, "/api/v1/admin/elections", 401, token=voter_token)
                http(ra_origin, "/api/v1/ra/auth/me", 401, token=token)
                stage[0] = "open_interrupted"
                with publisher_denied(db):
                    http(origin, base + "/open", 503, method="POST", data={}, token=token)
                    policy_state(db, election, "OPEN", False, None)
                    http(ra_origin, "/api/v1/ra/elections", 503, token=voter_token)
                checkpoint("open_interrupted", scenario)
                stage[0] = "open_reconciled"
                http(origin, base + "/open", 200, method="POST", data={}, token=token)
                policy_state(db, election, "OPEN", True, True)
                status = http(origin, base, 200, token=token)
                check(status["status"] == "OPEN" and status["ra_ready"], "Admin opening status mismatch")
                listed = http(origin, "/api/v1/admin/elections", 200, token=token)["elections"]
                check(str(election) in {row["election_id"] for row in listed}, "Managed catalogue missing election")
                checkpoint("open_reconciled", scenario)
                frontend = services.enter_context(real.frontend(node, ra_origin, vote_origin, pin))
                screenshots = directory / (scenario + "-preview"); screenshots.mkdir(mode=0o700)
                def close(_event):
                    stage[0] = "close_interrupted"
                    with publisher_denied(db):
                        http(origin, base + "/close", 503, method="POST", data={}, token=token)
                        policy_state(db, election, "CLOSED", False, True)
                    checkpoint("close_interrupted", scenario)
                def progress(event):
                    if event in {"closed_recovery", "rejected_closed"}:
                        stage[0] = "close_reconciled"
                        # Browser proved recovery/closed rejection WHILE reconciliation was incomplete.
                        http(origin, base + "/close", 200, method="POST", data={}, token=token)
                        policy_state(db, election, "CLOSED", True, False)
                        http(origin, base + "/open", 409, method="POST", data={}, token=token)
                        checkpoint("close_reconciled", scenario)
                stage[0] = "browser"
                real.browser(node, {"origin": frontend, "scenario": scenario, "username": env["RA_DEMO_USERNAME"],
                    "password": password, "passphrase": secrets.token_urlsafe(48), "election_id": str(election),
                    "screenshots": str(screenshots)}, db, voter, election, stage, close=close, checkpoint=progress)
                stage[0] = "admin_audit"
                status = http(origin, base, 200, token=token)
                check(status["status"] == "CLOSED" and status["ra_ready"], "Admin closure status mismatch")
                audit = http(origin, base + "/audit", 200, token=token)["events"]
                expected = {"ELECTION_CREATED", "CANDIDATE_CREATED", "CONFIG_FROZEN", "ELECTION_OPENED", "ELECTION_CLOSED"}
                check(expected <= {event["event_type"] for event in audit}
                      and all(event["actor_principal_id"] == str(principal) for event in audit)
                      and sum(event["event_type"] == "ELECTION_OPENED" for event in audit) == 1
                      and sum(event["event_type"] == "ELECTION_CLOSED" for event in audit) == 1, "Admin audit mismatch")
                checkpoint("admin_audit", scenario)
                http(ra_origin, "/api/v1/ra/auth/logout", 204, method="POST", token=voter_token)
        stage[0] = "acl"
        admin_acl(db, voting_admin, publisher)
        checkpoint("acl")
        stage[0] = "database_assertions"
        with db.voting_fixture() as conn:
            check(conn.execute("SELECT count(*) FROM voting.elections WHERE status='CLOSED'").fetchone() == (3,), "Expected three closed elections")
            check(conn.execute("SELECT count(*) FROM voting.accepted_ballots").fetchone() == (2,), "Expected two committed ballots")
        with db.ra_fixture() as conn:
            check(conn.execute("SELECT count(*) FROM ra.blind_issuances").fetchone() == (3,), "Expected three native issuances")
            check(conn.execute("SELECT count(*) FROM ra.credential_reservations").fetchone() == (3,), "Expected three durable authorizations")
        checkpoint("database_assertions")
        http(origin, "/api/v1/admin/auth/logout", 204, method="POST", data={}, token=token)
        http(origin, "/api/v1/admin/elections", 401, token=token)
        stage[0] = "cleanup"
    # Retained immutable fixtures are destroyed with their owned databases, never individually deleted.
    remaining = real.vote_ci.docker("ps", "--all", "--no-trunc", "--format", "{{.ID}}").splitlines()
    check(ra.container_id not in remaining and voting.container_id not in remaining and not directory.exists(), "Owned resources remain")
    checkpoint("cleanup")
    print("PASS: admin_voter_e2e scenarios=3 real_services=true owned_containers=removed", flush=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--allow-ephemeral-ci-databases", action="store_true", required=True)
    parser.add_argument("--node", type=Path)
    parser.add_argument("--signer-binary", type=Path)
    parser.add_argument("--serve-role", choices=tuple(ROLE_FIELDS), help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    stage = ["preflight"]
    try:
        require_ci()  # Before files, processes, Docker or database access.
        logging.disable(logging.CRITICAL)
        def terminate(_signal, _frame): raise KeyboardInterrupt()
        signal.signal(signal.SIGTERM, terminate)
        if args.serve_role: serve(args.serve_role)
        else:
            real.vote_ci.verify_dependencies()
            check(args.node is not None and args.node.is_file() and args.signer_binary is not None
                  and args.signer_binary.is_file() and not args.signer_binary.is_symlink()
                  and args.signer_binary.resolve().is_relative_to(require_ci()), "Reviewed native executables required")
            run(args.node, args.signer_binary, stage)
    except BaseException as error:
        raise SystemExit(failure(stage[0], error)) from None


if __name__ == "__main__":
    main()
