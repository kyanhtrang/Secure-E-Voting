"""Separate hosted-only Admin PostgreSQL gate. No target/credential arguments."""
import argparse
import hashlib
import logging
import secrets
import sys
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import psycopg
from psycopg import sql
from pydantic import SecretStr
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine
from sqlalchemy.pool import NullPool
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519

from backend.admin.auth import AdminAuthentication, token_digest
from backend.admin.service import AdminService, ManifestAuthority
from backend.admin.store import AdminError, VotingAdminStore, RAPublisherStore
from backend.crypto.credential_protocol import b64encode, verify_manifest
from scripts import ra_gate2_ci as ra_ci, voting_postgres_ci as vote_ci, real_voting_e2e as real


def provision_role(module, target, bootstrap, role, password):
    module.require_ci(); target.validate()
    with module.connect(target, "postgres", bootstrap) as conn:
        # Same independent marker/ownership check used for ALL runtime connects.
        row = conn.execute("SELECT pg_get_userbyid(datdba),shobj_description(oid,'pg_database') FROM pg_database WHERE datname=current_database()").fetchone()
        assert row == ("ra_owner" if module is ra_ci else "voting_owner", "secure-evoting-disposable:" + target.marker)
        conn.execute(sql.SQL("CREATE ROLE {} LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 20 PASSWORD {}").format(sql.Identifier(role), sql.Literal(password.get_secret_value())))
        conn.execute(sql.SQL("GRANT CONNECT ON DATABASE {} TO {}").format(sql.Identifier(target.database), sql.Identifier(role)))


def migrate(module, target, password, name, head):
    config = Config()
    config.set_main_option("script_location", str(ROOT / f"scripts/ci_{name}_migrations"))
    config.set_main_option("version_locations", " ".join(str(ROOT / f"migrations/{directory}/versions") for directory in (name, "admin_" + name)))
    config.set_main_option("path_separator", "space")
    assert ScriptDirectory.from_config(config).get_heads() == [head]
    engine = create_engine("postgresql+psycopg://", creator=lambda: module.connect(target, name + "_migrator_login", password), poolclass=NullPool, echo=False, hide_parameters=True)
    def guard(connection):
        module.require_ci()
        assert connection.exec_driver_sql("SELECT session_user,current_user").one() == ("ra_migrator_login", "ra_migrator_login")
        ra_ci.verify_disposable_database(connection.connection.driver_connection, target.database, target.marker)
    try:
        with engine.begin() as connection:
            config.attributes.update(connection=connection, disposable_database=target.database,
                disposable_marker=target.marker, disposable_connection_guard=guard)
            command.upgrade(config, head)
    finally:
        engine.dispose()


def runtime(target, role, password, owner):
    return real.guarded(lambda: psycopg.connect(host="127.0.0.1", port=target.port, dbname=target.database,
        user=role, password=password.get_secret_value(), connect_timeout=5, sslmode="disable",
        options="-c statement_timeout=10000 -c lock_timeout=3000"), target, owner, role)


def denied(action, status=409):
    try: action()
    except AdminError as error: assert error.status == status
    else: raise AssertionError()


def harness(db, voting_runtime, ra_runtime):
    voterless_actor = uuid4()
    with db.voting_fixture() as conn:
        conn.execute("INSERT INTO voting_admin.principals(admin_id,is_active,role) VALUES(%s,true,'ELECTION_ADMIN')", (voterless_actor,))
    store = VotingAdminStore(voting_runtime)
    password = secrets.token_urlsafe(32); salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    auth = AdminAuthentication(store, voterless_actor, "synthetic-ci-admin", salt, digest)
    token = auth.limited.login("synthetic-ci-admin", password)
    def key(key_id):
        private = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        raw = private.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        return {"key_id": key_id, "spki": b64encode(raw), "fingerprint": hashlib.sha256(raw).hexdigest()}
    authority = ed25519.Ed25519PrivateKey.generate()
    pin = authority.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    publisher = RAPublisherStore(ra_runtime)
    service = AdminService(auth, store, publisher, ManifestAuthority(authority, pin), {"ci": {
        "ra_key": key("ci-ra-" + uuid4().hex), "tally_key": key("ci-tally-" + uuid4().hex), "private_key_reference": "ci-opaque-reference"}})
    now = datetime.now(timezone.utc)
    fields = {"title": "Synthetic Admin CI", "opens_at": (now - timedelta(minutes=2)).strftime("%Y-%m-%dT%H:%M:%SZ"), "closes_at": (now + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")}
    election = service.create(token, fields); eid = __import__('uuid').UUID(election["election_id"])
    def edit(_):
        try: service.change(token, eid, "edit", dict(fields, revision=1)); return 200
        except AdminError as error: return error.status
    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(edit, range(2))) == [200, 409]
    election = service.detail(token, eid)
    for name in ("Synthetic A", "Synthetic B"):
        election = service.change(token, eid, "candidate", {"revision": election["revision"], "candidate_id": str(uuid4()), "candidate_name": name})
    first_candidate = election["candidates"][0]["candidate_id"]
    election = service.change(token, eid, "candidate", {"revision": election["revision"], "candidate_id": first_candidate, "candidate_name": "Synthetic updated"})
    extra_candidate = str(uuid4())
    election = service.change(token, eid, "candidate", {"revision": election["revision"], "candidate_id": extra_candidate, "candidate_name": "Synthetic temporary"})
    election = service.change(token, eid, "remove", {"revision": election["revision"], "candidate_id": extra_candidate})
    assert len(election["candidates"]) == 2
    # Force failure AFTER the mutation and audit INSERT to prove RPC rollback.
    with db.voting_fixture() as conn:
        conn.execute("CREATE FUNCTION voting_admin.ci_fail_audit() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$ BEGIN RAISE EXCEPTION 'Synthetic transaction failure'; END $$")
        conn.execute("REVOKE ALL ON FUNCTION voting_admin.ci_fail_audit() FROM PUBLIC")
        conn.execute("CREATE TRIGGER ci_fail_admin_audit AFTER INSERT ON voting.voting_audit_events FOR EACH ROW EXECUTE FUNCTION voting_admin.ci_fail_audit()")
    try:
        denied(lambda: service.change(token, eid, "edit", dict(fields, title="Synthetic rollback", revision=election["revision"])), 503)
        after = service.detail(token, eid)
        assert after["title"] == election["title"] and after["revision"] == election["revision"]
    finally:
        with db.voting_fixture() as conn:
            conn.execute("DROP TRIGGER ci_fail_admin_audit ON voting.voting_audit_events")
            conn.execute("DROP FUNCTION voting_admin.ci_fail_audit()")
    # A failed SQL transaction must leave neither election nor audit/control row.
    bad_id = uuid4()
    denied(lambda: service.change(token, bad_id, "create", dict(fields, title=None)), 503)
    with db.voting_fixture() as conn:
        assert conn.execute("SELECT count(*) FROM voting.elections WHERE election_id=%s", (bad_id,)).fetchone() == (0,)
    election = service.finalize(token, eid, election["revision"], "ci")
    _, config_hash = verify_manifest(election["bundle"], pin, str(eid))
    denied(lambda: service.change(token, eid, "edit", dict(fields, revision=election["revision"])))
    with db.ra_fixture() as conn:
        assert conn.execute("SELECT count(*) FROM ra.credential_policies WHERE election_id=%s", (eid,)).fetchone() == (0,)
    # Fail AFTER Voting OPEN commit; an exact retry reconciles the same hash.
    class Offline:
        prepare = publisher.prepare
        def reconcile(self, *_): raise AdminError(503)
    service.publisher = Offline()
    denied(lambda: service.transition(token, eid, False), 503)
    assert service.detail(token, eid)["status"] == "OPEN" and not service.detail(token, eid)["ra_ready"]
    service.publisher = publisher
    assert service.transition(token, eid, False)["ra_ready"]
    with db.ra_fixture() as conn:
        assert conn.execute("SELECT encode(config_hash,'hex'),issuance_enabled FROM ra.credential_policies WHERE election_id=%s", (eid,)).fetchone() == (config_hash, True)
    # Fail after Voting CLOSED commit; it remains closed until RA reconciliation.
    service.publisher = Offline()
    denied(lambda: service.transition(token, eid, True), 503)
    assert service.detail(token, eid)["status"] == "CLOSED"
    service.publisher = publisher
    assert service.transition(token, eid, True)["ra_ready"]
    denied(lambda: service.transition(token, eid, False))
    with db.ra_fixture() as conn:
        assert conn.execute("SELECT issuance_enabled FROM ra.credential_policies WHERE election_id=%s", (eid,)).fetchone() == (False,)
        assert conn.execute("SELECT closed,closed_at IS NOT NULL FROM ra_admin.publications WHERE election_id=%s", (eid,)).fetchone() == (True, True)
        assert {row[0] for row in conn.execute("SELECT action FROM ra_admin.events WHERE election_id=%s AND actor_id=%s", (eid, voterless_actor))} == {"PREPARE", "ENABLE", "CLOSE"}
    events = service.audit(token, eid)
    assert {"ELECTION_CREATED", "CONFIG_FROZEN", "ELECTION_OPENED", "ELECTION_CLOSED"} <= {event["event_type"] for event in events}
    assert all(event["actor_principal_id"] == str(voterless_actor) for event in events)
    for connect, schema, forbidden in ((voting_runtime, "voting_admin", "voting.accepted_ballots"), (ra_runtime, "ra_admin", "ra.voters")):
        with connect() as conn:
            assert conn.execute("SELECT has_table_privilege(current_user,c.oid,'SELECT,INSERT,UPDATE,DELETE') FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=%s AND c.relname=%s", tuple(forbidden.split('.'))).fetchone() == (False,)
            assert conn.execute("SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace CROSS JOIN LATERAL aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a WHERE n.nspname=%s AND a.grantee=0 AND a.privilege_type='EXECUTE'", (schema,)).fetchone() == (0,)
        try:
            with connect() as conn: conn.execute(sql.SQL("SELECT * FROM {} LIMIT 0").format(sql.Identifier(*forbidden.split('.'))))
        except psycopg.errors.InsufficientPrivilege as error: assert error.sqlstate == "42501"
        else: raise AssertionError()
    with db.ra_auth() as conn:
        assert conn.execute("SELECT has_function_privilege(current_user,p.oid,'EXECUTE') FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='ra_admin' AND p.proname='reconcile'").fetchone() == (False,)
    auth.logout(token); denied(lambda: service.list(token), 401)
    expired = auth.limited.login("synthetic-ci-admin", password)
    with db.voting_fixture() as conn:
        conn.execute("UPDATE voting_admin.sessions SET created_at=statement_timestamp()-interval '16 minutes',expires_at=statement_timestamp()-interval '1 minute' WHERE digest=%s", (token_digest(expired),))
    denied(lambda: service.list(expired), 401)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--allow-ephemeral-ci-databases", action="store_true", required=True)
    parser.parse_args(argv)
    logging.disable(logging.CRITICAL)
    stage = "provision"
    try:
        ra_ci.require_ci(); vote_ci.require_ci()
        with ExitStack() as resources:
            ra_container, ra_bootstrap = resources.enter_context(vote_ci.ephemeral_postgres())
            voting, voting_bootstrap = resources.enter_context(vote_ci.ephemeral_postgres())
            ra = ra_ci.Target("ra_demo_test_ci_" + uuid4().hex, ra_container.marker, ra_container.port)
            passwords = {role: SecretStr(secrets.token_urlsafe(48)) for role in (*ra_ci.LOGINS, *vote_ci.LOGINS, "voting_admin_login", "ra_election_publisher_login")}
            ra_ci.bootstrap_database(ra, ra_bootstrap, {r: passwords[r] for r in ra_ci.LOGINS})
            vote_ci.bootstrap_database(voting, voting_bootstrap, {r: passwords[r] for r in vote_ci.LOGINS})
            db = real.connections(ra, voting, passwords)
            stage = "baseline_migrations"
            ra_ci.migrate(ra, passwords["ra_migrator_login"]); vote_ci.migrate(voting, passwords["voting_migrator_login"])
            stage = "admin_migrations"
            provision_role(ra_ci, ra, ra_bootstrap, "ra_election_publisher_login", passwords["ra_election_publisher_login"])
            provision_role(vote_ci, voting, voting_bootstrap, "voting_admin_login", passwords["voting_admin_login"])
            migrate(ra_ci, ra, passwords["ra_migrator_login"], "ra", "bf932d0f8702")
            migrate(vote_ci, voting, passwords["voting_migrator_login"], "voting", "af821c9e7601")
            stage = "admin_contracts"
            harness(db, runtime(voting, "voting_admin_login", passwords["voting_admin_login"], "voting_owner"),
                runtime(ra, "ra_election_publisher_login", passwords["ra_election_publisher_login"], "ra_owner"))
            stage = "cleanup"
        print("PASS: admin disposable PostgreSQL contracts and owned-container cleanup")
    except BaseException as error:
        category = "assertion" if isinstance(error, AssertionError) else "database" if isinstance(error, psycopg.Error) else "unavailable"
        state = getattr(error, "sqlstate", None)
        if not isinstance(state, str) or len(state) != 5 or not state.isalnum(): state = "unavailable"
        print(f"FAIL: admin_ci stage={stage} category={category} sqlstate={state}")
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
