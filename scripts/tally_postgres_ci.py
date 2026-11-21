"""Hosted-only disposable PostgreSQL 18 Tally gate. No target/credential arguments."""
import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
import hashlib
import logging
import re
from pathlib import Path
import secrets
import signal
import sys
import tempfile
from uuid import UUID, uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine
from sqlalchemy.pool import NullPool
from pydantic import SecretStr
import httpx
import psycopg
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from backend.tally.http import create_tally_app
from backend.tally.launcher import EncryptedTallyKey
from backend.tally.runtime import TallyAuthentication, TallyStore, TallyService, token_digest
from backend.tally.verification import EvidenceVault, TallyError
from backend.voting.ballot_service import BallotService, AlreadySpent
from backend.voting.postgres_ballot_store import PostgreSQLBallotStore
from scripts import admin_voter_e2e as guard, admin_postgres_ci as admin_ci
from tests.tally_helpers import material, ballot

HEAD = "e6a90c72b541"
STAGES = {"preflight", "provision", "baseline_migrations", "admin_migration", "tally_migration", "key_and_auth", "closed_enforcement", "accuracy",
          "rollback", "wrong_key", "configuration", "fencing", "acl", "cleanup"}
check = guard.check


def runtime(owned, password):
    def connect():
        owned.verify()
        return psycopg.connect(host="127.0.0.1", port=owned.target.port, dbname=owned.target.database,
            user="voting_tally_login", password=password.get_secret_value(), connect_timeout=5,
            options="-c statement_timeout=30000 -c lock_timeout=3000", sslmode="disable")
    return guard.real.guarded(connect, owned.target, "voting_owner", "voting_tally_login")


def migrate(target, password):
    config = Config()
    config.set_main_option("script_location", str(ROOT / "scripts/ci_voting_migrations"))
    config.set_main_option("version_locations", " ".join(str(ROOT / f"migrations/{folder}/versions") for folder in ("voting", "admin_voting", "tally")))
    config.set_main_option("path_separator", "space")
    graph = ScriptDirectory.from_config(config)
    check(graph.get_heads() == [HEAD] and len(list(graph.walk_revisions())) == 5, "Unexpected Tally migration graph")
    engine = create_engine("postgresql+psycopg://", creator=lambda: guard.real.vote_ci.connect(target, "voting_migrator_login", password), poolclass=NullPool, echo=False, hide_parameters=True)
    try:
        with engine.begin() as conn:
            config.attributes.update(connection=conn, disposable_database=target.database, disposable_marker=target.marker)
            command.upgrade(config, HEAD)
    finally: engine.dispose()


def seed(fixture, value, *, closed=False, bad_signature=False):
    e = value.manifest["election_id"]
    with fixture() as conn:
        conn.execute("INSERT INTO voting.elections(election_id,title,status,opens_at,closes_at,election_config_digest) VALUES(%s,'Synthetic Tally CI',%s,%s,%s,%s)",
            (e, "CLOSED" if closed else "OPEN", value.policy.opens_at, value.policy.closes_at, value.policy.config_digest))
        conn.execute("INSERT INTO voting.election_configs(election_id,config_bytes,config_digest,config_signature,config_signing_key_id,config_signing_key_fingerprint,evidence_reference) VALUES(%s,%s,%s,%s,'test-authority',%s,'disposable-test-only')",
            (e, value.policy.manifest_bytes, value.policy.config_digest, bytes(64) if bad_signature else value.policy.signature, value.policy.authority_fingerprint))
        for c in value.manifest["candidates"]:
            conn.execute("INSERT INTO voting.candidates(election_id,candidate_id,candidate_name) VALUES(%s,%s,%s)", (e, c["candidate_id"], c["candidate_name"]))
        conn.execute("INSERT INTO voting_admin.controls(election_id,phase,ra_ready) VALUES(%s,%s,true)", (e, "CLOSED" if closed else "OPEN"))


def close(fixture, election):
    with fixture() as conn:
        conn.execute("UPDATE voting.elections SET status='CLOSED' WHERE election_id=%s AND status='OPEN'", (election,))
        conn.execute("UPDATE voting_admin.controls SET phase='CLOSED' WHERE election_id=%s", (election,))


def check_acl(connect, other, fixture):
    for query in ("SELECT * FROM voting.accepted_ballots", "DELETE FROM voting.tally_reports", "SET ROLE voting_owner",
                  "SELECT voting_tally._b64(decode('00','hex'))"):
        guard.real.deny(connect, query)
    with connect() as conn:
        expected = {"login_session", "session", "logout", "list_elections", "view_report", "claim", "work", "seal", "complete", "fail"}
        rows = conn.execute("SELECT n.nspname,p.proname FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname IN ('voting','voting_admin','voting_tally') AND has_function_privilege(current_user,p.oid,'EXECUTE')").fetchall()
        check(set(rows) == {("voting_tally", name) for name in expected}, "Unexpected runtime EXECUTE surface")
    with other() as conn:
        check(conn.execute("SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='voting_tally' AND has_function_privilege(current_user,p.oid,'EXECUTE')").fetchone() == (0,), "Voting has Tally execution")
    with fixture() as conn:
        rows = conn.execute("SELECT p.prosecdef,p.proconfig,p.proowner='voting_owner'::regrole FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='voting_tally'").fetchall()
        check(all(definer and owner and any(c.replace(' ','').startswith('search_path=pg_catalog,') and c.endswith('pg_temp') for c in config) for definer,config,owner in rows), "Unsafe function ownership or search path")
        check(conn.execute("SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace CROSS JOIN LATERAL aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a WHERE n.nspname='voting_tally' AND a.grantee=0").fetchone() == (0,), "PUBLIC Tally execution")


def harness(fixture, connect, voting, directory, stage):
    operator, salt, password = uuid4(), secrets.token_bytes(16), secrets.token_urlsafe(48)
    with fixture() as conn:
        conn.execute("INSERT INTO voting_tally.principals(operator_id,role,is_active) VALUES(%s,'TALLY_OPERATOR',true)", (operator,))
    store = TallyStore(connect)
    auth = TallyAuthentication(store, operator, "synthetic-tally", salt, hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32))
    snapshot_private = ed25519.Ed25519PrivateKey.generate()
    snapshot_pin = snapshot_private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    vault = EvidenceVault(directory, snapshot_private, snapshot_pin, "ci-snapshot")
    value = material()
    key_path = directory / "encrypted-tally.pem"
    unlock = guard.write_key(key_path, value.tally)
    loader = EncryptedTallyKey(key_path, unlock, value.manifest["tally_key"]["key_id"])
    service = TallyService(auth, store, value.pin, vault, loader)
    with guard.real.http_service(create_tally_app(service)) as origin, httpx.Client(base_url=origin, trust_env=False, follow_redirects=False, timeout=30) as http:
        def request(method, path, status, *, body=None, token=None):
            result = http.request(method, "/api/v1/tally/" + path, json=body, headers={} if token is None else {"Authorization": "Bearer " + token})
            check(result.status_code == status and result.headers.get("Cache-Control") == "no-store", "Unexpected Tally HTTP response")
            return result.json() if result.status_code != 204 else None
        stage[0] = "key_and_auth"
        request("GET", "elections", 401)
        token = request("POST", "auth/login", 200, body={"username": "synthetic-tally", "password": password})["access_token"]
        check(request("GET", "auth/me", 200, token=token)["role"] == "TALLY_OPERATOR", "Operator role mismatch")
        request("GET", "auth/me", 401, token="adm1." + secrets.token_urlsafe(32))
        request("GET", "auth/me", 401, token=secrets.token_urlsafe(32))
        stage[0] = "closed_enforcement"
        seed(fixture, value)
        e = UUID(value.manifest["election_id"]); path = "elections/" + str(e)
        request("POST", path + "/run", 409, body={}, token=token)
        voting_service = BallotService(PostgreSQLBallotStore(voting), value.pin)
        accepted = [ballot(value), ballot(value), ballot(value, candidate=value.manifest["candidates"][1]["candidate_id"])]
        accepted += [ballot(value, invalid=reason) for reason in ("aead", "wrap", "candidate")]
        for payload in accepted: voting_service.submit(payload)
        try: voting_service.submit(accepted[0])
        except AlreadySpent: pass
        else: raise AssertionError("Duplicate accepted")
        close(fixture, e)
        # Durable claim blocks other workers; terminal failure permits an explicit retry.
        reserved = store.call("claim", token_digest(token), e)
        request("POST", path + "/run", 409, body={}, token=token)
        store.call("fail", token_digest(token), e, UUID(reserved["job_id"]), reserved["fence"], "UNAVAILABLE")
        stage[0] = "rollback"
        with fixture() as conn:
            conn.execute("CREATE FUNCTION voting_tally.ci_rollback() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$ BEGIN RAISE EXCEPTION 'Synthetic report failure'; END $$")
            conn.execute("REVOKE ALL ON FUNCTION voting_tally.ci_rollback() FROM PUBLIC")
            conn.execute("CREATE TRIGGER ci_rollback BEFORE INSERT ON voting.tally_reports FOR EACH ROW EXECUTE FUNCTION voting_tally.ci_rollback()")
        try: request("POST", path + "/run", 503, body={}, token=token)
        finally:
            with fixture() as conn:
                conn.execute("DROP TRIGGER ci_rollback ON voting.tally_reports")
                conn.execute("DROP FUNCTION voting_tally.ci_rollback()")
        with fixture() as conn:
            check(conn.execute("SELECT status FROM voting.elections WHERE election_id=%s", (e,)).fetchone() == ("CLOSED",), "Rollback changed lifecycle")
            check(conn.execute("SELECT count(*) FROM voting.tally_reports WHERE election_id=%s", (e,)).fetchone() == (0,), "Rollback persisted partial report")
            snapshot = conn.execute("SELECT snapshot_id FROM voting.final_snapshots WHERE election_id=%s AND status='FINALIZED'", (e,)).fetchone()[0]
        stage[0] = "accuracy"
        def tally(_):
            with httpx.Client(base_url=origin, trust_env=False, timeout=30) as client:
                response = client.post("/api/v1/tally/" + path + "/run", json={}, headers={"Authorization": "Bearer " + token})
                check(response.status_code in (200, 409), "Concurrent Tally failed")
                return response.status_code
        with ThreadPoolExecutor(max_workers=4) as pool: outcomes = list(pool.map(tally, range(4)))
        check(200 in outcomes, "No tally completed")
        result = request("GET", path + "/report", 200, token=token)
        report = result["report"]
        check(report["accepted_total"] == 6 and report["valid_total"] == report["invalid_total"] == report["counted_total"] == 3, "Tally totals incorrect")
        check([r["vote_count"] for r in report["candidate_counts"]] == [2, 1] and report["invalid_reasons"] == {"AEAD":1,"KEY_WRAP":1,"PLAINTEXT":1}, "Tally classifications incorrect")
        check(request("POST", path + "/run", 200, body={}, token=token) == result, "Completed retry changed report")
        with fixture() as conn:
            check(conn.execute("SELECT snapshot_id FROM voting.tally_reports WHERE election_id=%s", (e,)).fetchone() == (snapshot,), "Recovery replaced snapshot")
            check(conn.execute("SELECT count(*) FROM voting.tally_jobs WHERE election_id=%s AND status='SUCCEEDED'", (e,)).fetchone() == (1,), "Multiple successful tallies")
            check(conn.execute("SELECT count(*) FROM voting.voting_audit_events WHERE election_id=%s AND event_type IN ('SNAPSHOT_FINALIZED','ELECTION_TALLIED')", (e,)).fetchone() == (2,), "Missing durable success audit")
        # Correct record receipts are still recoverable after TALLIED.
        check(voting_service.recover(accepted[0]) == voting_service.verify(accepted[0]).receipt_hash.hex(), "Receipt contract changed")
        stage[0] = "wrong_key"
        other = material(); seed(fixture, other, closed=True)
        wrong_service = TallyService(auth, store, other.pin, vault, EncryptedTallyKey(key_path, unlock, other.manifest["tally_key"]["key_id"]))
        try: wrong_service.run(token, UUID(other.manifest["election_id"]))
        except TallyError as error: check(error.code == "KEY_UNAVAILABLE", "Wrong key misclassified")
        else: raise AssertionError("Wrong Tally key accepted")
        stage[0] = "configuration"
        unsigned = material(); seed(fixture, unsigned, closed=True, bad_signature=True)
        unsigned_service = TallyService(auth, store, unsigned.pin, vault, loader)
        try: unsigned_service.run(token, UUID(unsigned.manifest["election_id"]))
        except TallyError as error: check(error.code == "INTEGRITY", "Unsigned config misclassified")
        else: raise AssertionError("Unsigned configuration accepted")
        stage[0] = "fencing"
        pending = material(); seed(fixture, pending, closed=True)
        pe = UUID(pending.manifest["election_id"])
        old = store.call("claim", token_digest(token), pe)
        with fixture() as conn:
            conn.execute("UPDATE voting.tally_jobs SET started_at=statement_timestamp()-interval '6 minutes',last_heartbeat_at=statement_timestamp()-interval '6 minutes',lease_until=statement_timestamp()-interval '1 minute' WHERE tally_job_id=%s", (old["job_id"],))
        new = store.call("claim", token_digest(token), pe)
        check(new["fence"] > old["fence"], "Lease fencing did not advance")
        try: store.call("work", token_digest(token), pe, UUID(old["job_id"]), old["fence"])
        except TallyError as error: check(error.status == 409, "Stale worker misclassified")
        else: raise AssertionError("Stale worker accepted")
        stage[0] = "acl"
        check_acl(connect, voting, fixture)
        request("POST", "auth/logout", 204, body={}, token=token)
        request("GET", "auth/me", 401, token=token)
        expired = request("POST", "auth/login", 200, body={"username": "synthetic-tally", "password": password})["access_token"]
        with fixture() as conn:
            conn.execute("UPDATE voting_tally.sessions SET created_at=statement_timestamp()-interval '16 minutes',expires_at=statement_timestamp()-interval '1 minute' WHERE digest=%s", (token_digest(expired),))
        request("GET", "auth/me", 401, token=expired)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--allow-ephemeral-ci-database", action="store_true", required=True)
    parser.parse_args(argv)
    stage = ["preflight"]
    try:
        root = guard.require_ci()
        logging.disable(logging.CRITICAL)
        def terminate(_signal, _frame): raise KeyboardInterrupt()
        signal.signal(signal.SIGTERM, terminate)
        guard.real.vote_ci.verify_dependencies()
        with ExitStack() as resources:
            stage[0] = "provision"
            target, bootstrap = resources.enter_context(guard.real.vote_ci.ephemeral_postgres())
            owned = guard.discover("voting", target)
            passwords = {role: SecretStr(secrets.token_urlsafe(48)) for role in (*guard.real.vote_ci.LOGINS, "voting_admin_login", "voting_tally_login")}
            guard.real.vote_ci.bootstrap_database(target, bootstrap, {r: passwords[r] for r in guard.real.vote_ci.LOGINS})
            stage[0] = "baseline_migrations"
            guard.real.vote_ci.migrate(target, passwords["voting_migrator_login"])
            for role in ("voting_admin_login", "voting_tally_login"):
                admin_ci.provision_role(guard.real.vote_ci, target, bootstrap, role, passwords[role])
            stage[0] = "admin_migration"
            admin_ci.migrate(guard.real.vote_ci, target, passwords["voting_migrator_login"], "voting", "af821c9e7601")
            stage[0] = "tally_migration"
            migrate(target, passwords["voting_migrator_login"])
            fixture = guard.connection(owned, "voting_migrator_login", passwords["voting_migrator_login"], fixture=True)
            voting = guard.connection(owned, "voting_ballot_login", passwords["voting_ballot_login"])
            directory = Path(resources.enter_context(tempfile.TemporaryDirectory(prefix="evote-tally-ci-", dir=root)))
            harness(fixture, runtime(owned, passwords["voting_tally_login"]), voting, directory, stage)
            stage[0] = "cleanup"
        check(not directory.exists() and owned.container_id not in guard.real.vote_ci.docker("ps", "--all", "--no-trunc", "--format", "{{.ID}}").splitlines(), "Owned cleanup incomplete")
        print("PASS: tally_postgres_ci real_crypto=true owned_container=removed")
    except BaseException as error:
        label = stage[0] if stage[0] in STAGES else "preflight"
        root_error = getattr(error, "orig", None) or error
        state = getattr(root_error, "sqlstate", None)
        if not isinstance(state, str) or re.fullmatch(r"[0-9A-Z]{5}", state) is None: state = "unavailable"
        category = "assertion" if isinstance(error, AssertionError) else "database" if isinstance(root_error, psycopg.Error) else "unavailable"
        raise SystemExit(f"FAIL: tally_postgres_ci stage={label} category={category} sqlstate={state}") from None


if __name__ == "__main__": main()
