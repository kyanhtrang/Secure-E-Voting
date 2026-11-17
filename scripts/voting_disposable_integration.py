"""Manual-only real Voting tests. No provisioning or migrations occur here.

Requires an independently named AND marked disposable Voting database at the
reviewed migration head. Importing this module never connects or reads secrets.
"""

import argparse
import copy
import getpass
import re
import sys
import threading
import time
import warnings
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from uuid import UUID

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import psycopg
from fastapi.testclient import TestClient
from pydantic import SecretStr

from backend.voting.ballot_service import BallotService, VotingUnavailable
from backend.voting.local_launcher import create_voting_app
from backend.voting.postgres_ballot_store import PostgreSQLBallotStore
from tests.voting_helpers import material, payload_for
from scripts.voting_integration_diagnostics import IntegrationDiagnostics


def check(condition, label):
    if not condition:
        raise AssertionError(label)


def designation(database, marker):
    check(type(database) is str and re.fullmatch(r"voting_demo_test_[a-z0-9_]+", database) is not None,
          "A distinct voting_demo_test_ database is required")
    try:
        check(type(marker) is str and str(UUID(marker)) == marker, "Canonical marker required")
    except (ValueError, AttributeError, TypeError):
        raise AssertionError("Canonical marker required") from None


def verify_database(conn, database, marker):
    designation(database, marker)
    check(conn.execute("""SELECT current_database(),pg_catalog.shobj_description(oid,'pg_database')
        FROM pg_catalog.pg_database WHERE datname=current_database()""").fetchone() ==
          (database, "secure-evoting-disposable:"+marker), "Disposable marker mismatch; refusing all writes")


def factory(database, marker, port, password, *, fixture=False):
    designation(database, marker)
    check(type(port) is int and 1 <= port <= 65535, "Invalid loopback port")
    login = "voting_migrator_login" if fixture else "voting_ballot_login"
    role = "voting_owner" if fixture else login

    def connect():
        conn = psycopg.connect(host="127.0.0.1", port=port, dbname=database, user=login,
            password=password.get_secret_value(), connect_timeout=5,
            options="-c statement_timeout=20000 -c lock_timeout=10000")
        try:
            verify_database(conn, database, marker)  # Repeated on every connection, including cleanup.
            if fixture:
                conn.execute("SET LOCAL ROLE voting_owner")
            check(conn.execute("SELECT current_database(),session_user,current_user").fetchone() ==
                  (database, login, role), "Unexpected test connection identity")
            return conn
        except BaseException:
            conn.close()
            raise
    return connect


def password(label):
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        value = SecretStr(getpass.getpass(label))
    check(bool(value.get_secret_value()), "Empty test password refused")
    return value


def seed(conn, value):
    check(conn.execute("SELECT version_num FROM voting.alembic_version").fetchone() ==
          ("d8f27a4c610b",), "Reviewed Voting migration head required")
    election, policy = value.manifest["election_id"], value.policy
    check(conn.execute("SELECT 1 FROM voting.elections WHERE election_id=%s", (election,)).fetchone() is None,
          "Refusing to reuse an existing election")
    conn.execute("""INSERT INTO voting.elections(election_id,title,status,opens_at,closes_at,election_config_digest)
        VALUES(%s,'Disposable Voting fixture','OPEN',%s,%s,%s)""",
        (election, policy.opens_at, policy.closes_at, policy.config_digest))
    conn.execute("""INSERT INTO voting.election_configs(election_id,config_bytes,config_digest,config_signature,
        config_signing_key_id,config_signing_key_fingerprint,evidence_reference)
        VALUES(%s,%s,%s,%s,'test-authority',%s,'ephemeral-test-only')""",
        (election, policy.manifest_bytes, policy.config_digest, policy.signature, policy.authority_fingerprint))


def sql_params(ballot):
    return (ballot.election_id, ballot.config_digest, ballot.serial,
            ballot.envelope, ballot.prepared_msg, ballot.signature)


ACCEPT = "SELECT voting.accept_anonymous_ballot(%s::uuid,%s::bytea,%s::bytea,%s::bytea,%s::bytea,%s::bytea)"
URL = "/api/v1/vote/ballots"


def client(service):
    return TestClient(create_voting_app(service), base_url="http://127.0.0.1", client=("127.0.0.1", 50000))


def await_lock_wait(observer, blocker):
    deadline = time.monotonic()+8
    while time.monotonic() < deadline:
        # pg_stat_activity caches its backend snapshot within a transaction.
        # Refresh observation without committing/releasing the election lock.
        observer.execute("SELECT pg_catalog.pg_stat_clear_snapshot()")
        if observer.execute("""SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_stat_activity
            WHERE datname=current_database() AND %s=ANY(pg_catalog.pg_blocking_pids(pid)))""",
            (blocker,)).fetchone() == (True,):
            return
        time.sleep(0.02)
    raise AssertionError("Expected PostgreSQL election-lock contention did not occur")


def run(fixture, runtime, database, marker, *, diagnostics=None):
    diagnostics = diagnostics if diagnostics is not None else IntegrationDiagnostics()
    diagnostics.set_stage("fixture_seed")
    value = material()  # Generated TEST keys in memory only. No actual RA credential is consumed.
    election = value.manifest["election_id"]
    created = []
    try:
        with fixture() as conn:
            seed(conn, value)
        created.append(election)
        service = BallotService(PostgreSQLBallotStore(runtime), value.pin)
        payload = payload_for(value)
        barrier = threading.Barrier(20)

        def vote(_):
            with client(service) as http:
                barrier.wait(timeout=20)
                response = http.post(URL, json=payload)
                return response.status_code

        diagnostics.set_stage("concurrency_20")
        with ThreadPoolExecutor(max_workers=20) as pool:
            results = list(pool.map(vote, range(20)))
        check(results.count(201) == 1 and results.count(409) == 19, "20-way serial uniqueness failed")
        with fixture() as conn:
            check(conn.execute("SELECT count(*) FROM voting.accepted_ballots WHERE election_id=%s", (election,)).fetchone()
                  == (1,), "Unexpected ballot count")
        with client(service) as http:
            diagnostics.set_stage("duplicate_retry")
            check(http.post(URL, json=payload).status_code == 409, "Retry inserted a second ballot")
            diagnostics.set_stage("receipt_recovery")
            recovered = http.post(URL+"/receipt", json=payload)
            expected = service.verify(payload).receipt_hash.hex()
            check(recovered.status_code == 200 and recovered.json()["receipt_hash"] == expected,
                  "Lost-response recovery or SQL/Python receipt interoperability failed")
            diagnostics.set_stage("identity_and_signature_rejection")
            for field in ("voter_id", "username", "request_id", "ra_token"):
                check(http.post(URL, json={**payload, field: "SYNTHETIC_CANARY"}).status_code == 422,
                      "Identity metadata accepted")
            check(http.post(URL, json=payload, headers={"Authorization": "Bearer SYNTHETIC_CANARY"}).status_code == 400,
                  "RA bearer accepted")
            for change in ("signature", "envelope", "config", "election"):
                bad = copy.deepcopy(payload)
                if change == "signature":
                    from backend.crypto.credential_protocol import b64encode
                    bad["credential"]["signature"] = b64encode(b"x"*384)
                elif change == "envelope":
                    bad["envelope"]["key_id"] = "wrong-tally-key"
                elif change == "config":
                    bad["credential"]["message"]["config_hash"] = "0"*64
                else:
                    bad["credential"]["message"]["election_id"] = "00000000-0000-4000-8000-000000000000"
                check(http.post(URL, json=bad).status_code == 422, "Invalid cryptographic binding accepted")
        # The same plaintext choice with independently randomized encryption and serial is permitted.
        with client(service) as http:
            check(http.post(URL, json=payload_for(value)).status_code == 201, "Identical candidate choice rejected")

        diagnostics.set_stage("rollback")
        rollback_payload = payload_for(value)
        ballot = service.verify(rollback_payload)
        try:
            with runtime() as conn:
                conn.execute(ACCEPT, sql_params(ballot)).fetchone()
                raise RuntimeError("synthetic rollback")
        except RuntimeError:
            pass
        with client(service) as http:
            check(http.post(URL+"/receipt", json=rollback_payload).status_code == 404, "Rollback retained a receipt")
            check(http.post(URL, json=rollback_payload).status_code == 201, "Rolled-back serial consumed")

        diagnostics.set_stage("lost_response")
        # Execute COMMIT for real, then inject response loss at the application boundary.
        class LostResponseStore(PostgreSQLBallotStore):
            def accept(self, ballot):
                super().accept(ballot)
                raise VotingUnavailable()
        lost_payload = payload_for(value)
        with client(BallotService(LostResponseStore(runtime), value.pin)) as http:
            check(http.post(URL, json=lost_payload).status_code == 503, "Response-loss injection failed")
        with client(service) as http:
            check(http.post(URL+"/receipt", json=lost_payload).status_code == 200, "Committed response loss unrecoverable")
            check(http.post(URL, json=lost_payload).status_code == 409, "Response loss allowed another acceptance")

        diagnostics.set_stage("closing_first_race")
        # Closing wins the election lock. This is a controlled lock race, not a timing-only sleep.
        blocked = threading.Event()
        race_payload = payload_for(value)
        def blocked_vote():
            blocked.set()
            with client(service) as http:
                return http.post(URL, json=race_payload).status_code
        with ThreadPoolExecutor(max_workers=1) as pool:
            with fixture() as closing:
                closing.execute("SELECT 1 FROM voting.elections WHERE election_id=%s FOR UPDATE", (election,))
                blocker = closing.execute("SELECT pg_backend_pid()").fetchone()[0]
                future = pool.submit(blocked_vote)
                check(blocked.wait(10), "Closing race worker absent")
                await_lock_wait(closing, blocker)
                closing.execute("UPDATE voting.elections SET status='CLOSED' WHERE election_id=%s", (election,))
            check(future.result(timeout=20) == 409, "Closed election accepted a racing ballot")
        with client(service) as http:
            check(http.post(URL+"/receipt", json=payload).status_code == 200, "Closed election prevented recovery")

        diagnostics.set_stage("acceptance_first_race")
        # Acceptance wins the lock; closing must wait for its commit.
        with fixture() as conn:
            conn.execute("UPDATE voting.elections SET status='OPEN' WHERE election_id=%s", (election,))
        first = service.verify(payload_for(value))
        def close_after_accept():
            with fixture() as conn:
                conn.execute("UPDATE voting.elections SET status='CLOSED' WHERE election_id=%s", (election,))
        with ThreadPoolExecutor(max_workers=1) as pool:
            with runtime() as conn:
                check(bytes(conn.execute(ACCEPT, sql_params(first)).fetchone()[0]) == first.receipt_hash,
                      "Acceptance-first receipt mismatch")
                blocker = conn.execute("SELECT pg_backend_pid()").fetchone()[0]
                future = pool.submit(close_after_accept)
                with fixture() as observer:
                    await_lock_wait(observer, blocker)
            future.result(timeout=20)

        diagnostics.set_stage("election_time")
        # OPEN status alone is insufficient; DB time must enforce both boundaries.
        for opening, closing in ((-7200, -3600), (3600, 7200)):
            timed = material(opens_offset=opening, closes_offset=closing)
            with fixture() as conn:
                seed(conn, timed)
            created.append(timed.manifest["election_id"])
            timed_service = BallotService(PostgreSQLBallotStore(runtime), timed.pin)
            with client(timed_service) as http:
                check(http.post(URL, json=payload_for(timed)).status_code == 409, "Database voting window ignored")

        diagnostics.set_stage("acl_verification")
        # Effective privileges and ownership, including helpers and other workers.
        with fixture() as conn:
            rows = conn.execute("""SELECT p.proname,r.rolname,p.prosecdef,p.proconfig,
              has_function_privilege('voting_ballot_login',p.oid,'EXECUTE')
              FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
              JOIN pg_roles r ON r.oid=p.proowner WHERE n.nspname='voting'""").fetchall()
            expected = {"ballot_policy", "accept_anonymous_ballot", "recover_ballot_receipt"}
            check(len(rows) == 5, "Unexpected Voting functions")
            for name, owner, definer, config, executable in rows:
                check(owner == "voting_owner" and definer and
                      any(item.replace(" ", "") == "search_path=pg_catalog,voting,pg_temp" for item in config)
                      and executable == (name in expected),
                      "Unsafe Voting function boundary")
            check(conn.execute("""SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
                CROSS JOIN (VALUES ('voting_admin_service'),('voting_snapshot_worker'),('voting_tally_worker'),
                  ('voting_publication_service'),('voting_board_reader'),('voting_audit_reader')) AS worker(name)
                WHERE n.nspname='voting' AND has_function_privilege(worker.name,p.oid,'EXECUTE')""").fetchone() == (0,),
                  "Another worker can invoke anonymous ballot functions")
            check(conn.execute("""SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace,
                LATERAL aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a
                WHERE n.nspname='voting' AND a.grantee=0 AND a.privilege_type='EXECUTE'""").fetchone() == (0,),
                  "PUBLIC function execution remains")
            check(conn.execute("""SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
                WHERE n.nspname='voting' AND c.relkind IN ('r','p') AND
                (has_table_privilege('voting_ballot_login',c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
                 OR has_any_column_privilege('voting_ballot_login',c.oid,'SELECT,INSERT,UPDATE,REFERENCES'))""").fetchone() == (0,),
                  "Runtime has direct table access")
        for query in ("SELECT * FROM voting.accepted_ballots", "DELETE FROM voting.accepted_ballots",
                      "SELECT voting._ballot_receipt(NULL,NULL,NULL,NULL,NULL)"):
            try:
                with runtime() as conn:
                    conn.execute(query)
            except psycopg.errors.InsufficientPrivilege:
                pass
            else:
                raise AssertionError("Unauthorized SQL succeeded")
        # Even the trusted fixture cannot accidentally update the frozen policy.
        for query in ("UPDATE voting.election_configs SET config_bytes=config_bytes WHERE election_id=%s",
                      "UPDATE voting.elections SET closes_at=closes_at+interval '1 hour' WHERE election_id=%s"):
            try:
                with fixture() as conn:
                    conn.execute(query, (election,))
            except psycopg.errors.RaiseException:
                pass
            else:
                raise AssertionError("Frozen policy mutation succeeded")
        print("PASS: 20-way uniqueness, duplicate retry, receipts, rollback, closing races, DB time, identity rejection and ACLs")
    except (Exception, SystemExit) as error:
        diagnostics.report(error)  # Capture the original phase BEFORE cleanup changes it.
        raise
    finally:
        if created:
            # No shared fixture, voter or unrelated ballot is ever deleted.
            with diagnostics.at("cleanup"), fixture() as conn:
                verify_database(conn, database, marker)
                for own_election in created:
                    conn.execute("DELETE FROM voting.accepted_ballots WHERE election_id=%s", (own_election,))
                    conn.execute("DELETE FROM voting.election_configs WHERE election_id=%s", (own_election,))
                    conn.execute("DELETE FROM voting.elections WHERE election_id=%s", (own_election,))
                    check(conn.execute("SELECT 1 FROM voting.elections WHERE election_id=%s", (own_election,)).fetchone() is None,
                          "Fixture cleanup failed")


def main(argv=None, *, password_prompt=None, diagnostics=None):
    parser = argparse.ArgumentParser(description="Manual marked-disposable Voting integration only")
    parser.add_argument("--allow-disposable-database", action="store_true", required=True)
    parser.add_argument("--database", required=True)
    parser.add_argument("--marker", required=True)
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args(argv)
    diagnostics = diagnostics if diagnostics is not None else IntegrationDiagnostics()
    diagnostics.set_stage("fixture_seed")
    try:
        designation(args.database, args.marker)  # Before prompting or connecting.
        collect = password if password_prompt is None else password_prompt
        owner = collect("Disposable voting_migrator_login password: ")
        limited = collect("Disposable voting_ballot_login password: ")
        run(factory(args.database, args.marker, args.port, owner, fixture=True),
            factory(args.database, args.marker, args.port, limited), args.database, args.marker,
            diagnostics=diagnostics)
    except Exception as error:
        diagnostics.report(error)  # Emit the safe record before argparse converts to SystemExit.
        parser.exit(1, "FAIL: disposable Voting integration (details suppressed to protect credentials)\n")


if __name__ == "__main__":
    main()
