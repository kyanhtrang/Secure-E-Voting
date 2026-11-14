"""MANUAL PostgreSQL test, never part of database-free pytest discovery.

Requires a distinct ra_demo_test_ database and an independently installed
database comment matching --disposable-marker. Never targets existing ra_db.

The application uses ra_auth_login only. A separate fixture connection uses
ra_migrator_login/ra_owner for setup, assertions, and UUID-scoped cleanup.
No role provisioning, grants, or migrations are performed by this script.
"""

import argparse
import secrets
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path
from uuid import uuid4

from fastapi.testclient import TestClient
from psycopg.errors import InsufficientPrivilege

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.ra.demo_launcher import create_demo_app
from scripts.ra_demo_db_test_support import (
    check, database_factory, digest, prompt_password, seed_disposable_voters,
    synthetic_environment, validate_disposable_designation,
)


PREFIX = "/api/v1/ra/auth"
WRAPPERS = {
    "issue_demo_session": "v",
    "find_active_demo_voter_id": "s",
    "find_active_demo_session": "v",
    "revoke_demo_session": "v",
}


def assert_denied(factory, sql):
    try:
        with factory() as conn:
            conn.execute(sql)
    except InsufficientPrivilege:
        return
    raise AssertionError("Protected runtime operation was not denied")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--disposable-fixture-writes", action="store_true", required=True)
    parser.add_argument("--database", required=True)
    parser.add_argument("--disposable-marker", required=True)
    parser.add_argument("--port", type=int, default=5432)
    args = parser.parse_args()
    validate_disposable_designation(args.database, args.disposable_marker)
    auth_password = prompt_password("Disposable DB password for ra_auth_login: ")
    fixture_password = prompt_password("Fixture-only password for ra_migrator_login: ")
    target = dict(database=args.database, port=args.port, disposable_marker=args.disposable_marker)
    runtime_connection = database_factory(auth_password, **target)
    fixture_connection = database_factory(fixture_password, fixture=True, **target)

    voter_id, other_id = uuid4(), uuid4()
    fixture_created = False
    try:
        with fixture_connection() as conn:
            seed_disposable_voters(
                conn, voter_id, other_id, database=args.database,
                marker=args.disposable_marker,
            )
        fixture_created = True

        with runtime_connection() as conn:
            check(conn.execute(
                "SELECT has_schema_privilege(current_user, 'ra', 'USAGE')"
            ).fetchone() == (False,), "General RA schema unexpectedly accessible")
            rows = conn.execute(
                """SELECT p.proname, p.prosecdef, r.rolname, p.provolatile,
                          p.proconfig, has_function_privilege(current_user, p.oid, 'EXECUTE'),
                          NOT EXISTS (
                              SELECT 1 FROM aclexplode(COALESCE(
                                  p.proacl, acldefault('f', p.proowner)
                              )) AS a
                              WHERE a.grantee NOT IN (p.proowner,
                                  (SELECT oid FROM pg_roles WHERE rolname='ra_auth_login'))
                          )
                   FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
                   JOIN pg_roles r ON r.oid=p.proowner
                   WHERE n.nspname='ra_demo'"""
            ).fetchall()
            check(len(rows) == len(WRAPPERS) and {row[0] for row in rows} == set(WRAPPERS),
                  "Unexpected demo function surface")
            for name, definer, owner, volatility, config, execute, restricted_acl in rows:
                check(definer and owner == "ra_owner" and execute and restricted_acl
                      and volatility == WRAPPERS[name]
                      and "search_path=pg_catalog,ra,pg_temp" in "".join("".join(config or []).split()),
                      "Demo function metadata or ACL mismatch")
            check(not any(row[0] for row in conn.execute(
                """SELECT has_function_privilege(current_user, p.oid, 'EXECUTE')
                   FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
                   WHERE n.nspname='ra'"""
            )), "General RA function execution unexpectedly allowed")
            check(not any(any(row) for row in conn.execute(
                """SELECT has_table_privilege(current_user, c.oid, 'SELECT'),
                          has_table_privilege(current_user, c.oid, 'INSERT'),
                          has_table_privilege(current_user, c.oid, 'UPDATE'),
                          has_table_privilege(current_user, c.oid, 'DELETE')
                   FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
                   WHERE n.nspname='ra' AND c.relkind IN ('r','p')"""
            )), "Direct RA table access unexpectedly allowed")
            check(conn.execute(
                "SELECT ra_demo.find_active_demo_voter_id(%s,%s)",
                ("demo-e2e-fixture", str(other_id)),
            ).fetchone() == (None,), "Other identity accessible through demo wrapper")

        for sql in (
            "SELECT * FROM ra.ra_sessions LIMIT 0",
            "UPDATE ra.ra_sessions SET revoked_at=clock_timestamp() WHERE false",
            "SELECT ra.find_active_voter_id('demo-local','demo-voter-001')",
            "SELECT ra.find_active_session(repeat('a',64))",
            "SELECT ra.revoke_session(repeat('a',64))",
            "SELECT ra.create_session(NULL::text,NULL::uuid,NULL::timestamptz,NULL::timestamptz)",
            "SET ROLE ra_owner",
            "SET ROLE ra_migrator_login",
            "SET ROLE postgres",
        ):
            assert_denied(runtime_connection, sql)

        password, environment = synthetic_environment(auth_password)
        with TestClient(create_demo_app(environment, connection_factory=runtime_connection),
                        base_url="http://127.0.0.1:8000",
                        client=("127.0.0.1", 50000)) as client:
            def login():
                response = client.post(PREFIX + "/login", json={
                    "username": "demo-e2e", "password": password
                })
                check(response.status_code == 200, "Real login failed")
                check(response.headers.get("cache-control") == "no-store", "Missing cache policy")
                return response.json()["access_token"]

            def headers(token):
                return {"Authorization": "Bearer " + token}

            token = login()
            with fixture_connection() as conn:
                row = conn.execute(
                    """SELECT voter_id, expires_at-created_at, revoked_at
                       FROM ra.ra_sessions WHERE token_digest=%s""", (digest(token),)
                ).fetchone()
                check(row == (voter_id, timedelta(minutes=15), None), "Digest or database TTL mismatch")
            response = client.get(PREFIX + "/me", headers=headers(token))
            check(response.status_code == 200 and response.json() == {"voter_id": str(voter_id)},
                  "Real session verification failed")
            check(client.post(PREFIX + "/logout", headers=headers(token)).status_code == 204,
                  "Real logout failed")
            check(client.post(PREFIX + "/logout", headers=headers(token)).status_code == 204,
                  "Repeated logout failed")
            check(client.get(PREFIX + "/me", headers=headers(token)).status_code == 401,
                  "Revoked session accepted")
            with fixture_connection() as conn:
                check(conn.execute(
                    "SELECT revoked_at IS NOT NULL FROM ra.ra_sessions WHERE token_digest=%s",
                    (digest(token),),
                ).fetchone() == (True,), "Revocation did not persist")

            other_token = secrets.token_urlsafe(32)
            with fixture_connection() as conn:
                conn.execute(
                    """WITH t AS (SELECT clock_timestamp() AS now)
                       SELECT ra.create_session(%s,%s,t.now,t.now+interval '15 minutes') FROM t""",
                    (digest(other_token), other_id),
                )
            check(client.get(PREFIX + "/me", headers=headers(other_token)).status_code == 401,
                  "Other voter session accepted")
            check(client.post(PREFIX + "/logout", headers=headers(other_token)).status_code == 204,
                  "Other-voter logout leaked existence")
            with fixture_connection() as conn:
                check(conn.execute(
                    "SELECT revoked_at FROM ra.ra_sessions WHERE token_digest=%s", (digest(other_token),)
                ).fetchone() == (None,), "Other voter session revoked")

            expired = login()
            with fixture_connection() as conn:
                conn.execute(
                    """UPDATE ra.ra_sessions SET created_at=clock_timestamp()-interval '20 minutes',
                       expires_at=clock_timestamp()-interval '5 minutes' WHERE token_digest=%s""",
                    (digest(expired),),
                )
            check(client.get(PREFIX + "/me", headers=headers(expired)).status_code == 401,
                  "Expired session accepted")

            concurrent = login()

            def revoke(_):
                with runtime_connection() as conn:
                    return conn.execute(
                        "SELECT ra_demo.revoke_demo_session(%s)", (digest(concurrent),)
                    ).fetchone()[0]

            with ThreadPoolExecutor(max_workers=2) as executor:
                check(sorted(executor.map(revoke, range(2))) == [False, True],
                      "Concurrent revocation was not idempotent")
            disabled = login()
            with fixture_connection() as conn:
                conn.execute("UPDATE ra.voters SET is_active=false WHERE voter_id=%s", (voter_id,))
            check(client.get(PREFIX + "/me", headers=headers(disabled)).status_code == 401,
                  "Disabled voter session accepted")
            check(client.post(PREFIX + "/logout", headers=headers(disabled)).status_code == 204,
                  "Disabled voter session could not be revoked")
    finally:
        if fixture_created:
            with fixture_connection() as conn:
                conn.execute("DELETE FROM ra.ra_sessions WHERE voter_id IN (%s,%s)", (voter_id, other_id))
                conn.execute("DELETE FROM ra.voters WHERE voter_id IN (%s,%s)", (voter_id, other_id))
    print("PASS: real RA demo lifecycle, scoped permissions, expiry, disablement, concurrent revocation")


if __name__ == "__main__":
    try:
        main()
    except AssertionError as exc:
        raise SystemExit(str(exc)) from None
    except Exception:
        raise SystemExit("RA demo integration failed; internal details suppressed") from None
