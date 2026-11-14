"""Manual existing-demo smoke test: never writes or removes a voter.

Run after human approval and reviewed migration application:
python scripts/test_ra_demo_existing_smoke.py --existing-demo-session-writes
"""

import argparse
import secrets
import sys
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch
from uuid import UUID

from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.ra.demo_auth_runtime import demo_connection_factory
from backend.ra.demo_launcher import create_demo_app
from scripts.ra_demo_db_test_support import (
    check, database_factory, digest, prompt_password, require_migration,
    synthetic_environment,
)


PREFIX = "/api/v1/ra/auth"


def existing_voter(conn):
    row = conn.execute(
        """SELECT voter_id, auth_provider, auth_subject, is_active, created_at, updated_at
           FROM ra.voters WHERE auth_provider=%s AND auth_subject=%s""",
        ("demo-local", "demo-voter-001"),
    ).fetchone()
    check(row is not None and isinstance(row[0], UUID) and row[3] is True,
          "An existing active demo voter is required; no voter will be created")
    return row


def run_smoke(fixture_connection, runtime_connection, environment, password):
    # Reserve a freshly random token before issuance so cleanup can identify
    # precisely this test's session, even after a lost/failed login response.
    token = secrets.token_urlsafe(32)
    token_digest = digest(token)
    with fixture_connection() as conn:
        require_migration(conn)
        before = existing_voter(conn)
        check(conn.execute(
            "SELECT 1 FROM ra.ra_sessions WHERE token_digest=%s", (token_digest,)
        ).fetchone() is None, "Reserved session digest already exists; refusing test")
    voter_id = before[0]
    try:
        app = create_demo_app(environment, connection_factory=runtime_connection)
        with TestClient(app, base_url="http://127.0.0.1:8000",
                        client=("127.0.0.1", 50000)) as client:
            # Only token generation is supplied; the real HTTP, verifier,
            # issuer, connections, SQL functions, and commits remain in use.
            with patch("backend.ra.postgres_demo_session_issuer.secrets.token_urlsafe",
                       return_value=token):
                response = client.post(PREFIX + "/login", json={
                    "username": environment["RA_DEMO_USERNAME"], "password": password
                })
            check(response.status_code == 200
                  and response.json() == {"access_token": token, "token_type": "Bearer"},
                  "Existing-demo login failed")
            check(response.headers.get("cache-control") == "no-store", "Missing login cache policy")
            with fixture_connection() as conn:
                check(conn.execute(
                    """SELECT voter_id, expires_at-created_at, revoked_at
                       FROM ra.ra_sessions WHERE token_digest=%s""", (token_digest,)
                ).fetchone() == (voter_id, timedelta(minutes=15), None),
                    "ASCII digest or database-controlled TTL mismatch")
            headers = {"Authorization": "Bearer " + token}
            response = client.get(PREFIX + "/me", headers=headers)
            check(response.status_code == 200 and response.json() == {"voter_id": str(voter_id)},
                  "Existing-demo session verification failed")
            check(client.post(PREFIX + "/logout", headers=headers).status_code == 204,
                  "Existing-demo logout failed")
            check(client.get(PREFIX + "/me", headers=headers).status_code == 401,
                  "Logged-out session accepted")
            check(client.post(PREFIX + "/logout", headers=headers).status_code == 204,
                  "Repeated logout failed")
            with fixture_connection() as conn:
                check(conn.execute(
                    """SELECT revoked_at IS NOT NULL FROM ra.ra_sessions
                       WHERE token_digest=%s AND voter_id=%s""", (token_digest, voter_id)
                ).fetchone() == (True,), "Logout revocation did not persist")
    finally:
        with fixture_connection() as conn:
            # No voter writes, no voter-wide session deletion, no unrelated IDs.
            conn.execute(
                "DELETE FROM ra.ra_sessions WHERE token_digest=%s AND voter_id=%s",
                (token_digest, voter_id),
            )
        # Check separately so a concurrent voter change cannot roll cleanup back.
        with fixture_connection() as conn:
            check(existing_voter(conn) == before, "Existing voter changed during smoke test")
            check(conn.execute(
                "SELECT 1 FROM ra.ra_sessions WHERE token_digest=%s", (token_digest,)
            ).fetchone() is None, "Smoke session cleanup failed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--existing-demo-session-writes", action="store_true", required=True)
    parser.parse_args()
    auth_password = prompt_password("Existing ra_db password for ra_auth_login: ")
    fixture_password = prompt_password("Session-inspection/cleanup password for ra_migrator_login: ")
    password, environment = synthetic_environment(auth_password)
    run_smoke(
        database_factory(fixture_password, fixture=True),
        demo_connection_factory(auth_password), environment, password,
    )
    print("PASS: existing-demo lifecycle, ASCII digest, TTL, exact-session cleanup; voter unchanged")


if __name__ == "__main__":
    try:
        main()
    except AssertionError as exc:
        raise SystemExit(str(exc)) from None
    except Exception:
        raise SystemExit("Existing-demo smoke test failed; internal details suppressed") from None
