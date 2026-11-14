import getpass
import hashlib
import secrets
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import psycopg

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.ra.postgres_session_store import PostgreSQLRASessionStore
from backend.ra.session_service import (
    RASessionRecord,
    RASessionService,
)


password = getpass.getpass(
    "PostgreSQL password for postgres: "
)


def runtime_connection():
    # Administrative connection used ONLY to simulate
    # the effective privileges of the runtime login.
    conn = psycopg.connect(
        host="127.0.0.1",
        port=5432,
        dbname="ra_db",
        user="postgres",
        password=password,
        connect_timeout=5,
    )

    try:
        conn.execute("SET ROLE ra_service_login")
        conn.commit()

        database, session_user, current_user = conn.execute(
            "SELECT current_database(), session_user, current_user"
        ).fetchone()

        assert (
            database,
            session_user,
            current_user,
        ) == (
            "ra_db",
            "postgres",
            "ra_service_login",
        ), "Unexpected database or effective role"

        conn.commit()
        return conn

    except BaseException:
        conn.close()
        raise


def expect_denied(label, action):
    try:
        action()
    except psycopg.errors.InsufficientPrivilege as exc:
        assert exc.sqlstate == "42501"
        print(f"PASS: {label}")
    else:
        raise AssertionError(
            f"SECURITY FAIL: {label} was unexpectedly allowed"
        )


def main():
    store = PostgreSQLRASessionStore(runtime_connection)

    with runtime_connection() as conn:
        actual_role = conn.execute(
            "SELECT current_user"
        ).fetchone()[0]

        assert actual_role == "ra_service_login"

    print("PASS 1/5: Effective runtime role verified")

    digest = hashlib.sha256(
        secrets.token_bytes(32)
    ).hexdigest()

    voter_id = uuid4()
    now = datetime.now(timezone.utc)

    record = RASessionRecord(
        token_digest=digest,
        voter_id=voter_id,
        created_at=now,
        expires_at=now + timedelta(minutes=10),
    )

    expect_denied(
        "2/5: Runtime adapter cannot save session",
        lambda: store.save_session(record),
    )

    expect_denied(
        "3/5: Runtime adapter cannot resolve session",
        lambda: store.find_session(digest),
    )

    expect_denied(
        "4/5: Runtime adapter cannot revoke session",
        lambda: store.revoke_session(digest, now),
    )

    service = RASessionService(store)

    expect_denied(
        "5/5: Session service cannot issue token "
        "when persistence is denied",
        lambda: service.issue_ra_session(voter_id),
    )

    print("RA runtime adapter fail-closed: PASS 5/5")


if __name__ == "__main__":
    main()