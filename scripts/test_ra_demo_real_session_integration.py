import getpass
import hashlib
import sys
from datetime import timedelta
from pathlib import Path
from uuid import UUID, uuid4

import psycopg
from psycopg.errors import InsufficientPrivilege

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.ra.postgres_demo_session_issuer import (
    PostgreSQLDemoSessionIssuer,
)


def check(condition, message):
    if not condition:
        raise AssertionError(message)
    print("PASS:", message)


def main():
    auth_password = getpass.getpass(
        "PostgreSQL password for ra_auth_login: "
    )
    migrator_password = getpass.getpass(
        "PostgreSQL password for ra_migrator_login: "
    )

    def auth_connection():
        return psycopg.connect(
            host="127.0.0.1",
            port=5432,
            dbname="ra_db",
            user="ra_auth_login",
            password=auth_password,
            connect_timeout=5,
        )

    def owner_connection():
        conn = psycopg.connect(
            host="127.0.0.1",
            port=5432,
            dbname="ra_db",
            user="ra_migrator_login",
            password=migrator_password,
            connect_timeout=5,
        )
        try:
            conn.execute("SET ROLE ra_owner")
            conn.commit()
            return conn
        except BaseException:
            conn.close()
            raise

    with auth_connection() as conn:
        identity = conn.execute(
            "SELECT current_database(), session_user, current_user"
        ).fetchone()

        check(
            identity == (
                "ra_db",
                "ra_auth_login",
                "ra_auth_login",
            ),
            "Dedicated authentication connection",
        )

    with owner_connection() as conn:
        voter_id = conn.execute(
            """
            SELECT ra.find_active_voter_id(%s, %s)
            """,
            ("demo-local", "demo-voter-001"),
        ).fetchone()[0]

        check(
            isinstance(voter_id, UUID),
            "Registered active demo voter",
        )

        privileges = conn.execute(
            """
            SELECT
                has_schema_privilege(
                    'ra_auth_login', 'ra', 'USAGE'
                ),
                has_function_privilege(
                    'ra_auth_login',
                    'ra.create_session(text,uuid,timestamptz,timestamptz)',
                    'EXECUTE'
                ),
                has_function_privilege(
                    'ra_auth_login',
                    'ra_demo.issue_demo_session(text,uuid)',
                    'EXECUTE'
                )
            """
        ).fetchone()

        check(
            privileges == (False, False, True),
            "Restricted authorization boundary",
        )

    issuer = PostgreSQLDemoSessionIssuer(auth_connection)
    issued_digest = None

    try:
        token = issuer.issue_ra_session(voter_id)
        issued_digest = hashlib.sha256(
            token.encode("ascii")
        ).hexdigest()

        check(
            isinstance(token, str) and len(token) >= 43,
            "Cryptographically generated bearer token",
        )

        with owner_connection() as conn:
            stored = conn.execute(
                """
                SELECT
                    voter_id,
                    token_digest,
                    created_at,
                    expires_at,
                    revoked_at
                FROM ra.ra_sessions
                WHERE token_digest = %s
                """,
                (issued_digest,),
            ).fetchone()

        check(stored is not None, "Session persisted")

        stored_voter, stored_digest, created, expires, revoked = stored

        check(
            stored_voter == voter_id
            and stored_digest == issued_digest
            and stored_digest != token
            and revoked is None,
            "Correct voter and hashed token storage",
        )

        check(
            timedelta(seconds=899)
            <= expires - created
            <= timedelta(seconds=901),
            "Database-enforced 15-minute session TTL",
        )

        try:
            issuer.issue_ra_session(uuid4())
        except InsufficientPrivilege:
            check(
                True,
                "Unauthorized voter session rejected",
            )
        else:
            raise AssertionError(
                "Wrong voter unexpectedly received a session"
            )

    finally:
        if issued_digest is not None:
            with owner_connection() as conn:
                conn.execute(
                    """
                    DELETE FROM ra.ra_sessions
                    WHERE token_digest = %s
                    """,
                    (issued_digest,),
                )

    with owner_connection() as conn:
        remaining = conn.execute(
            """
            SELECT COUNT(*)
            FROM ra.ra_sessions
            WHERE token_digest = %s
            """,
            (issued_digest,),
        ).fetchone()[0]

    check(remaining == 0, "Test session cleanup")
    print("RA real demo session integration: PASS")


if __name__ == "__main__":
    main()