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
from backend.ra.session_service import RASessionRecord


def new_digest():
    return hashlib.sha256(secrets.token_bytes(32)).hexdigest()


def main():
    password = getpass.getpass(
        "PostgreSQL password for ra_migrator_login: "
    )

    def owner_connection():
        conn = psycopg.connect(
            host="127.0.0.1",
            port=5432,
            dbname="ra_db",
            user="ra_migrator_login",
            password=password,
            connect_timeout=5,
        )
        try:
            conn.execute("SET ROLE ra_owner")
            conn.commit()
        except BaseException:
            conn.close()
            raise
        return conn

    store = PostgreSQLRASessionStore(owner_connection)

    voter_id = uuid4()
    digest = new_digest()
    now = datetime.now(timezone.utc)
    fixture_created = False

    try:
        # Safety: verify exact database and effective role.
        with owner_connection() as conn:
            identity = conn.execute(
                "SELECT current_database(), session_user, current_user"
            ).fetchone()

            assert identity == (
                "ra_db",
                "ra_migrator_login",
                "ra_owner",
            ), f"Unexpected database identity: {identity}"

            conn.execute(
                """
                INSERT INTO ra.voters (
                    voter_id, auth_provider,
                    auth_subject, is_active
                )
                VALUES (%s, %s, %s, true)
                """,
                (voter_id, "session_adapter_integration", str(voter_id)),
            )

        fixture_created = True
        print("PASS 1/9: Test voter created")

        record = RASessionRecord(
            token_digest=digest,
            voter_id=voter_id,
            created_at=now,
            expires_at=now + timedelta(minutes=10),
        )

        store.save_session(record)
        print("PASS 2/9: Session saved via PostgreSQL function")

        resolved = store.find_session(digest)
        assert resolved is not None
        assert resolved.voter_id == voter_id
        assert resolved.token_digest == digest
        print("PASS 3/9: Session resolved via adapter")

        # Verify commit through an independent connection.
        with owner_connection() as conn:
            count = conn.execute(
                """
                SELECT COUNT(*)
                FROM ra.ra_sessions
                WHERE token_digest = %s
                  AND voter_id = %s
                """,
                (digest, voter_id),
            ).fetchone()[0]

            assert count == 1

        print("PASS 4/9: Session persisted across connections")

        assert store.revoke_session(digest, now) is True
        assert store.find_session(digest) is None
        print("PASS 5/9: Revoked session rejected")

        assert store.revoke_session(digest, now) is False
        print("PASS 6/9: Repeated revocation rejected")

        expired_digest = new_digest()

        with owner_connection() as conn:
            conn.execute(
                """
                INSERT INTO ra.ra_sessions (
                    token_digest, voter_id,
                    created_at, expires_at
                )
                VALUES (%s, %s, %s, %s)
                """,
                (
                    expired_digest,
                    voter_id,
                    now - timedelta(hours=2),
                    now - timedelta(hours=1),
                ),
            )

        assert store.find_session(expired_digest) is None
        print("PASS 7/9: Expired session rejected")

        active_digest = new_digest()

        store.save_session(
            RASessionRecord(
                token_digest=active_digest,
                voter_id=voter_id,
                created_at=datetime.now(timezone.utc),
                expires_at=datetime.now(timezone.utc)
                + timedelta(minutes=10),
            )
        )

        # Test fixture setup only: simulate a disabled voter.
        with owner_connection() as conn:
            conn.execute(
                """
                UPDATE ra.voters
                SET is_active = false
                WHERE voter_id = %s
                """,
                (voter_id,),
            )

        assert store.find_session(active_digest) is None
        print("PASS 8/9: Disabled voter session rejected")

        try:
            store.save_session(
                RASessionRecord(
                    token_digest=new_digest(),
                    voter_id=voter_id,
                    created_at=datetime.now(timezone.utc),
                    expires_at=datetime.now(timezone.utc)
                    + timedelta(minutes=10),
                )
            )
        except psycopg.Error as exc:
            assert exc.sqlstate == "23514", (
                f"Unexpected SQLSTATE: {exc.sqlstate}"
            )
        else:
            raise AssertionError(
                "Inactive voter was allowed to create a session"
            )

        print("PASS 9/9: New session denied for inactive voter")

    finally:
        if fixture_created:
            with owner_connection() as conn:
                conn.execute(
                    """
                    DELETE FROM ra.ra_sessions
                    WHERE voter_id = %s
                    """,
                    (voter_id,),
                )
                conn.execute(
                    """
                    DELETE FROM ra.voters
                    WHERE voter_id = %s
                    """,
                    (voter_id,),
                )

            with owner_connection() as conn:
                remaining = conn.execute(
                    """
                    SELECT COUNT(*) FROM ra.voters
                    WHERE voter_id = %s
                    """,
                    (voter_id,),
                ).fetchone()[0]

                assert remaining == 0, "Fixture cleanup incomplete"

            print("Fixture cleanup: PASS")

    print("RA PostgreSQL adapter integration: PASS 9/9")


if __name__ == "__main__":
    main()