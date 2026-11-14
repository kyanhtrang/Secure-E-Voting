import getpass
import sys
from pathlib import Path
from uuid import uuid4

import psycopg

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.ra.postgres_voter_account_reader import (
    PostgreSQLVoterAccountReader,
)


def check(condition, label):
    if not condition:
        raise AssertionError(f"FAIL: {label}")
    print(f"PASS: {label}")


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
            return conn
        except BaseException:
            conn.close()
            raise

    reader = PostgreSQLVoterAccountReader(
        owner_connection
    )

    voter_id = uuid4()
    provider = "reader_integration_test"
    subject = str(voter_id)
    fixture_created = False

    try:
        with owner_connection() as conn:
            identity = conn.execute(
                """
                SELECT current_database(),
                       session_user,
                       current_user
                """
            ).fetchone()

        check(
            identity == (
                "ra_db",
                "ra_migrator_login",
                "ra_owner",
            ),
            "1/9: Database and effective role verified",
        )

        # Create an isolated synthetic voter.
        with owner_connection() as conn:
            conn.execute(
                """
                INSERT INTO ra.voters (
                    voter_id,
                    auth_provider,
                    auth_subject,
                    is_active
                )
                VALUES (%s, %s, %s, true)
                """,
                (voter_id, provider, subject),
            )

        fixture_created = True

        # Test committed data from a separate connection.
        result = reader.find_active_voter_id(
            provider, subject
        )

        check(
            result == voter_id,
            "2/9: Active voter resolved to correct UUID",
        )

        check(
            reader.find_active_voter_id(
                "wrong_provider", subject
            ) is None,
            "3/9: Wrong provider rejected",
        )

        check(
            reader.find_active_voter_id(
                provider, "wrong_subject"
            ) is None,
            "4/9: Wrong subject rejected",
        )

        check(
            reader.find_active_voter_id(
                provider, str(uuid4())
            ) is None,
            "5/9: Unknown identity rejected",
        )

        check(
            reader.find_active_voter_id(
                provider.upper(), subject
            ) is None,
            "6/9: Exact provider matching",
        )

        check(
            reader.find_active_voter_id(
                "", subject
            ) is None
            and reader.find_active_voter_id(
                provider, "   "
            ) is None
            and reader.find_active_voter_id(
                "p" * 129, subject
            ) is None,
            "7/9: Invalid identity inputs rejected",
        )

        check(
            reader.find_active_voter_id(
                provider, "' OR TRUE --"
            ) is None,
            "8/9: SQL injection-like input rejected",
        )

        # Deactivate voter and verify future lookups.
        with owner_connection() as conn:
            conn.execute(
                """
                UPDATE ra.voters
                SET is_active = false
                WHERE voter_id = %s
                """,
                (voter_id,),
            )

        check(
            reader.find_active_voter_id(
                provider, subject
            ) is None,
            "9/9: Disabled voter no longer resolved",
        )

    finally:
        if fixture_created:
            with owner_connection() as conn:
                conn.execute(
                    """
                    DELETE FROM ra.voters
                    WHERE voter_id = %s
                      AND auth_provider = %s
                    """,
                    (voter_id, provider),
                )

            with owner_connection() as conn:
                remaining = conn.execute(
                    """
                    SELECT COUNT(*)
                    FROM ra.voters
                    WHERE voter_id = %s
                    """,
                    (voter_id,),
                ).fetchone()[0]

            check(
                remaining == 0,
                "Fixture cleanup",
            )

    print(
        "RA voter reader PostgreSQL integration: "
        "PASS 9/9"
    )


if __name__ == "__main__":
    main()