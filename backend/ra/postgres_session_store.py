from collections.abc import Callable
from datetime import datetime

from psycopg import Connection

from backend.ra.session_service import RASessionRecord


class PostgreSQLRASessionStore:
    """
    PostgreSQL implementation of RASessionStore.

    Uses restricted database functions rather than
    direct SELECT/INSERT/UPDATE on session tables.

    The connection factory must provide an already
    authorized database connection.
    """

    def __init__(
        self,
        connection_factory: Callable[[], Connection],
    ) -> None:
        self._connection_factory = connection_factory

    def save_session(
        self,
        record: RASessionRecord,
    ) -> None:
        with self._connection_factory() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT ra.create_session(
                        %s::text,
                        %s::uuid,
                        %s::timestamptz,
                        %s::timestamptz
                    )
                    """,
                    (
                        record.token_digest,
                        record.voter_id,
                        record.created_at,
                        record.expires_at,
                    ),
                )

    def find_session(
        self,
        token_digest: str,
    ) -> RASessionRecord | None:
        with self._connection_factory() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT
                        voter_id,
                        created_at,
                        expires_at,
                        revoked_at
                    FROM ra.find_active_session(%s::text)
                    """,
                    (token_digest,),
                )

                row = cursor.fetchone()

        if row is None:
            return None

        return RASessionRecord(
            token_digest=token_digest,
            voter_id=row[0],
            created_at=row[1],
            expires_at=row[2],
            revoked_at=row[3],
        )

    def revoke_session(
        self,
        token_digest: str,
        revoked_at: datetime,
    ) -> bool:
        # The PostgreSQL function uses trusted database
        # server time. The Python timestamp is not used.
        _ = revoked_at

        with self._connection_factory() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT ra.revoke_session(%s::text)
                    """,
                    (token_digest,),
                )

                row = cursor.fetchone()

        if row is None:
            raise RuntimeError(
                "Session revocation returned no result"
            )

        if not isinstance(row[0], bool):
            raise RuntimeError(
                "Invalid session revocation response"
            )

        return row[0]