"""Dedicated adapters: no access to general RA functions or tables."""

from collections.abc import Callable
from datetime import datetime
from uuid import UUID

from psycopg import Connection

from backend.ra.session_service import RASessionRecord


class PostgreSQLDemoVoterAccountReader:
    def __init__(self, connection_factory: Callable[[], Connection]):
        self._connection_factory = connection_factory

    def find_active_voter_id(self, provider: str, subject: str) -> UUID | None:
        with self._connection_factory() as conn:
            row = conn.execute(
                "SELECT ra_demo.find_active_demo_voter_id(%s::text, %s::text)",
                (provider, subject),
            ).fetchone()
        if row is None or len(row) != 1:
            raise RuntimeError("Invalid demo identity response")
        if row[0] is not None and not isinstance(row[0], UUID):
            raise RuntimeError("Invalid demo identity response")
        return row[0]


class PostgreSQLDemoSessionStore:
    def __init__(self, connection_factory: Callable[[], Connection]):
        self._connection_factory = connection_factory

    def save_session(self, record: RASessionRecord) -> None:
        raise RuntimeError("Use the restricted demo session issuer")

    def find_session(self, token_digest: str) -> RASessionRecord | None:
        with self._connection_factory() as conn:
            row = conn.execute(
                """SELECT voter_id, created_at, expires_at, revoked_at
                   FROM ra_demo.find_active_demo_session(%s::text)""",
                (token_digest,),
            ).fetchone()
        if row is None:
            return None
        if (
            len(row) != 4
            or not isinstance(row[0], UUID)
            or not isinstance(row[1], datetime)
            or not isinstance(row[2], datetime)
            or (row[3] is not None and not isinstance(row[3], datetime))
        ):
            raise RuntimeError("Invalid demo session response")
        return RASessionRecord(token_digest, *row)

    def revoke_session(self, token_digest: str, revoked_at: datetime) -> bool:
        # The wrapper assigns revocation time using the database clock.
        with self._connection_factory() as conn:
            row = conn.execute(
                "SELECT ra_demo.revoke_demo_session(%s::text)",
                (token_digest,),
            ).fetchone()
        if row is None or len(row) != 1 or not isinstance(row[0], bool):
            raise RuntimeError("Invalid demo revocation response")
        return row[0]
