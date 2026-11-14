import hashlib
import secrets
from collections.abc import Callable
from uuid import UUID

from psycopg import Connection


class PostgreSQLDemoSessionIssuer:
    """
    Local demo session issuer.

    Uses only ra_demo.issue_demo_session.
    Never connects as a database owner or migrator.
    """

    def __init__(
        self,
        connection_factory: Callable[[], Connection],
    ):
        if not callable(connection_factory):
            raise TypeError("Connection factory must be callable")

        self._connection_factory = connection_factory

    def issue_ra_session(self, voter_id: UUID) -> str:
        if not isinstance(voter_id, UUID):
            raise TypeError("voter_id must be a UUID")

        # 32 cryptographically random bytes.
        token = secrets.token_urlsafe(32)

        # Only the digest is persisted in PostgreSQL.
        token_digest = hashlib.sha256(
            token.encode("ascii")
        ).hexdigest()

        with self._connection_factory() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT ra_demo.issue_demo_session(
                        %s::text,
                        %s::uuid
                    )
                    """,
                    (token_digest, voter_id),
                )

        # Return plaintext only after DB operation succeeds.
        return token