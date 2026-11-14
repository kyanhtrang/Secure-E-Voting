from collections.abc import Callable
from uuid import UUID

from psycopg import Connection


class PostgreSQLVoterAccountReader:
    """
    Resolve a trusted identity to an active RA voter.

    This class does not authenticate credentials.
    It must only receive identity values produced
    by a trusted CredentialVerifier.
    """

    def __init__(
        self,
        connection_factory: Callable[[], Connection],
    ) -> None:
        self._connection_factory = connection_factory

    def find_active_voter_id(
        self,
        provider: str,
        subject: str,
    ) -> UUID | None:
        with self._connection_factory() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT ra.find_active_voter_id(
                        %s::text,
                        %s::text
                    )
                    """,
                    (provider, subject),
                )

                row = cursor.fetchone()

        if row is None or len(row) != 1:
            raise RuntimeError(
                "Invalid voter identity lookup response"
            )

        voter_id = row[0]

        if voter_id is None:
            return None

        if not isinstance(voter_id, UUID):
            raise RuntimeError(
                "Invalid voter identity lookup result type"
            )

        return voter_id