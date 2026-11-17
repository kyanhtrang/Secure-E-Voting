"""Parameterized restricted-function calls; a successful return follows COMMIT."""

from contextlib import contextmanager
from datetime import datetime

from backend.voting.ballot_service import (
    AlreadySpent, ElectionClosed, ElectionPolicy, ReceiptNotFound, VotingUnavailable,
)


@contextmanager
def sanitized_errors():
    try:
        yield
    except (AlreadySpent, ElectionClosed, ReceiptNotFound, VotingUnavailable):
        raise
    except Exception as error:
        kind = {"P4201": ElectionClosed, "P4202": AlreadySpent,
                "P4203": ReceiptNotFound}.get(getattr(error, "sqlstate", None), VotingUnavailable)
        raise kind() from None


class PostgreSQLBallotStore:
    def __init__(self, connection_factory):
        self._connect = connection_factory

    def policy(self, election):
        with sanitized_errors():
            with self._connect() as conn:
                row = conn.execute("SELECT * FROM voting.ballot_policy(%s::uuid)", (election,)).fetchone()
                if row is None or len(row) != 6:
                    raise VotingUnavailable()
                policy = ElectionPolicy(*(bytes(value) for value in row[:4]), *row[4:])
                if (len(policy.signature) != 64 or len(policy.config_digest) != 32
                        or len(policy.authority_fingerprint) != 32
                        or any(not isinstance(t, datetime) or t.utcoffset() is None for t in row[4:])):
                    raise VotingUnavailable()
            return policy

    def _call(self, function, ballot):
        # Function names are selected internally, never interpolated from input.
        queries = {
            "accept": "SELECT voting.accept_anonymous_ballot(%s::uuid,%s::bytea,%s::bytea,%s::bytea,%s::bytea,%s::bytea)",
            "receipt": "SELECT voting.recover_ballot_receipt(%s::uuid,%s::bytea,%s::bytea,%s::bytea,%s::bytea,%s::bytea)",
        }
        params = (ballot.election_id, ballot.config_digest, ballot.serial,
                  ballot.envelope, ballot.prepared_msg, ballot.signature)
        with sanitized_errors():
            with self._connect() as conn:
                row = conn.execute(queries[function], params).fetchone()
                if row is None or len(row) != 1 or len(bytes(row[0])) != 32:
                    raise VotingUnavailable()
                result = bytes(row[0])
            return result  # psycopg's context has committed and closed.

    def accept(self, ballot):
        return self._call("accept", ballot)

    def receipt(self, ballot):
        return self._call("receipt", ballot)
