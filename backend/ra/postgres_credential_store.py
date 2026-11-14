"""Explicit two-transaction adapter. Runtime calls restricted functions only."""

from contextlib import contextmanager
from datetime import datetime, timezone
from uuid import UUID

from backend.ra.credential_service import (
    CredentialConflict, CredentialContext, CredentialDenied, CredentialExpired,
    CredentialPolicy, CredentialUnavailable,
)
from backend.ra.session_service import InvalidRASession


ERRORS = {"P4101": InvalidRASession, "P4102": CredentialDenied,
          "P4103": CredentialConflict, "P4104": CredentialExpired}


@contextmanager
def sanitized_database_errors():
    try:
        yield
    except (InvalidRASession, CredentialDenied, CredentialConflict, CredentialExpired, CredentialUnavailable):
        raise
    except Exception as error:
        raise ERRORS.get(getattr(error, "sqlstate", None), CredentialUnavailable)() from None


def context_row(row):
    if row is None or len(row) != 13:
        raise CredentialUnavailable()
    values = list(row)
    for i in (0, 1, 2, 3):
        if not isinstance(values[i], UUID):
            raise CredentialUnavailable()
    for i in (4, 6, 10, 11):
        if values[i] is not None:
            values[i] = bytes(values[i])
    for i in (7, 8):
        if not isinstance(values[i], datetime) or values[i].utcoffset() is None:
            raise CredentialUnavailable()
        values[i] = values[i].astimezone(timezone.utc)
    if (len(values[4]) != 32 or len(values[6]) != 32 or not isinstance(values[5], str)
        or (values[9] is not None and not isinstance(values[9], UUID))):
        raise CredentialUnavailable()
    return CredentialContext(*values)


class _LockedRequest:
    def __init__(self, conn, params, context):
        self._conn, self._params, self.context = conn, params, context

    def complete(self, ciphertext, nonce, storage_key_id):
        row = self._conn.execute(
            "SELECT * FROM ra_credential.complete_request(%s::text,%s::uuid,%s::uuid,%s::bytea,%s::bytea,%s::bytea,%s::bytea,%s::text)",
            (*self._params, ciphertext, nonce, storage_key_id),
        ).fetchone()
        return context_row(row)


class PostgreSQLCredentialStore:
    def __init__(self, connection_factory):
        self._connection_factory = connection_factory

    def policy(self, session_digest, election_id):
        with sanitized_database_errors():
            with self._connection_factory() as conn:
                row = conn.execute(
                    "SELECT * FROM ra_credential.policy_for_session(%s::text,%s::uuid)",
                    (session_digest, election_id),
                ).fetchone()
                if row is None or len(row) != 6:
                    raise CredentialUnavailable()
                return CredentialPolicy(bytes(row[0]), bytes(row[1]), bytes(row[2]),
                                        row[3], bytes(row[4]), bytes(row[5]))

    def reserve(self, *params):
        with sanitized_database_errors():
            with self._connection_factory() as conn:
                row = conn.execute(
                    "SELECT * FROM ra_credential.reserve_request(%s::text,%s::uuid,%s::uuid,%s::bytea,%s::bytea)", params,
                ).fetchone()
                context = context_row(row)
            return context  # Connection context has committed before returning.

    @contextmanager
    def locked(self, *params):
        with sanitized_database_errors():
            with self._connection_factory() as conn:
                row = conn.execute(
                    "SELECT * FROM ra_credential.lock_request(%s::text,%s::uuid,%s::uuid,%s::bytea,%s::bytea)", params,
                ).fetchone()
                yield _LockedRequest(conn, params, context_row(row))
            # Commit/connection failures propagate; callers cannot return success.
