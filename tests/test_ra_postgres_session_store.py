from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, Mock
from uuid import UUID

import pytest

from backend.ra.postgres_session_store import PostgreSQLRASessionStore
from backend.ra.session_service import RASessionRecord


VOTER_ID = UUID("11111111-1111-4111-8111-111111111111")
DIGEST = "a" * 64

NOW = datetime(2026, 11, 13, 1, 0, tzinfo=timezone.utc)
EXPIRY = NOW + timedelta(minutes=15)


def make_store(row=None):
    cursor = MagicMock()
    cursor.fetchone.return_value = row

    conn = MagicMock()
    conn.__enter__.return_value = conn
    conn.cursor.return_value.__enter__.return_value = cursor

    factory = Mock(return_value=conn)

    return PostgreSQLRASessionStore(factory), factory, conn, cursor


def test_connection_created_lazily():
    store, factory, _, _ = make_store()

    assert store is not None
    factory.assert_not_called()


def test_save_session_uses_parameterized_sql():
    store, factory, conn, cursor = make_store()

    record = RASessionRecord(
        token_digest=DIGEST,
        voter_id=VOTER_ID,
        created_at=NOW,
        expires_at=EXPIRY,
    )

    store.save_session(record)

    sql, params = cursor.execute.call_args.args

    assert "ra.create_session" in sql
    assert "%s::text" in sql
    assert DIGEST not in sql
    assert params == (
        DIGEST, VOTER_ID, NOW, EXPIRY
    )

    factory.assert_called_once_with()
    conn.__exit__.assert_called_once()


def test_save_failure_propagates():
    store, _, conn, cursor = make_store()

    cursor.execute.side_effect = RuntimeError(
        "Synthetic database failure"
    )

    record = RASessionRecord(
        token_digest=DIGEST,
        voter_id=VOTER_ID,
        created_at=NOW,
        expires_at=EXPIRY,
    )

    with pytest.raises(RuntimeError):
        store.save_session(record)

    assert conn.__exit__.call_args.args[0] is RuntimeError


def test_find_session_returns_record():
    store, _, _, cursor = make_store(
        (VOTER_ID, NOW, EXPIRY, None)
    )

    result = store.find_session(DIGEST)

    assert result == RASessionRecord(
        token_digest=DIGEST,
        voter_id=VOTER_ID,
        created_at=NOW,
        expires_at=EXPIRY,
        revoked_at=None,
    )

    sql, params = cursor.execute.call_args.args

    assert "ra.find_active_session" in sql
    assert DIGEST not in sql
    assert params == (DIGEST,)


def test_find_missing_session_returns_none():
    store, _, _, _ = make_store(None)

    assert store.find_session(DIGEST) is None


def test_find_failure_does_not_return_session():
    store, _, _, cursor = make_store()

    cursor.execute.side_effect = RuntimeError(
        "Database unavailable"
    )

    with pytest.raises(RuntimeError):
        store.find_session(DIGEST)


@pytest.mark.parametrize("expected", [True, False])
def test_revoke_returns_database_result(expected):
    store, _, _, cursor = make_store((expected,))

    result = store.revoke_session(DIGEST, NOW)

    assert result is expected

    sql, params = cursor.execute.call_args.args

    assert "ra.revoke_session" in sql
    assert DIGEST not in sql
    assert params == (DIGEST,)


def test_revoke_missing_result_fails_closed():
    store, _, _, _ = make_store(None)

    with pytest.raises(
        RuntimeError,
        match="no result"
    ):
        store.revoke_session(DIGEST, NOW)


@pytest.mark.parametrize("bad_value", [None, 1, "true"])
def test_revoke_invalid_result_rejected(bad_value):
    store, _, _, _ = make_store((bad_value,))

    with pytest.raises(
        RuntimeError,
        match="Invalid session revocation response"
    ):
        store.revoke_session(DIGEST, NOW)


def test_revoke_database_failure_propagates():
    store, _, conn, cursor = make_store()

    cursor.execute.side_effect = RuntimeError(
        "Synthetic revocation failure"
    )

    with pytest.raises(RuntimeError):
        store.revoke_session(DIGEST, NOW)

    assert conn.__exit__.call_args.args[0] is RuntimeError