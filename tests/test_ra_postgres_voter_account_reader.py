from unittest.mock import MagicMock, Mock
from uuid import UUID

import pytest

from backend.ra.postgres_voter_account_reader import (
    PostgreSQLVoterAccountReader,
)


VOTER_ID = UUID("11111111-1111-4111-8111-111111111111")
PROVIDER = "trusted_identity_provider"
SUBJECT = "user-001"


def make_reader(row=None):
    cursor = MagicMock()
    cursor.fetchone.return_value = row

    conn = MagicMock()
    conn.__enter__.return_value = conn
    conn.cursor.return_value.__enter__.return_value = cursor

    factory = Mock(return_value=conn)

    reader = PostgreSQLVoterAccountReader(factory)

    return reader, factory, conn, cursor


def test_connection_created_lazily():
    reader, factory, _, _ = make_reader()

    assert reader is not None
    factory.assert_not_called()


def test_lookup_uses_parameterized_sql():
    reader, factory, conn, cursor = make_reader(
        (VOTER_ID,)
    )

    reader.find_active_voter_id(PROVIDER, SUBJECT)

    sql, params = cursor.execute.call_args.args

    assert "ra.find_active_voter_id" in sql
    assert sql.count("%s::text") == 2

    assert PROVIDER not in sql
    assert SUBJECT not in sql

    assert params == (PROVIDER, SUBJECT)

    factory.assert_called_once_with()
    conn.__exit__.assert_called_once()


def test_existing_active_voter_returns_uuid():
    reader, _, _, _ = make_reader((VOTER_ID,))

    result = reader.find_active_voter_id(
        PROVIDER, SUBJECT
    )

    assert result == VOTER_ID
    assert isinstance(result, UUID)


def test_unknown_or_inactive_voter_returns_none():
    reader, _, _, _ = make_reader((None,))

    result = reader.find_active_voter_id(
        PROVIDER, SUBJECT
    )

    assert result is None


@pytest.mark.parametrize(
    "row",
    [
        None,
        (),
        (VOTER_ID, "unexpected_extra_column"),
    ],
)
def test_malformed_database_response_rejected(row):
    reader, _, _, _ = make_reader(row)

    with pytest.raises(
        RuntimeError,
        match="Invalid voter identity lookup response",
    ):
        reader.find_active_voter_id(
            PROVIDER, SUBJECT
        )


@pytest.mark.parametrize(
    "invalid_value",
    [
        123,
        "11111111-1111-4111-8111-111111111111",
        b"invalid-uuid",
    ],
)
def test_invalid_uuid_type_rejected(invalid_value):
    reader, _, _, _ = make_reader((invalid_value,))

    with pytest.raises(
        RuntimeError,
        match="Invalid voter identity lookup result type",
    ):
        reader.find_active_voter_id(
            PROVIDER, SUBJECT
        )


def test_database_execution_failure_propagates():
    reader, _, conn, cursor = make_reader()

    cursor.execute.side_effect = RuntimeError(
        "Synthetic database failure"
    )

    with pytest.raises(
        RuntimeError,
        match="Synthetic database failure",
    ):
        reader.find_active_voter_id(
            PROVIDER, SUBJECT
        )

    assert (
        conn.__exit__.call_args.args[0]
        is RuntimeError
    )


def test_database_fetch_failure_propagates():
    reader, _, _, cursor = make_reader()

    cursor.fetchone.side_effect = RuntimeError(
        "Database fetch failed"
    )

    with pytest.raises(
        RuntimeError,
        match="Database fetch failed",
    ):
        reader.find_active_voter_id(
            PROVIDER, SUBJECT
        )


def test_connection_failure_propagates():
    factory = Mock(
        side_effect=RuntimeError(
            "Database connection unavailable"
        )
    )

    reader = PostgreSQLVoterAccountReader(factory)

    with pytest.raises(
        RuntimeError,
        match="Database connection unavailable",
    ):
        reader.find_active_voter_id(
            PROVIDER, SUBJECT
        )

    factory.assert_called_once_with()