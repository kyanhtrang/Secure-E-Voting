import hashlib
import re
from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest

from backend.ra.postgres_demo_session_issuer import (
    PostgreSQLDemoSessionIssuer,
)


@pytest.fixture
def database():
    conn = MagicMock()

    # Simulate psycopg Connection context manager correctly.
    conn.__enter__.return_value = conn

    factory = MagicMock(return_value=conn)
    cursor = conn.cursor.return_value.__enter__.return_value

    return factory, conn, cursor


def test_token_digest_only_sent_to_database(database):
    factory, conn, cursor = database
    voter_id = uuid4()
    test_token = "synthetic-unit-test-token"

    issuer = PostgreSQLDemoSessionIssuer(factory)

    with patch(
        "backend.ra.postgres_demo_session_issuer"
        ".secrets.token_urlsafe",
        return_value=test_token,
    ) as generator:
        result = issuer.issue_ra_session(voter_id)

    generator.assert_called_once_with(32)
    assert result == test_token

    cursor.execute.assert_called_once()
    sql, parameters = cursor.execute.call_args.args

    expected_digest = hashlib.sha256(
        test_token.encode("ascii")
    ).hexdigest()

    assert "ra_demo.issue_demo_session" in sql
    assert "ra.create_session" not in sql
    assert parameters == (expected_digest, voter_id)
    assert test_token not in str(parameters)

    factory.assert_called_once()
    conn.cursor.assert_called_once()
    conn.__exit__.assert_called_once()


def test_generated_tokens_are_random(database):
    factory, _, _ = database
    issuer = PostgreSQLDemoSessionIssuer(factory)
    voter_id = uuid4()

    first = issuer.issue_ra_session(voter_id)
    second = issuer.issue_ra_session(voter_id)

    assert first != second
    assert len(first) >= 43
    assert len(second) >= 43
    assert re.fullmatch(r"[A-Za-z0-9_-]+", first)
    assert re.fullmatch(r"[A-Za-z0-9_-]+", second)


@pytest.mark.parametrize("invalid_id", [
    None,
    "not-a-uuid",
    123,
])
def test_invalid_voter_id_rejected(database, invalid_id):
    factory, _, _ = database
    issuer = PostgreSQLDemoSessionIssuer(factory)

    with pytest.raises(TypeError):
        issuer.issue_ra_session(invalid_id)

    factory.assert_not_called()


def test_database_failure_propagates(database):
    factory, _, cursor = database
    cursor.execute.side_effect = PermissionError(
        "Database denied session issuance"
    )

    issuer = PostgreSQLDemoSessionIssuer(factory)

    with pytest.raises(PermissionError):
        issuer.issue_ra_session(uuid4())


def test_connection_failure_propagates():
    def failing_connection():
        raise ConnectionError("Database unavailable")

    issuer = PostgreSQLDemoSessionIssuer(
        failing_connection
    )

    with pytest.raises(ConnectionError):
        issuer.issue_ra_session(uuid4())


def test_invalid_connection_factory_rejected():
    with pytest.raises(TypeError):
        PostgreSQLDemoSessionIssuer(None)