from unittest.mock import MagicMock, Mock
from uuid import UUID

import pytest

from backend.ra.auth_service import (
    RAAuthenticationService,
    VerifiedIdentity,
    AuthenticationDenied,
    AuthenticationUnavailable,
)
from backend.ra.postgres_voter_account_reader import (
    PostgreSQLVoterAccountReader,
)


VOTER_ID = UUID("11111111-1111-4111-8111-111111111111")
IDENTITY = VerifiedIdentity(
    provider="trusted_provider",
    subject="subject-001",
)


def setup_authentication(row=(VOTER_ID,)):
    cursor = MagicMock()
    cursor.fetchone.return_value = row

    conn = MagicMock()
    conn.__enter__.return_value = conn
    conn.cursor.return_value.__enter__.return_value = cursor

    factory = Mock(return_value=conn)
    reader = PostgreSQLVoterAccountReader(factory)

    verifier = MagicMock()
    verifier.verify_credentials.return_value = IDENTITY

    issuer = MagicMock()
    issuer.issue_ra_session.return_value = "synthetic-ra-token"

    service = RAAuthenticationService(
        verifier,
        reader,
        issuer,
    )

    return service, verifier, issuer, factory, cursor


def test_successful_login_uses_verified_identity():
    service, verifier, issuer, factory, cursor = (
        setup_authentication()
    )

    token = service.login("alice", "example-password")

    assert token == "synthetic-ra-token"

    verifier.verify_credentials.assert_called_once_with(
        "alice", "example-password"
    )

    sql, params = cursor.execute.call_args.args

    assert "ra.find_active_voter_id" in sql
    assert params == ("trusted_provider", "subject-001")
    assert "example-password" not in sql
    assert "example-password" not in params

    factory.assert_called_once_with()
    issuer.issue_ra_session.assert_called_once_with(VOTER_ID)


def test_invalid_credentials_never_query_database():
    service, verifier, issuer, factory, _ = (
        setup_authentication()
    )
    verifier.verify_credentials.return_value = None

    with pytest.raises(AuthenticationDenied):
        service.login("alice", "wrong-password")

    factory.assert_not_called()
    issuer.issue_ra_session.assert_not_called()


def test_unknown_voter_cannot_get_session():
    service, _, issuer, _, _ = setup_authentication(
        row=(None,)
    )

    with pytest.raises(AuthenticationDenied):
        service.login("alice", "example-password")

    issuer.issue_ra_session.assert_not_called()


def test_database_failure_fails_closed():
    service, _, issuer, _, cursor = setup_authentication()

    cursor.execute.side_effect = RuntimeError(
        "Database unavailable"
    )

    with pytest.raises(AuthenticationUnavailable):
        service.login("alice", "example-password")

    issuer.issue_ra_session.assert_not_called()


def test_verifier_failure_fails_closed():
    service, verifier, issuer, factory, _ = (
        setup_authentication()
    )

    verifier.verify_credentials.side_effect = RuntimeError(
        "Identity Provider unavailable"
    )

    with pytest.raises(AuthenticationUnavailable):
        service.login("alice", "example-password")

    factory.assert_not_called()
    issuer.issue_ra_session.assert_not_called()


def test_session_issuer_failure_fails_closed():
    service, _, issuer, _, _ = setup_authentication()

    issuer.issue_ra_session.side_effect = RuntimeError(
        "Session persistence failure"
    )

    with pytest.raises(AuthenticationUnavailable):
        service.login("alice", "example-password")


@pytest.mark.parametrize(
    "username,password",
    [
        ("", "example-password"),
        ("alice", ""),
    ],
)
def test_empty_credentials_rejected(username, password):
    service, verifier, issuer, factory, _ = (
        setup_authentication()
    )

    with pytest.raises(AuthenticationDenied):
        service.login(username, password)

    verifier.verify_credentials.assert_not_called()
    factory.assert_not_called()
    issuer.issue_ra_session.assert_not_called()


def test_malformed_database_result_fails_closed():
    service, _, issuer, _, _ = setup_authentication(
        row=("not-a-uuid",)
    )

    with pytest.raises(AuthenticationUnavailable):
        service.login("alice", "example-password")

    issuer.issue_ra_session.assert_not_called()