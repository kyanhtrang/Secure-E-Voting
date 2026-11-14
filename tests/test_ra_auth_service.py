from unittest.mock import Mock
from uuid import UUID

import pytest

from backend.ra.auth_service import (
    AuthenticationDenied,
    AuthenticationUnavailable,
    RAAuthenticationService,
    VerifiedIdentity,
)


VOTER_ID = UUID("11111111-1111-4111-8111-111111111111")


def make_service():
    verifier = Mock()
    accounts = Mock()
    sessions = Mock()

    verifier.verify_credentials.return_value = VerifiedIdentity(
        provider="test-idp",
        subject="voter-subject-001",
    )

    accounts.find_active_voter_id.return_value = VOTER_ID
    sessions.issue_ra_session.return_value = "test-ra-token"

    service = RAAuthenticationService(
        verifier=verifier,
        accounts=accounts,
        sessions=sessions,
    )

    return service, verifier, accounts, sessions


def test_successful_login():
    service, verifier, accounts, sessions = make_service()

    token = service.login("voter001", "example-password")

    assert token == "test-ra-token"

    verifier.verify_credentials.assert_called_once_with(
        "voter001",
        "example-password",
    )

    accounts.find_active_voter_id.assert_called_once_with(
        "test-idp",
        "voter-subject-001",
    )

    sessions.issue_ra_session.assert_called_once_with(VOTER_ID)


@pytest.mark.parametrize(
    "username,password",
    [
        ("", "password"),
        ("   ", "password"),
        ("voter001", ""),
        ("", ""),
    ],
)
def test_invalid_login_input(username, password):
    service, verifier, accounts, sessions = make_service()

    with pytest.raises(AuthenticationDenied):
        service.login(username, password)

    verifier.verify_credentials.assert_not_called()
    accounts.find_active_voter_id.assert_not_called()
    sessions.issue_ra_session.assert_not_called()


def test_invalid_credentials():
    service, verifier, accounts, sessions = make_service()

    verifier.verify_credentials.return_value = None

    with pytest.raises(AuthenticationDenied):
        service.login("voter001", "wrong-password")

    accounts.find_active_voter_id.assert_not_called()
    sessions.issue_ra_session.assert_not_called()


def test_inactive_or_unregistered_voter():
    service, verifier, accounts, sessions = make_service()

    accounts.find_active_voter_id.return_value = None

    with pytest.raises(AuthenticationDenied):
        service.login("voter001", "example-password")

    sessions.issue_ra_session.assert_not_called()


@pytest.mark.parametrize(
    "component,method",
    [
        ("verifier", "verify_credentials"),
        ("accounts", "find_active_voter_id"),
        ("sessions", "issue_ra_session"),
    ],
)
def test_dependency_failure_fails_closed(component, method):
    service, verifier, accounts, sessions = make_service()

    dependencies = {
        "verifier": verifier,
        "accounts": accounts,
        "sessions": sessions,
    }

    dependency = dependencies[component]

    getattr(dependency, method).side_effect = RuntimeError(
        "Synthetic dependency failure"
    )

    with pytest.raises(AuthenticationUnavailable):
        service.login("voter001", "example-password")

    if component != "sessions":
        sessions.issue_ra_session.assert_not_called()


def test_empty_session_token_rejected():
    service, verifier, accounts, sessions = make_service()

    sessions.issue_ra_session.return_value = ""

    with pytest.raises(AuthenticationUnavailable):
        service.login("voter001", "example-password")


@pytest.mark.parametrize(
    "provider,subject",
    [
        ("", "subject"),
        ("   ", "subject"),
        ("provider", ""),
        ("provider", "   "),
    ],
)
def test_invalid_verified_identity(provider, subject):
    with pytest.raises(ValueError):
        VerifiedIdentity(
            provider=provider,
            subject=subject,
        )