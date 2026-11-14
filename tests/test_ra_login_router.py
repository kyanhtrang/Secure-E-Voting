import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.ra.auth_service import (
    AuthenticationDenied,
    AuthenticationUnavailable,
)
from backend.ra.login_router import (
    router,
    get_ra_auth_service,
)


URL = "/api/v1/ra/auth/login"
USERNAME = "demo-user"
PASSWORD = "synthetic-password"


class FakeAuthService:
    def __init__(self, token="synthetic-token", error=None):
        self.token = token
        self.error = error
        self.calls = []

    def login(self, username, password):
        self.calls.append((username, password))
        if self.error is not None:
            raise self.error
        return self.token


def make_client(service=None):
    app = FastAPI()
    app.include_router(router)

    if service is not None:
        app.dependency_overrides[get_ra_auth_service] = (
            lambda: service
        )

    return TestClient(app)


def valid_payload():
    return {
        "username": USERNAME,
        "password": PASSWORD,
    }


def test_default_login_disabled():
    response = make_client().post(
        URL, json=valid_payload()
    )

    assert response.status_code == 503
    assert "access_token" not in response.json()
    assert response.headers["cache-control"] == "no-store"


def test_successful_login():
    service = FakeAuthService()
    response = make_client(service).post(
        URL, json=valid_payload()
    )

    assert response.status_code == 200
    assert response.json() == {
        "access_token": "synthetic-token",
        "token_type": "Bearer",
    }
    assert response.headers["cache-control"] == "no-store"
    assert service.calls == [(USERNAME, PASSWORD)]
    assert PASSWORD not in response.text


def test_invalid_credentials():
    service = FakeAuthService(
        error=AuthenticationDenied()
    )
    response = make_client(service).post(
        URL, json=valid_payload()
    )

    assert response.status_code == 401
    assert "access_token" not in response.json()
    assert PASSWORD not in response.text
    assert response.headers["cache-control"] == "no-store"


def test_authentication_unavailable():
    service = FakeAuthService(
        error=AuthenticationUnavailable()
    )
    response = make_client(service).post(
        URL, json=valid_payload()
    )

    assert response.status_code == 503
    assert "access_token" not in response.json()


def test_unexpected_exception_is_hidden():
    service = FakeAuthService(
        error=RuntimeError("sensitive-internal-error")
    )
    response = make_client(service).post(
        URL, json=valid_payload()
    )

    assert response.status_code == 503
    assert "sensitive-internal-error" not in response.text
    assert PASSWORD not in response.text


@pytest.mark.parametrize("token", ["", None, 123])
def test_invalid_issued_token_rejected(token):
    service = FakeAuthService(token=token)
    response = make_client(service).post(
        URL, json=valid_payload()
    )

    assert response.status_code == 503
    assert "access_token" not in response.json()


@pytest.mark.parametrize(
    "payload",
    [
        {"username": "", "password": PASSWORD},
        {"username": USERNAME},
        {
            **valid_payload(),
            "voter_id": "00000000-0000-0000-0000-000000000001",
        },
        {
            **valid_payload(),
            "auth_provider": "attacker",
        },
        {
            **valid_payload(),
            "auth_subject": "attacker",
        },
    ],
)
def test_invalid_request_rejected(payload):
    service = FakeAuthService()
    response = make_client(service).post(
        URL, json=payload
    )

    assert response.status_code == 422
    assert service.calls == []
    assert "access_token" not in response.json()


def test_validation_error_must_not_leak_password():
    service = FakeAuthService()

    canary = "TEST_SECRET_CANARY_" + "x" * 1100
    response = make_client(service).post(
        URL,
        json={
            "username": USERNAME,
            "password": canary,
        },
    )

    assert response.status_code == 422
    assert service.calls == []
    assert canary not in response.text, (
        "SECURITY ISSUE: Password leaked in validation response"
    )


def test_validation_error_should_not_be_cached():
    service = FakeAuthService()

    response = make_client(service).post(
        URL,
        json={
            "username": "",
            "password": PASSWORD,
        },
    )

    assert response.status_code == 422
    assert response.headers.get(
        "cache-control"
    ) == "no-store", (
        "SECURITY ISSUE: Validation response lacks no-store"
    )