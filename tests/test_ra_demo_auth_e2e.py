import hashlib
import secrets
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from tests.demo_auth_helpers import (
    DemoDatabaseDouble, PASSWORD, VOTER_ID, demo_client, demo_environment,
)


PREFIX = "/api/v1/ra/auth"


@pytest.fixture
def environment():
    return demo_environment()


@pytest.fixture
def demo(environment):
    database = DemoDatabaseDouble()
    with demo_client(database, environment) as client:
        yield client, database


def login(client, password=PASSWORD):
    return client.post(
        PREFIX + "/login", json={"username": "demo-voter", "password": password}
    )


def test_http_lifecycle_uses_one_ascii_digest(demo, caplog):
    caplog.set_level("DEBUG")
    client, database = demo
    response = login(client)
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    token = response.json()["access_token"]
    assert response.json()["token_type"] == "Bearer"
    digest = hashlib.sha256(token.encode("ascii")).hexdigest()
    assert list(database.records) == [digest]
    headers = {"Authorization": "Bearer " + token}
    response = client.get(PREFIX + "/me", headers=headers)
    assert response.json() == {"voter_id": str(VOTER_ID)}
    assert response.headers["cache-control"] == "no-store"
    response = client.post(PREFIX + "/logout", headers=headers)
    assert response.status_code == 204
    assert response.content == b""
    assert response.headers["cache-control"] == "no-store"
    assert client.get(PREFIX + "/me", headers=headers).status_code == 401
    assert client.post(PREFIX + "/logout", headers=headers).status_code == 204
    # Identity lookup aside, every SQL operation uses precisely the issuer digest.
    for sql, params in database.queries:
        if "find_active_demo_voter_id" not in sql:
            assert params[0] == digest
        assert token not in str(params)
        assert PASSWORD not in str(params)
    assert token not in caplog.text
    assert PASSWORD not in caplog.text


def test_wrong_password_never_accesses_database(demo):
    client, database = demo
    response = login(client, "synthetic-wrong-password")
    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid credentials"}
    database.factory.assert_not_called()


@pytest.mark.parametrize("active", [False, True])
def test_expired_or_inactive_session_is_denied(demo, active):
    client, database = demo
    token = login(client).json()["access_token"]
    digest = hashlib.sha256(token.encode("ascii")).hexdigest()
    database.active = active
    if active:
        database.records[digest] = replace(
            database.records[digest],
            expires_at=datetime.now(timezone.utc) - timedelta(seconds=1),
        )
    response = client.get(PREFIX + "/me", headers={"Authorization": "Bearer " + token})
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"


def test_logout_does_not_revoke_another_session(demo):
    client, _ = demo
    first = login(client).json()["access_token"]
    second = login(client).json()["access_token"]
    client.post(PREFIX + "/logout", headers={"Authorization": "Bearer " + first})
    assert client.get(
        PREFIX + "/me", headers={"Authorization": "Bearer " + second}
    ).status_code == 200


@pytest.mark.parametrize("path,method", [("/me", "get"), ("/logout", "post"), ("/login", "post")])
def test_database_errors_are_sanitized(demo, caplog, path, method):
    client, database = demo
    token = login(client).json()["access_token"]
    canary = "DB_SECRET_CANARY_" + token + PASSWORD
    database.error = RuntimeError(canary)
    kwargs = {"headers": {"Authorization": "Bearer " + token}}
    if path == "/login":
        kwargs["json"] = {"username": "demo-voter", "password": PASSWORD}
    response = getattr(client, method)(PREFIX + path, **kwargs)
    assert response.status_code == 503
    assert response.json() == {"detail": "Authentication unavailable"}
    assert canary not in response.text + caplog.text
    assert token not in response.text + caplog.text
    assert PASSWORD not in response.text + caplog.text
    assert response.headers["cache-control"] == "no-store"


@pytest.mark.parametrize("path", ["/login", "/logout"])
def test_commit_failure_never_reports_success(demo, path):
    client, database = demo
    token = login(client).json()["access_token"]
    database.commit_error = RuntimeError("SYNTHETIC_COMMIT_SECRET")
    response = client.post(
        PREFIX + path,
        headers={"Authorization": "Bearer " + token},
        json={"username": "demo-voter", "password": PASSWORD},
    )
    assert response.status_code == 503
    assert "SYNTHETIC_COMMIT_SECRET" not in response.text
    assert "access_token" not in response.json()


@pytest.mark.parametrize("payload", [
    {"username": "demo-voter", "password": "INPUT_SECRET_" + "x" * 1100},
    {"username": "demo-voter", "password": PASSWORD, "voter_id": str(VOTER_ID)},
    {"username": "demo-voter"},
])
def test_login_validation_is_sanitized(demo, caplog, payload):
    client, database = demo
    response = client.post(PREFIX + "/login", json=payload)
    assert response.status_code == 422
    assert response.json() == {"detail": "Invalid login request"}
    assert PASSWORD not in response.text + caplog.text
    assert "INPUT_SECRET_" not in response.text + caplog.text
    database.factory.assert_not_called()


def test_unknown_canonical_token_is_not_an_enumeration_oracle(demo):
    client, _ = demo
    headers = {"Authorization": "Bearer " + secrets.token_urlsafe(32)}
    assert client.get(PREFIX + "/me", headers=headers).status_code == 401
    assert client.post(PREFIX + "/logout", headers=headers).status_code == 204


def test_malformed_json_login_does_not_echo_input(demo, caplog):
    client, database = demo
    caplog.set_level("DEBUG")
    canary = "MALFORMED_JSON_SECRET"
    response = client.post(
        PREFIX + "/login", content='{"password":"' + canary,
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 422
    assert response.json() == {"detail": "Invalid login request"}
    assert canary not in response.text + caplog.text
    assert response.headers["cache-control"] == "no-store"
    database.factory.assert_not_called()


def test_failed_login_limit_is_shared_across_usernames(demo):
    client, database = demo
    for index in range(5):
        response = client.post(PREFIX + "/login", json={
            "username": f"synthetic-user-{index}", "password": "wrong"
        })
        assert response.status_code == 401
    response = login(client)
    assert response.status_code == 429
    assert 1 <= int(response.headers["retry-after"]) <= 60
    assert response.headers["cache-control"] == "no-store"
    database.factory.assert_not_called()


@pytest.mark.parametrize("method,path", [
    ("get", "/login"), ("post", "/me"), ("get", "/missing"),
    ("get", "/me"), ("post", "/logout"),
])
def test_all_auth_responses_prevent_caching(demo, method, path):
    client, _ = demo
    response = getattr(client, method)(PREFIX + path)
    assert response.headers["cache-control"] == "no-store"
