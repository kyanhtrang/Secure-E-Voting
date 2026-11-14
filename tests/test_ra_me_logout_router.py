import secrets
from unittest.mock import Mock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.main import app as default_app
from backend.ra.session_router import get_ra_session_service, router


PREFIX = "/api/v1/ra/auth"


@pytest.mark.parametrize("method,path", [("get", "/me"), ("post", "/logout")])
def test_default_session_endpoints_disabled(method, path):
    response = getattr(TestClient(default_app), method)(PREFIX + path)
    assert response.status_code == 503
    assert response.headers["cache-control"] == "no-store"


@pytest.mark.parametrize("header", [
    None, "", "Basic SECRET", "Bearer abc", "Bearer " + "A" * 42 + "B",
    "Bearer " + "A" * 43 + "=", "Bearer  " + "A" * 43,
    "Bearer " + "A" * 43 + " extra", "Bearer " + "@" * 43,
])
@pytest.mark.parametrize("method,path", [("get", "/me"), ("post", "/logout")])
def test_invalid_bearer_rejected_before_service(header, method, path):
    service = Mock()
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_ra_session_service] = lambda: service
    headers = {} if header is None else {"Authorization": header}
    response = getattr(TestClient(app), method)(PREFIX + path, headers=headers)
    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid authentication credentials"}
    assert response.headers["www-authenticate"] == "Bearer"
    assert response.headers["cache-control"] == "no-store"
    service.resolve_voter_id.assert_not_called()
    service.revoke_ra_session.assert_not_called()


def test_duplicate_bearer_headers_and_query_tokens_rejected():
    service = Mock()
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_ra_session_service] = lambda: service
    client = TestClient(app)
    token = secrets.token_urlsafe(32)
    response = client.get(PREFIX + "/me", headers=[
        ("Authorization", "Bearer " + token), ("Authorization", "Bearer " + token)
    ])
    assert response.status_code == 401
    assert token not in response.text
    assert client.get(PREFIX + "/me", params={"access_token": token}).status_code == 401
    service.resolve_voter_id.assert_not_called()
