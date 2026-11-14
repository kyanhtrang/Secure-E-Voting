import hashlib
import json
from unittest.mock import Mock

import pytest
from fastapi.testclient import TestClient

from backend.crypto.credential_protocol import b64encode
from backend.ra.credential_runtime import create_credential_app
from backend.ra.credential_service import CredentialConflict, CredentialDenied, CredentialExpired
from backend.ra.demo_session_service import DemoSessionService
from backend.ra.session_service import InvalidRASession
from tests.credential_helpers import credential_environment, credential_material
from tests.demo_auth_helpers import DemoDatabaseDouble, PASSWORD, demo_environment


ISSUE = "/api/v1/ra/credentials/issue"
AUTH = "/api/v1/ra/auth"


@pytest.fixture(scope="module")
def material():
    return credential_material()


@pytest.fixture
def demo(material):
    env = credential_environment(material)
    database = DemoDatabaseDouble()
    app = create_credential_app(demo_environment(), env.service, auth_connection_factory=database.factory)
    with TestClient(app, base_url="http://127.0.0.1:8000", client=("127.0.0.1", 50000)) as client:
        yield client, database, env


def payload(env):
    return {"election_id": str(env.store.election), "request_id": str(env.request),
            "blinded_msg": b64encode(env.blinded)}


def headers(env):
    return {"Authorization": "Bearer " + env.token}


def test_login_issue_retry_me_logout(demo, caplog):
    client, database, env = demo
    response = client.post(AUTH+"/login", json={"username": "demo-voter", "password": PASSWORD})
    assert response.status_code == 200
    env.token = response.json()["access_token"]
    env.store.session_digest = DemoSessionService._digest(env.token)
    env.store.voter = next(iter(database.records.values())).voter_id

    original_session = env.store._session
    def session(digest):
        record = database.records.get(digest)
        if record is None or record.revoked_at is not None:
            raise InvalidRASession()
        original_session(digest)
    env.store._session = session
    first = client.post(ISSUE, json=payload(env), headers=headers(env))
    assert first.status_code == 201
    assert first.json() == {"status": "issued", "ra_key_id": env.store.public_policy.key_id,
        "profile": "RSABSSA-SHA384-PSS-Randomized", "blind_sig": b64encode(env.signature)}
    again = client.post(ISSUE, json=payload(env), headers=headers(env))
    assert again.status_code == 200 and again.json()["blind_sig"] == first.json()["blind_sig"]
    env.signer.sign.assert_called_once_with(env.blinded)
    assert client.get(AUTH+"/me", headers=headers(env)).status_code == 200
    assert client.post(AUTH+"/logout", headers=headers(env)).status_code == 204
    assert client.post(ISSUE, json=payload(env), headers=headers(env)).status_code == 401
    assert env.store.session_digest == hashlib.sha256(env.token.encode("ascii")).hexdigest()
    assert env.token not in caplog.text and PASSWORD not in caplog.text
    for response in (first, again):
        assert response.headers["cache-control"] == "no-store"
        assert "voter_id" not in response.text and "request_id" not in response.text


@pytest.mark.parametrize("error,status", [(InvalidRASession,401),(CredentialDenied,403),
    (CredentialConflict,409),(CredentialExpired,410),(RuntimeError,503)])
def test_errors_are_generic_no_store_and_do_not_leak(demo, error, status, caplog):
    client, _, env = demo
    secret = "synthetic-sensitive-error-canary"
    env.service.store.policy = Mock(side_effect=error(secret))
    response = client.post(ISSUE, json=payload(env), headers=headers(env))
    assert response.status_code == status
    assert response.headers["cache-control"] == "no-store"
    assert secret not in response.text+caplog.text
    assert env.token not in response.text+caplog.text


@pytest.mark.parametrize("change", [{"voter_id":"secret-identity-canary"}, {"serial":"serial-canary"},
    {"envelope":"ballot-canary"}, {"blinded_msg":"malformed-secret-canary"},
    {"election_id":"NOT-A-UUID-secret"}, {"request_id":None}])
def test_request_rejects_identity_and_noncanonical_fields_before_database(demo, change):
    client, _, env = demo
    env.store.policy = Mock(side_effect=AssertionError("database must not be called"))
    response = client.post(ISSUE, json=payload(env)|change, headers=headers(env))
    assert response.status_code == 422
    assert response.json() == {"detail":"Invalid credential request"}
    assert response.headers["cache-control"] == "no-store"
    env.store.policy.assert_not_called()


def test_duplicate_fields_and_oversized_body_rejected(demo):
    client, _, env = demo
    body = json.dumps(payload(env))[:-1]+',"request_id":"secret-canary"}'
    assert client.post(ISSUE, content=body, headers=headers(env)).status_code == 422
    assert client.post(ISSUE, content=b"x"*4097, headers=headers(env)).status_code == 413
    assert not env.store.records


@pytest.mark.parametrize("authorization", [None,"Bearer malformed", "Basic secret-canary"])
def test_invalid_bearer_rejected_before_database(demo, authorization):
    client, _, env = demo
    env.store.policy = Mock()
    response = client.post(ISSUE, json=payload(env),
                           headers={} if authorization is None else {"Authorization":authorization})
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"
    env.store.policy.assert_not_called()


def test_commit_failure_is_503_and_exact_retry_recovers(demo):
    client, _, env = demo
    env.store.fail_after_commit = True
    assert client.post(ISSUE,json=payload(env),headers=headers(env)).status_code == 503
    env.store.fail_after_commit = False
    response = client.post(ISSUE,json=payload(env),headers=headers(env))
    assert response.status_code == 200
    assert response.json()["blind_sig"] == b64encode(env.signature)


def test_default_app_has_no_issuance_route_and_local_app_rejects_remote(demo):
    from backend.main import app
    with TestClient(app) as client:
        assert client.post(ISSUE,json={}).status_code == 404
        assert client.post(AUTH+"/login", json={"username":"x","password":"x"}).status_code == 503
    client, _, env = demo
    assert client.post(ISSUE,json=payload(env),headers=headers(env)|{"Origin":"https://remote.invalid"}).status_code == 403
    response = client.get(ISSUE)
    assert response.status_code == 405 and response.headers["cache-control"] == "no-store"
