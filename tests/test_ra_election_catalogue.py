"""Opt-in catalogue contract tests. No PostgreSQL or existing configuration files."""

from dataclasses import replace
from unittest.mock import Mock
from uuid import UUID, uuid4

from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest

from backend.ra.election_catalogue import ElectionCatalogue, get_election_catalogue, router
from backend.ra.session_router import get_ra_session_service
from backend.ra.session_service import InvalidRASession
from crypto_interop.gate import ELECTION
from tests.credential_helpers import credential_material


@pytest.fixture(scope="module")
def material():
    return credential_material()


def client(catalogue, sessions=None):
    app=FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_election_catalogue]=lambda:catalogue
    app.dependency_overrides[get_ra_session_service]=lambda:sessions or Mock()
    return TestClient(app)


def test_catalogue_uses_only_existing_restricted_policy_read_and_does_not_reserve(material):
    import secrets
    policy,pin=material
    store=Mock()
    store.policy.return_value=policy
    catalogue=ElectionCatalogue(store,pin,[UUID(ELECTION)])
    response=client(catalogue).get('/api/v1/ra/elections',headers={'Authorization':'Bearer '+secrets.token_urlsafe(32)})
    assert response.status_code==200 and response.headers['cache-control']=='no-store'
    row=response.json()['elections'][0]
    assert set(row)=={'election_id','bundle','eligibility','credential_availability'}
    assert row['election_id']==ELECTION and row['eligibility']==row['credential_availability']=='checked_on_issue'
    assert row['bundle']['manifest']['election_id']==ELECTION
    store.policy.assert_called_once()
    assert store.policy.call_args.args[1]==UUID(ELECTION)
    store.reserve.assert_not_called()
    store.locked.assert_not_called()


def test_even_empty_catalogue_requires_active_session():
    import secrets
    sessions=Mock()
    sessions.resolve_voter_id.side_effect=InvalidRASession()
    catalogue=Mock()
    response=client(catalogue,sessions).get('/api/v1/ra/elections',headers={'Authorization':'Bearer '+secrets.token_urlsafe(32)})
    assert response.status_code==401
    catalogue.list.assert_not_called()


def test_no_authentication_or_malformed_token_is_rejected_before_policy_read():
    catalogue=Mock()
    for headers in ({},{'Authorization':'Bearer invalid'}):
        assert client(catalogue).get('/api/v1/ra/elections',headers=headers).status_code==401
    catalogue.list.assert_not_called()


@pytest.mark.parametrize('change',['manifest','digest','key','pin','database'])
def test_bad_policy_or_database_failure_is_sanitized(material,change):
    import secrets
    policy,pin=material
    store=Mock()
    if change=='manifest': policy=replace(policy,manifest_bytes=b'PASSWORD_CANARY')
    elif change=='digest': policy=replace(policy,config_hash=b'x'*32)
    elif change=='key': policy=replace(policy,key_id='substituted')
    elif change=='pin': pin=b'x'*32
    if change=='database': store.policy.side_effect=RuntimeError('PASSWORD_CANARY')
    else: store.policy.return_value=policy
    response=client(ElectionCatalogue(store,pin,[UUID(ELECTION)])).get('/api/v1/ra/elections',headers={'Authorization':'Bearer '+secrets.token_urlsafe(32)})
    assert response.status_code==503 and 'PASSWORD_CANARY' not in response.text


def test_catalogue_is_absent_from_default_auth_app():
    from backend.main import app
    assert TestClient(app).get('/api/v1/ra/elections').status_code==404


def test_duplicate_public_configuration_refused(material):
    _,pin=material
    with pytest.raises(ValueError): ElectionCatalogue(Mock(),pin,[uuid4()]*2)
