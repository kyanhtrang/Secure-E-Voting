import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, Mock

import pytest

from backend.ra.demo_session_service import DemoSessionService
from backend.ra.postgres_demo_auth import PostgreSQLDemoSessionStore, PostgreSQLDemoVoterAccountReader
from backend.ra.session_service import InvalidRASession, RASessionService
from tests.demo_auth_helpers import VOTER_ID


def database_result(row):
    conn = MagicMock()
    conn.__enter__.return_value = conn
    conn.execute.return_value.fetchone.return_value = row
    return Mock(return_value=conn), conn


def test_ascii_digest_is_explicit_and_legacy_default_preserved():
    token = "A" * 43
    assert DemoSessionService._digest(token) == hashlib.sha256(token.encode("ascii")).hexdigest()
    assert RASessionService._digest(token) == hashlib.sha256(bytes(32)).hexdigest()
    assert DemoSessionService._digest(token) != RASessionService._digest(token)


@pytest.mark.parametrize("token", [None, "", "abc", "A" * 42 + "B", "A" * 43 + "=", "@" * 43])
@pytest.mark.parametrize("operation", ["resolve_voter_id", "revoke_ra_session"])
def test_bad_token_never_opens_database(token, operation):
    factory = Mock()
    service = DemoSessionService(PostgreSQLDemoSessionStore(factory))
    with pytest.raises(InvalidRASession):
        getattr(service, operation)(token)
    factory.assert_not_called()


def test_demo_adapter_never_falls_back_to_general_functions():
    factory, conn = database_result(None)
    service = DemoSessionService(PostgreSQLDemoSessionStore(factory))
    with pytest.raises(InvalidRASession):
        service.resolve_voter_id(secrets.token_urlsafe(32))
    assert conn.execute.call_count == 1
    assert "ra_demo.find_active_demo_session" in conn.execute.call_args.args[0]
    assert "ra.find_active_session" not in conn.execute.call_args.args[0]


def test_identity_adapter_parameterizes_trusted_identity():
    factory, conn = database_result((VOTER_ID,))
    reader = PostgreSQLDemoVoterAccountReader(factory)
    assert reader.find_active_voter_id("demo-local", "demo-voter-001") == VOTER_ID
    sql, params = conn.execute.call_args.args
    assert "ra_demo.find_active_demo_voter_id" in sql
    assert params == ("demo-local", "demo-voter-001")
    assert "demo-voter-001" not in sql


@pytest.mark.parametrize("row", [None, (), ("bad-uuid",), (VOTER_ID, 1)])
def test_bad_identity_response_fails_closed(row):
    factory, _ = database_result(row)
    with pytest.raises(RuntimeError):
        PostgreSQLDemoVoterAccountReader(factory).find_active_voter_id("demo-local", "demo-voter-001")


def test_null_identity_response_is_denied():
    factory, _ = database_result((None,))
    assert PostgreSQLDemoVoterAccountReader(factory).find_active_voter_id("demo-local", "demo-voter-001") is None


@pytest.mark.parametrize("row", [(), (None,), (1,), ("true",), (True, "extra")])
def test_malformed_revocation_response_cannot_succeed(row):
    factory, _ = database_result(row)
    with pytest.raises(RuntimeError):
        DemoSessionService(PostgreSQLDemoSessionStore(factory)).revoke_ra_session(secrets.token_urlsafe(32))


def test_demo_cannot_save_or_issue_through_generic_service():
    factory = Mock()
    store = PostgreSQLDemoSessionStore(factory)
    with pytest.raises(RuntimeError):
        store.save_session(None)
    with pytest.raises(RuntimeError):
        DemoSessionService(store).issue_ra_session(VOTER_ID)
    factory.assert_not_called()


def test_session_adapter_checks_result_and_uses_server_revocation_time():
    now = datetime.now(timezone.utc)
    factory, conn = database_result((VOTER_ID, now, now + timedelta(minutes=15), None))
    store = PostgreSQLDemoSessionStore(factory)
    record = store.find_session("a" * 64)
    assert record.voter_id == VOTER_ID
    assert record.token_digest == "a" * 64
    conn.execute.return_value.fetchone.return_value = (False,)
    assert store.revoke_session("a" * 64, now) is False
    sql, params = conn.execute.call_args.args
    assert "ra_demo.revoke_demo_session" in sql
    assert params == ("a" * 64,)
    assert now not in params


@pytest.mark.parametrize("row", [("not-uuid", 1, 2, None), (VOTER_ID,), (VOTER_ID, None, None, None)])
def test_bad_session_response_fails_closed(row):
    factory, _ = database_result(row)
    with pytest.raises(RuntimeError):
        PostgreSQLDemoSessionStore(factory).find_session("a" * 64)
