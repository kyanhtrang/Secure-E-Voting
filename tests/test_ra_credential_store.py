from dataclasses import astuple
from unittest.mock import MagicMock

import pytest
from pydantic import SecretStr

from backend.ra.credential_runtime import credential_connection_factory
from backend.ra.credential_service import CredentialConflict, CredentialDenied, CredentialExpired, CredentialUnavailable
from backend.ra.postgres_credential_store import PostgreSQLCredentialStore, sanitized_database_errors
from backend.ra.session_service import InvalidRASession
from tests.credential_helpers import credential_environment, credential_material


@pytest.fixture(scope="module")
def env():
    return credential_environment(credential_material())


@pytest.mark.parametrize("sqlstate,error",[("P4101",InvalidRASession),("P4102",CredentialDenied),
    ("P4103",CredentialConflict),("P4104",CredentialExpired),("42501",CredentialUnavailable),
    ("P4105",CredentialUnavailable),(None,CredentialUnavailable)])
def test_database_error_translation_hides_details(sqlstate,error):
    original = RuntimeError("synthetic database credential canary")
    original.sqlstate = sqlstate
    with pytest.raises(error) as caught:
        with sanitized_database_errors():
            raise original
    assert str(caught.value) == ""
    assert caught.value.__suppress_context__


def test_store_reservation_and_locked_completion_have_separate_commit_boundaries(env):
    params = (env.store.session_digest,env.store.election,env.request,b"h"*32,env.store.public_policy.config_hash)
    context = env.store.reserve(*params)
    first, second = MagicMock(), MagicMock()
    first.__enter__.return_value=first
    second.__enter__.return_value=second
    first.execute.return_value.fetchone.return_value=astuple(context)
    second.execute.return_value.fetchone.return_value=astuple(context)
    connections = iter([first,second])
    store = PostgreSQLCredentialStore(lambda:next(connections))
    assert store.reserve(*params)==context
    first.__exit__.assert_called_once_with(None,None,None)
    with store.locked(*params) as transaction:
        second.__exit__.assert_not_called()
        assert transaction.context==context
        transaction.complete(b"cipher",b"nonce","key")
    second.__exit__.assert_called_once_with(None,None,None)
    for call in [*first.execute.call_args_list,*second.execute.call_args_list]:
        sql, values = call.args
        assert sql.startswith("SELECT * FROM ra_credential.")
        assert env.store.session_digest not in sql
        assert values[:5]==params


def test_commit_failure_never_returns_reservation(env):
    conn=MagicMock()
    conn.__enter__.return_value=conn
    params=(env.store.session_digest,env.store.election,env.request,b"h"*32,env.store.public_policy.config_hash)
    conn.execute.return_value.fetchone.return_value=astuple(env.store.reserve(*params))
    conn.__exit__.side_effect=RuntimeError("commit credential canary")
    with pytest.raises(CredentialUnavailable):
        PostgreSQLCredentialStore(lambda:conn).reserve(*params)


def test_runtime_factory_uses_only_fixed_restricted_role(monkeypatch):
    connect=MagicMock()
    conn=connect.return_value
    conn.execute.return_value.fetchone.return_value=("ra_db","ra_issuance_login","ra_issuance_login")
    monkeypatch.setattr("backend.ra.credential_runtime.psycopg.connect",connect)
    factory=credential_connection_factory(SecretStr("synthetic-test-password"))
    connect.assert_not_called()
    assert factory() is conn
    assert connect.call_args.kwargs["user"]=="ra_issuance_login"
    assert connect.call_args.kwargs["host"]=="127.0.0.1"
    assert "password" not in connect.call_args.kwargs["options"]
    conn.execute.return_value.fetchone.return_value=("ra_db","ra_owner","ra_owner")
    with pytest.raises(CredentialUnavailable):
        factory()
    conn.close.assert_called_once()
