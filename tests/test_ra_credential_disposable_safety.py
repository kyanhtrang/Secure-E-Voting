from unittest.mock import Mock
from datetime import datetime,timezone,timedelta
import secrets
from uuid import uuid4

import pytest
from pydantic import SecretStr

from scripts import ra_credential_disposable_integration as integration


@pytest.mark.parametrize("database,marker",[("ra_db",str(uuid4())),("voting_db",str(uuid4())),
    ("ra_demo_test_gate2","not-a-marker"),("ra_demo_test_gate2",str(uuid4()).upper())])
def test_disposable_factory_refuses_unsafe_targets_before_connecting(monkeypatch,database,marker):
    connect=Mock(side_effect=AssertionError("No database access allowed"))
    monkeypatch.setattr(integration.psycopg,"connect",connect)
    with pytest.raises(AssertionError):
        integration.issuance_factory(SecretStr("synthetic"),database=database,marker=marker,port=5432)
    connect.assert_not_called()


def test_disposable_factory_checks_identity_and_independent_marker_every_connection(monkeypatch):
    marker=str(uuid4()); database="ra_demo_test_gate2"
    connect=Mock()
    conn=connect.return_value
    conn.execute.return_value.fetchone.side_effect=[
        (database,"ra_issuance_login","ra_issuance_login"),
        (database,"secure-evoting-disposable:"+marker),
        (database,"ra_issuance_login","ra_issuance_login"),
        (database,"wrong-marker")]
    monkeypatch.setattr(integration.psycopg,"connect",connect)
    factory=integration.issuance_factory(SecretStr("synthetic"),database=database,marker=marker,port=5432)
    assert factory() is conn
    with pytest.raises(AssertionError):
        factory()
    conn.close.assert_called_once()
    assert connect.call_args.kwargs["user"]=="ra_issuance_login"


def test_fixture_cleanup_is_scoped_to_invocation_generated_identifiers():
    voters=[uuid4(),uuid4()]; election=uuid4()
    conn=Mock()
    integration.cleanup(conn,voters,election)
    for call in conn.execute.call_args_list:
        sql,params=call.args
        assert " WHERE " in sql
        assert params in ((voters,),(election,))
        assert "demo-voter-001" not in sql
        assert "TRUNCATE" not in sql


def test_manual_cli_requires_opt_in_before_prompt_or_connection(monkeypatch):
    prompt=Mock(side_effect=AssertionError("must not read secrets"))
    monkeypatch.setattr(integration,"prompt_password",prompt)
    monkeypatch.setattr("sys.argv",["integration"])
    with pytest.raises(SystemExit):
        integration.main()
    prompt.assert_not_called()


def test_fixture_uses_trusted_eligibility_function_and_checks_generated_identifier():
    conn=Mock()
    voter,election,actor,eligibility=uuid4(),uuid4(),uuid4(),uuid4()
    now=datetime.now(timezone.utc)
    token=secrets.token_urlsafe(32)
    conn.execute.return_value.fetchone.side_effect=[(True,),(eligibility,True)]
    integration.seed_voter(conn,voter,election,token,now,actor)
    calls=conn.execute.call_args_list
    assert "is_active) VALUES(%s,%s,%s,true)" in calls[0].args[0]
    assert calls[1].args==("SELECT ra.set_voter_eligibility(%s,%s,true,%s)",(voter,election,actor))
    assert "SELECT eligibility_id,is_eligible" in calls[2].args[0]
    assert calls[3].args==("SELECT ra.create_session(%s,%s,%s,%s)",
        (integration.DemoSessionService._digest(token),voter,now,now+timedelta(minutes=15)))
    assert all("INSERT INTO ra.voter_eligibility" not in call.args[0] for call in calls)
    assert all(token not in str(call) for call in calls)


@pytest.mark.parametrize("rows",[[(False,)],[(True,),None],[(True,),(None,True)],[(True,),(uuid4(),False)]])
def test_fixture_fails_closed_without_successful_trusted_eligibility(rows):
    conn=Mock()
    conn.execute.return_value.fetchone.side_effect=rows
    with pytest.raises(AssertionError):
        integration.seed_voter(conn,uuid4(),uuid4(),secrets.token_urlsafe(32),datetime.now(timezone.utc),uuid4())
    assert all("ra.create_session" not in call.args[0] for call in conn.execute.call_args_list)
