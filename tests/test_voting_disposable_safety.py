from unittest.mock import Mock

import pytest
from pydantic import SecretStr

from scripts import voting_disposable_integration as harness


MARKER = "7a643b5c-4567-4567-8567-123456789abc"
DATABASE = "voting_demo_test_unit"


@pytest.mark.parametrize("database,marker", [
    ("ra_db", MARKER), ("voting_db", MARKER), ("voting_demo_test_", MARKER),
    ("voting_demo_test_a;drop", MARKER), ("VOTING_demo_test_a", MARKER),
    (DATABASE, ""), (DATABASE, MARKER.upper()), (DATABASE, "not-a-uuid"),
])
def test_designation_rejects_unsafe_targets_before_connect(database, marker, monkeypatch):
    connect = Mock()
    monkeypatch.setattr(harness.psycopg, "connect", connect)
    with pytest.raises(AssertionError):
        harness.factory(database, marker, 5433, SecretStr("SYNTHETIC"))
    connect.assert_not_called()


def test_independent_marker_is_required_on_every_connection(monkeypatch):
    conn = Mock()
    conn.execute.return_value.fetchone.return_value = (DATABASE, None)
    monkeypatch.setattr(harness.psycopg, "connect", Mock(return_value=conn))
    with pytest.raises(AssertionError):
        harness.factory(DATABASE, MARKER, 5433, SecretStr("SYNTHETIC"), fixture=True)()
    assert conn.execute.call_count == 1  # No SET ROLE, fixture DML, or migration before guard.
    conn.close.assert_called_once()


def test_fixture_and_runtime_connections_are_separate(monkeypatch):
    conns = []
    def connect(**kwargs):
        conn = Mock()
        role = "voting_owner" if kwargs["user"] == "voting_migrator_login" else "voting_ballot_login"
        conn.execute.return_value.fetchone.side_effect = [
            (DATABASE, "secure-evoting-disposable:"+MARKER), (DATABASE, kwargs["user"], role)]
        conns.append((kwargs, conn))
        return conn
    monkeypatch.setattr(harness.psycopg, "connect", connect)
    for fixture in (True, False):
        harness.factory(DATABASE, MARKER, 5433, SecretStr("SYNTHETIC"), fixture=fixture)()
    assert [entry[0]["user"] for entry in conns] == ["voting_migrator_login", "voting_ballot_login"]
    assert all(entry[0]["dbname"] == DATABASE and entry[0]["host"] == "127.0.0.1" for entry in conns)
    assert "SET LOCAL ROLE voting_owner" in str(conns[0][1].execute.call_args_list)
    assert "SET LOCAL ROLE" not in str(conns[1][1].execute.call_args_list)


def test_migration_runner_rejects_real_database_before_password(monkeypatch):
    from scripts import voting_disposable_migrate as runner
    monkeypatch.setattr("sys.argv", ["runner", "--allow-disposable-migrations", "--database", "ra_db",
                                    "--marker", MARKER, "--port", "5433"])
    prompt = Mock(side_effect=AssertionError("No secret collection"))
    monkeypatch.setattr(runner, "password", prompt)
    with pytest.raises(SystemExit) as caught:
        runner.main()
    assert caught.value.code == 1
    prompt.assert_not_called()
