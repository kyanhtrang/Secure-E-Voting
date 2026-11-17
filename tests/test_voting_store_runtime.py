from contextlib import contextmanager
from unittest.mock import Mock

import pytest
from pydantic import SecretStr

from backend.voting.ballot_service import AlreadySpent, BallotService, VotingUnavailable
from backend.voting.postgres_ballot_store import PostgreSQLBallotStore
from tests.voting_helpers import MemoryBallotStore, material, payload_for


@pytest.fixture(scope="module")
def verified():
    value = material()
    return BallotService(MemoryBallotStore(value), value.pin).verify(payload_for(value))


def test_store_returns_only_after_commit_and_uses_parameters(verified):
    events = []
    conn = Mock()
    conn.execute.return_value.fetchone.return_value = (verified.receipt_hash,)

    @contextmanager
    def connect():
        events.append("begin")
        yield conn
        events.append("commit")

    result = PostgreSQLBallotStore(connect).accept(verified)
    assert events == ["begin", "commit"] and result == verified.receipt_hash
    query, params = conn.execute.call_args.args
    assert "voting.accept_anonymous_ballot(" in query and query.count("%s") == 6
    assert params == (verified.election_id, verified.config_digest, verified.serial,
                      verified.envelope, verified.prepared_msg, verified.signature)
    assert verified.serial.hex() not in query


def test_commit_failure_cannot_report_success(verified):
    conn = Mock()
    conn.execute.return_value.fetchone.return_value = (verified.receipt_hash,)

    @contextmanager
    def connect():
        yield conn
        raise RuntimeError("SECRET_CANARY commit failed")

    with pytest.raises(VotingUnavailable) as caught:
        PostgreSQLBallotStore(connect).accept(verified)
    assert "SECRET_CANARY" not in str(caught.value)


@pytest.mark.parametrize("row", [None, (), (None,), (b"short",), (b"x"*32, b"extra")])
def test_malformed_database_result_fails_closed(verified, row):
    conn = Mock()
    conn.execute.return_value.fetchone.return_value = row

    @contextmanager
    def connect():
        yield conn

    with pytest.raises(VotingUnavailable):
        PostgreSQLBallotStore(connect).accept(verified)


def test_sqlstate_maps_without_database_detail(verified):
    class DatabaseError(Exception):
        sqlstate = "P4202"
    conn = Mock()
    conn.execute.side_effect = DatabaseError("SECRET_CANARY")

    @contextmanager
    def connect():
        yield conn

    with pytest.raises(AlreadySpent) as caught:
        PostgreSQLBallotStore(connect).accept(verified)
    assert not str(caught.value)


def test_launcher_is_opt_in_and_has_no_credential_discovery(monkeypatch):
    from backend.voting import local_launcher as launcher
    monkeypatch.setattr("sys.argv", ["launcher"])
    monkeypatch.setattr(launcher.psycopg, "connect", Mock(side_effect=AssertionError("No DB")))
    with pytest.raises(SystemExit) as caught:
        launcher.main()
    assert caught.value.code == 2
    launcher.psycopg.connect.assert_not_called()


def test_launcher_uses_only_fixed_unprivileged_voting_login(monkeypatch):
    from backend.voting import local_launcher as launcher
    conn = Mock()
    conn.execute.return_value.fetchone.return_value = (
        "voting_db", "voting_ballot_login", "voting_ballot_login", False, False, False, False, False, False)
    connect = Mock(return_value=conn)
    monkeypatch.setattr(launcher.psycopg, "connect", connect)
    assert launcher.connection_factory(SecretStr("SYNTHETIC_TEST_PASSWORD"))() is conn
    assert connect.call_args.kwargs["user"] == "voting_ballot_login"
    assert connect.call_args.kwargs["dbname"] == "voting_db"
    assert connect.call_args.kwargs["host"] == "127.0.0.1"
    conn.commit.assert_called_once()


def test_privileged_identity_refused_and_connection_closed(monkeypatch):
    from backend.voting import local_launcher as launcher
    conn = Mock()
    conn.execute.return_value.fetchone.return_value = ("voting_db", "voting_owner", "voting_owner")
    monkeypatch.setattr(launcher.psycopg, "connect", Mock(return_value=conn))
    with pytest.raises(VotingUnavailable):
        launcher.connection_factory(SecretStr("SYNTHETIC_TEST_PASSWORD"))()
    conn.close.assert_called_once()


def test_launcher_bind_and_logging_options(monkeypatch, tmp_path):
    from backend.voting import local_launcher as launcher
    public = tmp_path / "public-pin.bin"
    public.write_bytes(b"p"*32)  # Public-only synthetic fixture, never a private key.
    monkeypatch.setattr("sys.argv", ["launcher", "--enable-local-voting", "--manifest-authority-pin", str(public)])
    monkeypatch.setattr(launcher.getpass, "getpass", lambda _: "SYNTHETIC_TEST_PASSWORD")
    run = Mock()
    monkeypatch.setattr(launcher.uvicorn, "run", run)
    monkeypatch.setattr(launcher.psycopg, "connect", Mock(side_effect=AssertionError("No DB")))
    launcher.main()
    kwargs = run.call_args.kwargs
    assert kwargs["host"] == "127.0.0.1" and kwargs["port"] == 8001
    assert kwargs["proxy_headers"] is False and kwargs["access_log"] is False
    assert kwargs["forwarded_allow_ips"] == "" and kwargs["workers"] == 1
    launcher.psycopg.connect.assert_not_called()
