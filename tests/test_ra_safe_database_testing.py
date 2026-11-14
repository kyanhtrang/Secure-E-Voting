import secrets
import sys
import getpass
import warnings
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, Mock, patch
from uuid import uuid4

import pytest
from pydantic import SecretStr

from backend.ra.session_service import RASessionRecord
from scripts import test_ra_demo_auth_e2e_integration as disposable
from scripts import test_ra_demo_existing_smoke as smoke
from scripts.ra_demo_db_test_support import (
    database_factory, digest, prompt_password, seed_disposable_voters,
    validate_disposable_designation, verify_disposable_database,
)
from tests.demo_auth_helpers import DemoDatabaseDouble, PASSWORD, VOTER_ID, demo_environment


DATABASE = "ra_demo_test_security"
MARKER = "f83b1972-4d1c-4e4b-82ca-f67c317f88b8"


class ExistingDemoDouble(DemoDatabaseDouble):
    def __init__(self):
        super().__init__()
        self.fixture_queries = []
        self.fixture_factory = Mock(side_effect=self.fixture_connect)
        now = datetime.now(timezone.utc)
        self.voter = (VOTER_ID, "demo-local", "demo-voter-001", True, now, now)

    def fixture_connect(self):
        conn = MagicMock()
        conn.__enter__.return_value = conn
        conn.execute.side_effect = self.fixture_execute
        return conn

    def fixture_execute(self, sql, params=None):
        self.fixture_queries.append((sql, params))
        row = None
        if "version_num" in sql:
            row = ("f3c2a1d4e6b8",)
        elif "FROM ra.voters" in sql:
            row = self.voter
        elif sql.startswith("DELETE FROM ra.ra_sessions"):
            assert sql == "DELETE FROM ra.ra_sessions WHERE token_digest=%s AND voter_id=%s"
            record = self.records.get(params[0])
            if record and record.voter_id == params[1]:
                del self.records[params[0]]
        elif "FROM ra.ra_sessions" in sql:
            record = self.records.get(params[0])
            if record:
                if "expires_at-created_at" in sql:
                    row = (record.voter_id, record.expires_at-record.created_at, record.revoked_at)
                elif "revoked_at IS NOT NULL" in sql:
                    row = (record.revoked_at is not None,)
                else:
                    row = (1,)
        else:
            raise AssertionError("Unexpected fixture SQL")
        result = Mock()
        result.fetchone.return_value = row
        return result


@pytest.mark.parametrize("commit_failure", [False, True])
def test_existing_smoke_preserves_voter_and_unrelated_sessions(commit_failure, capsys, caplog):
    database = ExistingDemoDouble()
    token = secrets.token_urlsafe(32)
    other_token = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    # Unrelated sessions for both the same voter and another voter must survive.
    for item, voter in ((token, VOTER_ID), (other_token, uuid4())):
        key = digest(item)
        database.records[key] = RASessionRecord(key, voter, now, now+timedelta(minutes=15))
    before = dict(database.records)
    voter_before = database.voter
    if commit_failure:
        database.commit_error = RuntimeError("SYNTHETIC_LOST_COMMIT_RESPONSE")
        with pytest.raises(AssertionError, match="Existing-demo login failed"):
            smoke.run_smoke(database.fixture_factory, database.factory, demo_environment(), PASSWORD)
    else:
        smoke.run_smoke(database.fixture_factory, database.factory, demo_environment(), PASSWORD)
    assert database.voter == voter_before
    assert database.records == before
    writes = [(sql, params) for sql, params in database.fixture_queries if sql.startswith("DELETE")]
    assert len(writes) == 1
    assert writes[0][1][1] == VOTER_ID
    assert writes[0][1][0] not in before
    assert not any("UPDATE ra.voters" in sql or "INSERT INTO ra.voters" in sql
                   or "DELETE FROM ra.voters" in sql for sql, _ in database.fixture_queries)
    captured = capsys.readouterr()
    assert PASSWORD not in captured.out + captured.err + caplog.text
    assert token not in captured.out + captured.err + caplog.text


def test_existing_smoke_refuses_digest_collision_without_cleanup():
    database = ExistingDemoDouble()
    token = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    key = digest(token)
    database.records[key] = RASessionRecord(key, VOTER_ID, now, now+timedelta(minutes=15))
    before = dict(database.records)
    with patch("scripts.test_ra_demo_existing_smoke.secrets.token_urlsafe", return_value=token):
        with pytest.raises(AssertionError, match="Reserved session digest already exists"):
            smoke.run_smoke(database.fixture_factory, database.factory, demo_environment(), PASSWORD)
    assert database.records == before
    database.factory.assert_not_called()
    assert not any(sql.startswith("DELETE") for sql, _ in database.fixture_queries)


@pytest.mark.parametrize("voter", [None, (VOTER_ID, "demo-local", "demo-voter-001", False, None, None)])
def test_smoke_never_creates_or_activates_voter(voter):
    database = ExistingDemoDouble()
    database.voter = voter
    with pytest.raises(AssertionError, match="existing active demo voter is required"):
        smoke.run_smoke(database.fixture_factory, database.factory, demo_environment(), PASSWORD)
    database.factory.assert_not_called()
    assert all(sql.lstrip().startswith("SELECT") for sql, _ in database.fixture_queries)


@pytest.mark.parametrize("database,marker", [
    ("ra_db", MARKER), ("voting_db", MARKER), ("postgres", MARKER),
    ("ra_demo_test_security", "not-a-uuid"), ("ra_demo_test_security", MARKER.upper()),
    ("ra_demo_test_security; DROP DATABASE ra_db", MARKER),
])
def test_disposable_designation_cannot_select_existing_database(database, marker):
    with pytest.raises(AssertionError):
        validate_disposable_designation(database, marker)


@pytest.mark.parametrize("row", [None, (DATABASE, None), ("ra_db", "secure-evoting-disposable:"+MARKER),
                                    (DATABASE, "secure-evoting-disposable:"+str(uuid4()))])
def test_disposable_database_requires_independent_matching_marker(row):
    conn = Mock()
    conn.execute.return_value.fetchone.return_value = row
    with pytest.raises(AssertionError, match="not independently marked disposable"):
        verify_disposable_database(conn, DATABASE, MARKER)
    assert conn.execute.call_count == 1
    assert conn.execute.call_args.args[0].lstrip().startswith("SELECT")


@pytest.mark.parametrize("existing", [None, (1,)])
def test_disposable_seed_requires_empty_identity_and_explicit_active_voters(existing):
    conn = Mock()
    conn.execute.return_value.fetchone.side_effect = [
        (DATABASE, "secure-evoting-disposable:"+MARKER), ("f3c2a1d4e6b8",), existing,
    ]
    args = (conn, uuid4(), uuid4())
    if existing:
        with pytest.raises(AssertionError, match="Refusing to replace an existing demo identity"):
            seed_disposable_voters(*args, database=DATABASE, marker=MARKER)
        assert conn.execute.call_count == 3
    else:
        seed_disposable_voters(*args, database=DATABASE, marker=MARKER)
        sql, params = conn.execute.call_args.args
        assert "is_active" in sql
        assert sql.count("%s, %s, %s, true") == 2
        assert params[0] != params[3]


def test_missing_marker_prevents_fixture_seed_before_any_write():
    conn = Mock()
    conn.execute.return_value.fetchone.return_value = (DATABASE, None)
    with pytest.raises(AssertionError):
        seed_disposable_voters(conn, uuid4(), uuid4(), database=DATABASE, marker=MARKER)
    assert conn.execute.call_count == 1


def test_disposable_cli_rejects_existing_ra_db_before_password_prompt(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["disposable", "--disposable-fixture-writes",
                                     "--database", "ra_db", "--disposable-marker", MARKER])
    with patch.object(disposable, "prompt_password") as prompt, \
         patch.object(disposable, "database_factory") as factory:
        with pytest.raises(AssertionError):
            disposable.main()
        prompt.assert_not_called()
        factory.assert_not_called()


@pytest.mark.parametrize("fixture", [False, True])
def test_each_disposable_connection_rechecks_identity_and_marker(fixture):
    conn = MagicMock()
    login = "ra_migrator_login" if fixture else "ra_auth_login"
    role = "ra_owner" if fixture else "ra_auth_login"
    conn.execute.return_value.fetchone.side_effect = [
        (DATABASE, login, role), (DATABASE, "secure-evoting-disposable:"+MARKER),
        (DATABASE, login, role), (DATABASE, "MISSING_MARKER"),
    ]
    factory = database_factory(SecretStr("SYNTHETIC_TEST_PASSWORD"), database=DATABASE,
                               fixture=fixture, disposable_marker=MARKER)
    with patch("scripts.ra_demo_db_test_support.psycopg.connect", return_value=conn) as connect:
        assert factory() is conn
        with pytest.raises(AssertionError, match="not independently marked disposable"):
            factory()
        assert connect.call_args.kwargs["user"] == login
        assert connect.call_args.kwargs["dbname"] == DATABASE
    conn.close.assert_called_once_with()
    role_switches = [call for call in conn.execute.call_args_list
                     if call.args[0].startswith("SET LOCAL ROLE")]
    assert len(role_switches) == (2 if fixture else 0)


def test_manual_db_test_passwords_are_prompted_and_masked(capsys):
    with patch("scripts.ra_demo_db_test_support.getpass.getpass", return_value="SYNTHETIC_PASSWORD"):
        password = prompt_password("Synthetic prompt: ")
    assert "SYNTHETIC_PASSWORD" not in repr(password)
    captured = capsys.readouterr()
    assert "SYNTHETIC_PASSWORD" not in captured.out + captured.err


def test_manual_db_test_refuses_empty_or_echoing_password_input():
    with patch("scripts.ra_demo_db_test_support.getpass.getpass", return_value=""):
        with pytest.raises(AssertionError, match="Empty database password refused"):
            prompt_password("Synthetic prompt: ")

    def echoing(prompt):
        warnings.warn("Cannot control echo", getpass.GetPassWarning)
        raise AssertionError("Echoing input must not be read")

    with patch("scripts.ra_demo_db_test_support.getpass.getpass", side_effect=echoing):
        with pytest.raises(getpass.GetPassWarning):
            prompt_password("Synthetic prompt: ")
