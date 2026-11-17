"""Database-free ACL probe regression. PostgreSQL execution remains a CI gate."""

from contextlib import contextmanager
from unittest.mock import Mock

import psycopg
import pytest

from scripts import voting_disposable_integration as integration
from scripts.voting_integration_diagnostics import ACL_PROBE_IDS, ASSERTION_IDS, IntegrationDiagnostics


PROBES = integration.ACL_PROBES


def connection(outcome, *, metadata=(False,)):
    conn = Mock()
    def execute(query, params=None):
        if "has_table_privilege" in query or "has_function_privilege" in query:
            if isinstance(metadata, Exception):
                raise metadata
            return Mock(fetchone=Mock(return_value=metadata))
        if isinstance(outcome, Exception):
            raise outcome
        return Mock()
    conn.execute.side_effect = execute
    return conn


def runtime_for(conn, events):
    @contextmanager
    def runtime():
        try:
            yield conn
        except BaseException:
            events.append("rollback")
            raise
        else:
            events.append("commit")
    return runtime


def test_three_fixed_probe_ids_preserve_direct_select_delete_and_nonnull_execute():
    assert {probe[0] for probe in PROBES} == ACL_PROBE_IDS
    assert ACL_PROBE_IDS <= ASSERTION_IDS
    select, delete, helper = PROBES
    assert select[2] == "SELECT * FROM voting.accepted_ballots"
    assert delete[2] == "DELETE FROM voting.accepted_ballots"
    for probe, privilege in ((select, "SELECT"), (delete, "DELETE")):
        assert "pg_catalog.has_table_privilege(current_user," in probe[1]
        assert "'voting.accepted_ballots','"+privilege+"'" in probe[1]
        assert not probe[3]
    assert "pg_catalog.has_function_privilege(current_user," in helper[1]
    assert "voting._ballot_receipt(uuid,bytea,bytea,bytea,bytea)" in helper[1]
    assert "'EXECUTE'" in helper[1]
    assert helper[2].count("%s") == 5 and "NULL" not in helper[2]
    assert len(helper[3]) == 5 and all(value is not None for value in helper[3])
    assert [len(value) for value in helper[3][1:]] == [32, 2, 33, 384]


@pytest.mark.parametrize("probe", PROBES, ids=lambda probe: probe[0])
def test_each_probe_passes_only_on_real_attempted_42501_denial(monkeypatch, capsys, probe):
    monkeypatch.setattr(integration, "ACL_PROBES", (probe,))
    error = psycopg.errors.InsufficientPrivilege("SYNTHETIC_CANARY")
    conn = connection(error)
    events = []
    integration.run_acl_probes(runtime_for(conn, events), IntegrationDiagnostics())
    assert events == ["rollback"]
    assert conn.execute.call_args_list[0].args == (probe[1],)
    assert conn.execute.call_args_list[1].args == (probe[2], probe[3])
    assert not capsys.readouterr().out  # Expected denials are successful tests.


@pytest.mark.parametrize("probe", PROBES, ids=lambda probe: probe[0])
@pytest.mark.parametrize("outcome", ["success", "wrong_state", "unexpected"])
def test_success_wrong_sqlstate_or_unexpected_exception_fail_with_exact_id(monkeypatch, capsys, probe, outcome):
    monkeypatch.setattr(integration, "ACL_PROBES", (probe,))
    error = {"success": None,
             "wrong_state": psycopg.errors.UndefinedFunction("SYNTHETIC_CANARY"),
             "unexpected": RuntimeError("SYNTHETIC_CANARY")}[outcome]
    conn = connection(error)
    events = []
    diagnostics = IntegrationDiagnostics()
    with pytest.raises(AssertionError if outcome == "success" else type(error)):
        integration.run_acl_probes(runtime_for(conn, events), diagnostics)
    assert events == ["rollback"]  # Even a forbidden DELETE that succeeds cannot commit.
    output = capsys.readouterr().out
    assert "stage=acl_verification" in output and "assertion="+probe[0] in output
    assert "SQLSTATE=42883" in output if outcome == "wrong_state" else "SQLSTATE=unavailable" in output
    assert "SYNTHETIC_CANARY" not in output and probe[2] not in output


@pytest.mark.parametrize("metadata", [(True,), None, (), (False, True),
    psycopg.errors.InsufficientPrivilege("SYNTHETIC_CANARY")])
def test_privilege_metadata_must_explicitly_deny_before_attempt(monkeypatch, capsys, metadata):
    probe = PROBES[2]
    monkeypatch.setattr(integration, "ACL_PROBES", (probe,))
    conn = connection(psycopg.errors.InsufficientPrivilege("SYNTHETIC_CANARY"), metadata=metadata)
    events = []
    with pytest.raises((AssertionError, psycopg.errors.InsufficientPrivilege)):
        integration.run_acl_probes(runtime_for(conn, events), IntegrationDiagnostics())
    assert conn.execute.call_count == 1
    assert events == ["rollback"]
    output = capsys.readouterr().out
    assert "assertion=internal_receipt_execute" in output and "SYNTHETIC_CANARY" not in output


def test_connection_factory_denial_is_not_counted_as_probe_execution(monkeypatch):
    monkeypatch.setattr(integration, "ACL_PROBES", (PROBES[0],))
    runtime = Mock(side_effect=psycopg.errors.InsufficientPrivilege("SYNTHETIC_CANARY"))
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        integration.run_acl_probes(runtime, IntegrationDiagnostics())


def test_misclassified_insufficient_privilege_with_wrong_state_fails(monkeypatch, capsys):
    class WrongState(psycopg.errors.InsufficientPrivilege):
        sqlstate = "22023"
    monkeypatch.setattr(integration, "ACL_PROBES", (PROBES[2],))
    with pytest.raises(WrongState):
        integration.run_acl_probes(runtime_for(connection(WrongState("SYNTHETIC_CANARY")), []), IntegrationDiagnostics())
    assert "SQLSTATE=22023 assertion=internal_receipt_execute" in capsys.readouterr().out


def test_successful_query_followed_by_exit_denial_still_fails(monkeypatch):
    monkeypatch.setattr(integration, "ACL_PROBES", (PROBES[1],))
    conn = connection(None)
    @contextmanager
    def runtime():
        try:
            yield conn
        finally:
            raise psycopg.errors.InsufficientPrivilege("SYNTHETIC_CANARY")
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        integration.run_acl_probes(runtime, IntegrationDiagnostics())


def test_new_exit_exception_cannot_masquerade_as_the_query_denial(monkeypatch):
    monkeypatch.setattr(integration, "ACL_PROBES", (PROBES[2],))
    query_error = psycopg.errors.InsufficientPrivilege("SYNTHETIC_QUERY_CANARY")
    exit_error = psycopg.errors.InsufficientPrivilege("SYNTHETIC_EXIT_CANARY")
    conn = connection(query_error)
    @contextmanager
    def runtime():
        try:
            yield conn
        except psycopg.errors.InsufficientPrivilege:
            raise exit_error
    with pytest.raises(psycopg.errors.InsufficientPrivilege) as caught:
        integration.run_acl_probes(runtime, IntegrationDiagnostics())
    assert caught.value is exit_error


def test_unknown_probe_identifier_never_becomes_a_diagnostic(capsys):
    diagnostics = IntegrationDiagnostics()
    with pytest.raises(ValueError, match="Unknown ACL diagnostic identifier"):
        with diagnostics.probe("SYNTHETIC_CANARY"):
            raise AssertionError("unreachable")
    assert not capsys.readouterr().out
