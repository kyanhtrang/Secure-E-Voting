"""Failure injection only: no Docker, PostgreSQL or real credentials."""

import ast
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock
from uuid import uuid4

import psycopg
from pydantic import SecretStr
import pytest

from scripts import voting_disposable_integration as integration
from scripts import voting_postgres_ci as ci
from scripts.voting_integration_diagnostics import ASSERTIONS, ASSERTION_IDS, CATEGORIES, STAGES, IntegrationDiagnostics


@pytest.mark.parametrize("stage", sorted(STAGES))
def test_each_allowlisted_stage_has_closed_vocabulary_diagnostics(stage, capsys):
    diagnostics = IntegrationDiagnostics()
    diagnostics.set_stage(stage)
    error = AssertionError("20-way serial uniqueness failed")
    diagnostics.report(error)
    diagnostics.report(error)
    assert capsys.readouterr().out == (
        "stage="+stage+" category=assertion_error SQLSTATE=unavailable assertion=same_serial_outcomes\n")
    assert diagnostics.failures == 1


def test_invalid_stages_and_arbitrary_error_fields_cannot_escape(capsys):
    diagnostics = IntegrationDiagnostics()
    with pytest.raises(ValueError, match="Unknown integration diagnostic stage"):
        diagnostics.set_stage("SYNTHETIC_CANARY")
    error = AssertionError("password=secret SQL payload SYNTHETIC_CANARY")
    error.sqlstate = "42809\nSYNTHETIC_CANARY"
    error.diag = SimpleNamespace(message_primary="SYNTHETIC_CANARY", context="SYNTHETIC_CANARY")
    diagnostics.report(error)
    result = capsys.readouterr().out
    assert result == "stage=migration_head category=assertion_error SQLSTATE=unavailable assertion=unclassified\n"
    assert "SYNTHETIC_CANARY" not in result


@pytest.mark.parametrize("error,category,state", [
    (psycopg.errors.InsufficientPrivilege("SYNTHETIC_CANARY"), "database_error", "42501"),
    (TimeoutError("SYNTHETIC_CANARY"), "timeout_error", "unavailable"),
    (SystemExit("SYNTHETIC_CANARY"), "system_exit", "unavailable"),
    (RuntimeError("SYNTHETIC_CANARY"), "unexpected_error", "unavailable"),
])
def test_only_allowed_categories_and_sqlstate_are_reported(error, category, state):
    diagnostics = IntegrationDiagnostics()
    result = diagnostics.failure(error)
    assert category in CATEGORIES and "category="+category in result
    assert "SQLSTATE="+state in result and "SYNTHETIC_CANARY" not in result


def test_all_existing_harness_assertion_messages_have_fixed_identifiers():
    paths = [Path(integration.__file__), Path(ci.__file__)]
    for path in paths:
        tree = ast.parse(path.read_text())
        if path == Path(ci.__file__):
            tree = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "run_harness")
        roots = [node for node in tree.body if not (isinstance(node, ast.FunctionDef) and node.name == "check")] if isinstance(tree, ast.Module) else [tree]
        for node in (item for root in roots for item in ast.walk(root)):
            if not isinstance(node, ast.Call):
                continue
            if isinstance(node.func, ast.Name) and node.func.id == "check" and len(node.args) == 2:
                assert isinstance(node.args[1], ast.Constant) and node.args[1].value in ASSERTIONS
            if isinstance(node.func, ast.Name) and node.func.id == "AssertionError" and node.args:
                assert isinstance(node.args[0], ast.Constant) and node.args[0].value in ASSERTIONS


def test_actual_coordinator_and_harness_assign_all_required_stages():
    observed = {IntegrationDiagnostics().stage}
    for module in (integration, ci):
        tree = ast.parse(Path(module.__file__).read_text())
        if module is ci:
            tree = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "run_harness")
        for node in ast.walk(tree):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr in ("set_stage", "at") and node.args):
                assert isinstance(node.args[0], ast.Constant) and node.args[0].value in STAGES
                observed.add(node.args[0].value)
    assert observed == STAGES
    diagnostics = IntegrationDiagnostics()
    fields = dict(part.split("=", 1) for part in diagnostics.failure(AssertionError("unknown")).split())
    assert set(fields) == {"stage", "category", "SQLSTATE", "assertion"}
    assert fields["assertion"] in ASSERTION_IDS and fields["category"] in CATEGORIES


def coordinator_environment(monkeypatch):
    selected = ci.Target("voting_demo_test_ci_"+uuid4().hex, str(uuid4()), 35432)
    generated = {role: SecretStr("SYNTHETIC_TEST_PASSWORD") for role in ci.LOGINS}
    conn = MagicMock()
    conn.__enter__.return_value = conn
    conn.execute.return_value.fetchone.return_value = (ci.HEAD,)
    monkeypatch.setattr(ci, "require_ci", Mock())
    monkeypatch.setattr(integration, "factory", Mock(return_value=lambda: conn))
    before = {table: [] for table in ci.TABLES}
    monkeypatch.setattr(ci, "snapshot", Mock(return_value=before))
    return selected, generated, conn


@pytest.mark.parametrize("stage", ["migration_head", "initial_snapshot", "final_snapshot"])
def test_coordinator_failures_before_or_after_main_have_correct_stage(monkeypatch, capsys, stage):
    selected, generated, conn = coordinator_environment(monkeypatch)
    main = Mock()
    monkeypatch.setattr(integration, "main", main)
    if stage == "migration_head":
        conn.execute.return_value.fetchone.return_value = ("wrong-head",)
        expected = "committed_migration_head"
    elif stage == "initial_snapshot":
        ci.snapshot.side_effect = psycopg.errors.InsufficientPrivilege("SYNTHETIC_CANARY")
        expected = "none"
    else:
        ci.snapshot.side_effect = [{}, {"accepted_ballots": ["SYNTHETIC_CANARY"]}]
        expected = "committed_cleanup"
    with pytest.raises((AssertionError, psycopg.Error)):
        ci.run_harness(selected, generated)
    output = capsys.readouterr().out
    assert "stage="+stage in output and "assertion="+expected in output
    assert "SYNTHETIC_CANARY" not in output
    assert main.call_count == (1 if stage == "final_snapshot" else 0)


def test_real_main_systemexit_conversion_preserves_safe_original_stage_for_ci(monkeypatch, capsys):
    selected, generated, _ = coordinator_environment(monkeypatch)
    def fail(*args, diagnostics, **kwargs):
        diagnostics.set_stage("receipt_recovery")
        raise AssertionError("Lost-response recovery or SQL/Python receipt interoperability failed")
    monkeypatch.setattr(integration, "run", fail)
    with pytest.raises(RuntimeError, match="Voting integration terminated"):
        ci.run_harness(selected, generated)  # Calls the real main(), not a replacement.
    output = capsys.readouterr()
    assert output.out == "stage=receipt_recovery category=assertion_error SQLSTATE=unavailable assertion=receipt_consistency\n"
    assert "details suppressed" in output.err and "Traceback" not in output.err
    assert ci.snapshot.call_count == 1  # No final snapshot / success after failure.


def test_unexpected_systemexit_zero_cannot_turn_ci_green(monkeypatch, capsys):
    selected, generated, _ = coordinator_environment(monkeypatch)
    monkeypatch.setattr(integration, "main", Mock(side_effect=SystemExit(0)))
    with pytest.raises(RuntimeError, match="Voting integration terminated"):
        ci.run_harness(selected, generated)
    assert "stage=fixture_seed category=system_exit" in capsys.readouterr().out


def harness_environment(monkeypatch, *, cleanup_failure=False):
    conn = MagicMock()
    conn.__enter__.return_value = conn
    conn.execute.return_value.fetchone.return_value = None  # Newly owned election absent after cleanup.
    clean = MagicMock()
    clean.__enter__.return_value = clean
    clean.execute.side_effect = psycopg.errors.InsufficientPrivilege("SYNTHETIC_CANARY")
    fixture = Mock(side_effect=[conn, clean if cleanup_failure else conn])
    value = SimpleNamespace(manifest={"election_id": str(uuid4())}, pin=b"p"*32)
    monkeypatch.setattr(integration, "material", lambda: value)
    monkeypatch.setattr(integration, "seed", Mock())
    monkeypatch.setattr(integration, "verify_database", Mock())  # Catalog guards have separate real-logic tests.
    monkeypatch.setattr(integration, "payload_for", lambda _: {})
    monkeypatch.setattr(integration, "BallotService", Mock())
    client = MagicMock()
    client.__enter__.return_value = client
    client.post.return_value.status_code = 503
    monkeypatch.setattr(integration, "client", Mock(return_value=client))
    return fixture


@pytest.mark.parametrize("cleanup_failure", [False, True])
def test_original_concurrency_failure_is_recorded_before_cleanup(monkeypatch, capsys, cleanup_failure):
    fixture = harness_environment(monkeypatch, cleanup_failure=cleanup_failure)
    diagnostics = IntegrationDiagnostics()
    with pytest.raises(psycopg.Error if cleanup_failure else AssertionError):
        integration.run(fixture, Mock(), "voting_demo_test_unit", str(uuid4()), diagnostics=diagnostics)
    lines = capsys.readouterr().out.splitlines()
    assert lines[0] == "stage=concurrency_20 category=assertion_error SQLSTATE=unavailable assertion=same_serial_outcomes"
    assert len(lines) == (2 if cleanup_failure else 1)
    if cleanup_failure:
        assert lines[1] == "stage=cleanup category=database_error SQLSTATE=42501 assertion=none"
    assert not any("SYNTHETIC_CANARY" in line for line in lines)
    assert fixture.call_count == 2  # Cleanup still runs after the failed assertion.
    integration.verify_database.assert_called_once()  # The cleanup guard is still invoked.


def test_fixture_seed_failure_is_not_reported_as_a_concurrency_failure(monkeypatch, capsys):
    fixture = harness_environment(monkeypatch)
    monkeypatch.setattr(integration, "seed", Mock(side_effect=psycopg.errors.InsufficientPrivilege("SYNTHETIC_CANARY")))
    with pytest.raises(psycopg.Error):
        integration.run(fixture, Mock(), "voting_demo_test_unit", str(uuid4()))
    assert capsys.readouterr().out == "stage=fixture_seed category=database_error SQLSTATE=42501 assertion=none\n"
    assert fixture.call_count == 1  # Never clean up an election whose seed did not commit.
