"""Database-free classification and redaction checks; never execute PG migration SQL."""

import ast
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock

from alembic.config import Config
from alembic.script import ScriptDirectory
import pytest
from sqlalchemy import create_engine, event, text

from scripts import voting_postgres_ci as ci


def scripts():
    config = Config()
    config.set_main_option("script_location", str(ci.ROOT/"migrations/voting"))
    return ScriptDirectory.from_config(config)


def first_literal(revision):
    script = scripts().get_revision(revision)
    tree = ast.parse(Path(script.path).read_text(encoding="utf-8-sig"))
    upgrade = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "upgrade")
    return next(node.args[0].value for node in ast.walk(upgrade) if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute) and node.func.attr == "execute"
        and isinstance(node.func.value, ast.Name) and node.func.value.id == "op"
        and node.args and isinstance(node.args[0], ast.Constant))


@pytest.mark.parametrize("revision", ci.CHAIN)
def test_classifies_actual_unchanged_revision_statement_without_logging_sql(revision):
    diagnostics = ci.MigrationDiagnostics(scripts())
    diagnostics.set_stage("alembic")
    diagnostics.before_execute(None, text(first_literal(revision)), (), {"secret": "SYNTHETIC_CANARY"}, {})
    assert diagnostics.revision == revision and diagnostics.statement == "upgrade_sql_01"
    error = RuntimeError("SYNTHETIC_CANARY")
    error.sqlstate = "42809"
    result = diagnostics.failure(error)
    assert "revision="+revision in result and "check=upgrade_sql_01" in result
    assert "SQLSTATE=42809" in result and "SYNTHETIC_CANARY" not in result
    assert "CREATE TABLE" not in result and "DO $preflight$" not in result


def test_unrecognized_sql_and_parameters_are_not_used_as_labels():
    diagnostics = ci.MigrationDiagnostics(scripts())
    diagnostics.before_execute(None, text("SELECT 'SYNTHETIC_CANARY'"), (), {"password": "SYNTHETIC_CANARY"}, {})
    assert diagnostics.statement == "alembic_internal_or_nonliteral"
    result = diagnostics.failure(RuntimeError("SYNTHETIC_CANARY"))
    assert "SQLSTATE=unavailable" in result and "SYNTHETIC_CANARY" not in result


def test_only_exact_allowlisted_postgres_diagnostics_can_escape():
    diagnostics = ci.MigrationDiagnostics(scripts())
    error = RuntimeError("password SQL and SYNTHETIC_CANARY")
    error.sqlstate = "42809"
    error.diag = SimpleNamespace(schema_name="voting", table_name="accepted_ballots",
        source_function="has_sequence_privilege_name_id", message_primary="SYNTHETIC_CANARY",
        message_detail="SYNTHETIC_CANARY", context="SYNTHETIC_CANARY")
    result = diagnostics.failure(SimpleNamespace(orig=error))
    assert "schema_name=voting" in result and "table_name=accepted_ballots" in result
    assert "source_function=has_sequence_privilege_name_id" in result
    assert "SYNTHETIC_CANARY" not in result and "password" not in result
    for field in ("schema_name", "table_name", "source_function"):
        setattr(error.diag, field, "syntactically_valid_secret_canary")
    assert diagnostics.failure(error).count("=redacted") == 3
    assert "secret_canary" not in diagnostics.failure(error)


@pytest.mark.parametrize("state", [None, "42809\nSYNTHETIC_CANARY", "secret", 42809])
def test_invalid_sqlstate_cannot_escape(state):
    diagnostics = ci.MigrationDiagnostics(scripts())
    error = RuntimeError("SYNTHETIC_CANARY")
    error.sqlstate = state
    result = diagnostics.failure(error)
    assert "SQLSTATE=unavailable" in result and "SYNTHETIC_CANARY" not in result


def test_listener_uses_real_sqlalchemy_event_api_and_is_removable():
    diagnostics = ci.MigrationDiagnostics(scripts())
    # SQLite in-memory SELECT only checks SQLAlchemy event wiring, not PG behavior.
    engine = create_engine("sqlite://")
    try:
        with engine.connect() as conn:
            event.listen(conn, "before_execute", diagnostics.before_execute)
            assert conn.execute(text("SELECT 1")).scalar_one() == 1
            assert diagnostics.statement == "alembic_internal_or_nonliteral"
            event.remove(conn, "before_execute", diagnostics.before_execute)
            assert not event.contains(conn, "before_execute", diagnostics.before_execute)
    finally:
        engine.dispose()


def test_actual_migrate_reports_fixed_label_and_reraises_without_commit(monkeypatch, capsys):
    from uuid import uuid4
    from pydantic import SecretStr
    selected = ci.Target("voting_demo_test_ci_"+uuid4().hex, str(uuid4()), 35432)
    monkeypatch.setattr(ci, "require_ci", Mock())
    engine = MagicMock()
    conn = engine.begin.return_value.__enter__.return_value
    conn.exec_driver_sql.return_value.one.return_value = (selected.database, "voting_migrator_login", "voting_migrator_login", 5432)
    conn.exec_driver_sql.return_value.scalar_one.return_value = 0
    monkeypatch.setattr(ci, "create_engine", Mock(return_value=engine))
    monkeypatch.setattr(ci.integration, "verify_database", Mock())
    callbacks = []
    monkeypatch.setattr(ci.event, "listen", lambda connection, name, callback: callbacks.append(callback))
    remove = Mock()
    monkeypatch.setattr(ci.event, "remove", remove)
    error = RuntimeError("password=SYNTHETIC_CANARY SQL/parameters")
    error.sqlstate = "42809"
    error.diag = SimpleNamespace(source_function="has_sequence_privilege_name_id")

    def upgrade(config, head):
        callbacks[0](conn, text(first_literal(ci.HEAD)), (), {"password": "SYNTHETIC_CANARY"}, {})
        raise error
    monkeypatch.setattr(ci.command, "upgrade", upgrade)
    with pytest.raises(RuntimeError) as caught:
        ci.migrate(selected, SecretStr("SYNTHETIC_CANARY"))
    assert caught.value is error
    output = capsys.readouterr().out
    assert "stage=alembic revision=d8f27a4c610b check=upgrade_sql_01 SQLSTATE=42809" in output
    assert "source_function=has_sequence_privilege_name_id" in output
    assert "SYNTHETIC_CANARY" not in output and "PASS:" not in output
    remove.assert_called_once()
    engine.dispose.assert_called_once()
    assert engine.begin.return_value.__exit__.call_args.args[0] is RuntimeError
