"""Database-free safety/coordination regressions, not real E2E PASS evidence."""
from contextlib import contextmanager
import asyncio
import io
import json
from pathlib import Path
from unittest.mock import MagicMock, Mock
from uuid import uuid4

import pytest
import yaml

from scripts import admin_voter_e2e as gate


def wire(kind="ra"):
    return {"database": kind + "_demo_test_ci_" + uuid4().hex, "marker": str(uuid4()), "port": 23456,
        "container_id": "a" * 64, "container_name": "evote-voting-ci-" + "b" * 32}


def test_local_entrypoint_refuses_before_files_connections_or_children(monkeypatch):
    monkeypatch.setattr(gate.sys, "platform", "win32")
    connect, spawn, read = Mock(), Mock(), Mock()
    monkeypatch.setattr(gate.psycopg, "connect", connect)
    monkeypatch.setattr(gate.real.subprocess, "Popen", spawn)
    monkeypatch.setattr(Path, "read_bytes", read)
    with pytest.raises(SystemExit) as error:
        gate.main(["--allow-ephemeral-ci-databases", "--node", "never-open", "--signer-binary", "never-open"])
    assert str(error.value) == "FAIL: admin_voter_e2e stage=preflight category=assertion_error sqlstate=unavailable"
    connect.assert_not_called(); spawn.assert_not_called(); read.assert_not_called()


@pytest.mark.parametrize("kind,name", [("ra", "ra_db"), ("voting", "voting_db"), ("ra", "voting_demo_test_ci_bad")])
def test_normal_or_cross_database_targets_refused(kind, name):
    target = wire(kind); target["database"] = name
    with pytest.raises(AssertionError): gate.designated(kind, target)


@pytest.mark.parametrize("field,value", [("marker", "not-a-uuid"), ("port", 5432.1),
    ("container_id", "short"), ("container_name", "unrelated-container")])
def test_owned_identity_requires_exact_designation(field, value):
    target = wire(); target[field] = value
    with pytest.raises(AssertionError): gate.designated("ra", target)


@pytest.mark.parametrize("extra", ["authority_key", "publisher_password", "auth_password", "issuance_password", "keysets"])
def test_voting_configuration_cannot_receive_other_service_secrets(extra):
    config = {"target": wire("voting"), "pin": gate.b64encode(bytes(32)), "password": "synthetic-only"}
    assert gate.configuration("voting", config)[0].kind == "voting"
    with pytest.raises(AssertionError): gate.configuration("voting", dict(config, **{extra: "SECRET_CANARY"}))


def test_connection_checks_container_and_database_identity_on_every_use(monkeypatch):
    owned = gate.designated("ra", wire())
    verify = Mock()
    monkeypatch.setattr(gate.OwnedDatabase, "verify", verify)
    monkeypatch.setattr(gate.real, "require_ci", Mock())
    conn = Mock()
    conn.execute.return_value.fetchone.return_value = (owned.target.database, "ra_auth_login", "ra_auth_login",
        "ra_owner", "secure-evoting-disposable:" + owned.target.marker, 180000)
    connect = Mock(return_value=conn)
    monkeypatch.setattr(gate.psycopg, "connect", connect)
    factory = gate.connection(owned, "ra_auth_login", gate.SecretStr("synthetic-only"))
    assert factory() is conn and factory() is conn
    assert verify.call_count == connect.call_count == conn.execute.call_count == 2
    assert connect.call_args.kwargs["host"] == "127.0.0.1"
    assert connect.call_args.kwargs["dbname"].startswith("ra_demo_test_ci_")


def test_container_refusal_prevents_opening_connection(monkeypatch):
    owned = gate.designated("ra", wire())
    monkeypatch.setattr(gate.real, "require_ci", Mock())
    monkeypatch.setattr(gate.OwnedDatabase, "verify", Mock(side_effect=AssertionError()))
    connect = Mock(); monkeypatch.setattr(gate.psycopg, "connect", connect)
    with pytest.raises(AssertionError): gate.connection(owned, "ra_auth_login", gate.SecretStr("synthetic-only"))()
    connect.assert_not_called()


@pytest.mark.parametrize("role", ["postgres", "ra_owner", "ra_migrator_login", "voting_admin_login"])
def test_runtime_factory_rejects_privilege_or_database_role_mismatch(role):
    with pytest.raises(AssertionError): gate.connection(gate.designated("ra", wire()), role, gate.SecretStr("synthetic-only"))


def test_permission_fault_restores_only_original_grant_even_after_failure():
    conn = MagicMock(); conn.__enter__.return_value = conn
    conn.execute.return_value.fetchone.return_value = (True,)
    db = Mock(ra_fixture=Mock(return_value=conn))
    with pytest.raises(RuntimeError):
        with gate.publisher_denied(db): raise RuntimeError("SECRET_CANARY")
    statements = [call.args[0] for call in conn.execute.call_args_list]
    assert statements[1:] == [
        "REVOKE EXECUTE ON FUNCTION ra_admin.reconcile(uuid,bytea,boolean,uuid) FROM ra_election_publisher_login",
        "GRANT EXECUTE ON FUNCTION ra_admin.reconcile(uuid,bytea,boolean,uuid) TO ra_election_publisher_login"]
    assert db.ra_fixture.call_count == 2


def test_fault_does_not_widen_missing_initial_grant():
    conn = MagicMock(); conn.__enter__.return_value = conn
    conn.execute.return_value.fetchone.return_value = (False,)
    with pytest.raises(AssertionError):
        with gate.publisher_denied(Mock(ra_fixture=Mock(return_value=conn))): pass
    assert conn.execute.call_count == 1


@pytest.mark.parametrize("stage", ["open_interrupted", "close_interrupted", "SECRET_CANARY"])
def test_bounded_diagnostics_hide_secrets(stage):
    error = RuntimeError("password=SECRET_CANARY credential=SECRET_CANARY")
    result = gate.failure(stage, error)
    assert "SECRET_CANARY" not in result
    assert result == "FAIL: admin_voter_e2e stage=" + (stage if stage in gate.STAGES else "preflight") + " category=unexpected_error sqlstate=unavailable"


@pytest.mark.parametrize("status", [503, 200, 418, "SECRET_CANARY", True])
def test_http_status_diagnostics_are_allowlisted(status):
    error = AssertionError("SECRET_CANARY"); error.http_status = status
    output = gate.failure("open_interrupted", error)
    assert "SECRET_CANARY" not in output
    assert (" http_status=" in output) == (type(status) is int and status in gate.real.HTTP_STATUSES)


@pytest.mark.parametrize("header", [b"authorization", b"cookie", b"x-admin-token", b"x-admin-id", b"x-voter-id", b"x-ra-token"])
def test_real_voting_wire_observer_records_identity_without_interfering_with_service(header):
    calls = []
    async def app(scope, receive, send): calls.append(scope["path"])
    wire = gate.AnonymousWire(app)
    asyncio.run(wire({"type": "http", "path": "/api/v1/vote/ballots", "headers": [(header, b"synthetic-only")]}, None, None))
    assert wire.failed and wire.requests == 1 and calls == ["/api/v1/vote/ballots"]


def test_anonymous_wire_observer_accepts_only_unidentified_requests():
    async def app(scope, receive, send): pass
    wire = gate.AnonymousWire(app)
    asyncio.run(wire({"type": "http", "path": "/api/v1/vote/ballots/receipt", "headers": [(b"content-type", b"application/json")]}, None, None))
    assert wire.requests == 1 and not wire.failed


@pytest.mark.parametrize("bad", ["PGHOST", "DOCKER_HOST", "ADMIN_DEMO_DB_PASSWORD", "VITE_ENABLE_ADMIN"])
def test_inherited_service_or_database_configuration_refused(monkeypatch, tmp_path, bad):
    monkeypatch.setattr(gate.sys, "platform", "linux")
    for name in list(gate.os.environ):
        if name.startswith(("PG", "DOCKER_", "RA_DEMO_", "VOTING_DEMO_", "ADMIN_DEMO_", "VITE_")):
            monkeypatch.delenv(name)
    for name, value in {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "Linux", "RUNNER_TEMP": str(tmp_path), bad: "SECRET_CANARY"}.items():
        monkeypatch.setenv(name, value)
    with pytest.raises(AssertionError): gate.require_ci()


def test_browser_hook_closes_via_api_callback_and_preserves_all_db_checkpoints(monkeypatch):
    events = ["catalogue", "prepared", "issued", "accepted", "security_checks", "close_after_accept", "closed_recovery", "done"]
    process = Mock(stdin=io.StringIO(), stdout=io.StringIO("".join(json.dumps({"event": event}) + "\n" for event in events)))
    process.wait.return_value = 0
    @contextmanager
    def child(*args, **kwargs): yield process
    monkeypatch.setattr(gate.real, "child", child)
    assertion, fixture_close, close, progress = Mock(), Mock(), Mock(), Mock()
    monkeypatch.setattr(gate.real, "assert_database", assertion)
    monkeypatch.setattr(gate.real, "close_election", fixture_close)
    gate.real.browser(Path("node"), {"scenario": "accepted"}, None, None, None, ["browser"], close=close, checkpoint=progress)
    close.assert_called_once_with("close_after_accept")
    fixture_close.assert_not_called()
    assert assertion.call_count == progress.call_count == len(events) - 1
    assert [call.args[0] for call in progress.call_args_list] == events[:-1]
    assert len(process.stdin.getvalue().splitlines()) == len(events)


def test_callback_failure_stops_browser_ack(monkeypatch):
    process = Mock(stdin=io.StringIO(), stdout=io.StringIO('{"event":"before_submit_close"}\n'))
    @contextmanager
    def child(*args, **kwargs): yield process
    monkeypatch.setattr(gate.real, "child", child)
    assertion = Mock(); monkeypatch.setattr(gate.real, "assert_database", assertion)
    with pytest.raises(AssertionError):
        gate.real.browser(Path("node"), {"scenario": "closed_first"}, None, None, None, ["browser"], close=Mock(side_effect=AssertionError()))
    assert len(process.stdin.getvalue().splitlines()) == 1
    assertion.assert_not_called()


def test_gate_uses_admin_http_instead_of_finalized_election_fixture():
    import ast
    source = (gate.ROOT / "scripts/admin_voter_e2e.py").read_text(encoding="utf8")
    tree = ast.parse(source)
    sql = [node.args[0].value.lower() for node in ast.walk(tree)
           if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "execute"
           and node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str)]
    assert not any("insert into voting." in query or "insert into ra.credential_policies" in query
                   or "insert into ra.ra_signing_keys" in query or "update voting.elections" in query for query in sql)
    assert '"/finalize"' in source and '"/open"' in source and '"/close"' in source
    assert "LocalCIRCLSigner" in source and "BestAvailableEncryption" in source
    assert "real.seed(" not in source and "real.cleanup(" not in source


def test_workflow_is_separate_hosted_locked_and_runs_regression_before_real_gate():
    path = gate.ROOT / ".github/workflows/admin-voter-integration.yml"
    text = path.read_text(encoding="utf8")
    workflow = yaml.safe_load(text)
    trigger = workflow.get("on", workflow.get(True))
    assert trigger == {"push": {"branches": ["test/admin-voter-integration"]}, "workflow_dispatch": None}
    assert workflow["permissions"] == {"contents": "read"}
    job = workflow["jobs"]["admin-voter-integration"]
    assert job["runs-on"] == "ubuntu-24.04"
    assert not any(step.get("continue-on-error") for step in job["steps"])
    assert "secrets." not in text and "upload-artifact" not in text
    scripts = [step.get("run", "") for step in job["steps"]]
    real_step = next(i for i, script in enumerate(scripts) if "scripts/admin_voter_e2e.py" in script)
    for command in ("-m pytest", "npm test", "test:admin-browser", "go test"):
        assert any(command in script for script in scripts[:real_step])
    assert any("--no-deps -r backend/voting/requirements.lock.txt" in script for script in scripts)
    assert any("go-version" in step.get("with", {}) and step["with"]["go-version"] == "1.25.14" for step in job["steps"])
