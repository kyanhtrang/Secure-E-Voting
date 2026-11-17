"""CI confinement tests. All Docker/DB/migration execution uses test doubles."""

import json
from pathlib import Path
import secrets
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock
from uuid import uuid4

import pytest
from pydantic import SecretStr
import yaml

from scripts import voting_postgres_ci as ci
from scripts import voting_disposable_integration as integration


def target():
    return ci.Target("voting_demo_test_ci_"+uuid4().hex, str(uuid4()), 35432)


def passwords():
    return {role: SecretStr(secrets.token_urlsafe(48)) for role in ci.LOGINS}


def test_local_execution_refused_before_docker_database_or_secret_generation(monkeypatch):
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    monkeypatch.setattr("sys.argv", ["ci", "--allow-ephemeral-ci-database"])
    monkeypatch.setattr(ci, "verify_dependencies", Mock())
    monkeypatch.setattr(ci, "docker", Mock(side_effect=AssertionError("No Docker")))
    monkeypatch.setattr(ci.psycopg, "connect", Mock(side_effect=AssertionError("No database")))
    monkeypatch.setattr(ci.secrets, "token_urlsafe", Mock(side_effect=AssertionError("No secrets")))
    with pytest.raises(AssertionError, match="GitHub-hosted Linux"):
        ci.main()
    ci.docker.assert_not_called()
    ci.psycopg.connect.assert_not_called()
    ci.secrets.token_urlsafe.assert_not_called()


@pytest.mark.parametrize("change", [{"RUNNER_ENVIRONMENT": "self-hosted"}, {"RUNNER_OS": "Windows"},
    {"PGPASSWORD": "SYNTHETIC_CANARY"}, {"PGSERVICE": "unexpected"}, {"RUNNER_TEMP": "relative"},
    {"DOCKER_HOST": "tcp://untrusted.invalid:2375"}, {"DOCKER_CONTEXT": "untrusted"}])
def test_ci_host_guard(monkeypatch, tmp_path, change):
    monkeypatch.setattr(ci.sys, "platform", "linux")
    for name, value in {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted",
                        "RUNNER_OS": "Linux", "RUNNER_TEMP": str(tmp_path)}.items():
        monkeypatch.setenv(name, value)
    for name, value in change.items():
        monkeypatch.setenv(name, value)
    with pytest.raises(AssertionError):
        ci.require_ci()


def test_dependency_only_mode_never_activates_database_mode(monkeypatch):
    monkeypatch.setattr("sys.argv", ["ci", "--verify-dependencies"])
    monkeypatch.setattr(ci, "version", lambda name: ci.EXPECTED[name])
    guard = Mock(side_effect=AssertionError("No CI activation"))
    monkeypatch.setattr(ci, "require_ci", guard)
    ci.main()
    guard.assert_not_called()


def test_wrong_dependency_version_fails(monkeypatch):
    monkeypatch.setattr(ci, "version", lambda _: "wrong")
    with pytest.raises(AssertionError, match="dependency version mismatch"):
        ci.verify_dependencies()


def test_lock_composition_pins_all_required_dependencies_without_changing_versions():
    def pins(path):
        result = {}
        raw = path.read_bytes()
        # The existing root lock is UTF-16 with BOM; preserve it unchanged.
        text = raw.decode("utf-16" if raw.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-8-sig")
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("-r "):
                nested = pins((path.parent/line[3:]).resolve())
                assert all(name not in result or result[name] == value for name, value in nested.items())
                result.update(nested)
            elif line and not line.startswith("#"):
                name, value = line.split("==")
                assert name not in result or result[name] == value
                result[name] = value
        return result
    locked = pins(ci.ROOT/"backend/voting/requirements.lock.txt")
    assert all(locked[name] == value for name, value in ci.EXPECTED.items())
    assert locked == pins(ci.ROOT/"backend/ra/credential-requirements.lock.txt")


def test_docker_error_output_is_not_disclosed(monkeypatch, capsys):
    monkeypatch.setattr(ci, "require_ci", Mock())
    run = Mock(return_value=SimpleNamespace(returncode=1, stdout="SYNTHETIC_CANARY", stderr="SYNTHETIC_CANARY"))
    monkeypatch.setattr(ci.subprocess, "run", run)
    with pytest.raises(AssertionError) as caught:
        ci.docker("inspect", "a"*64)
    assert "SYNTHETIC_CANARY" not in str(caught.value)+capsys.readouterr().out
    assert run.call_args.args[0][:3] == ["docker", "--host", "unix:///var/run/docker.sock"]


def container_info():
    return {"Id": "a"*64, "Name": "/owned", "Config": {"Image": ci.POSTGRES_IMAGE,
            "Labels": {"secure-evoting-voting-ci": "marker"}},
        "HostConfig": {"PortBindings": {"5432/tcp": [{"HostIp": "127.0.0.1"}]},
                       "Tmpfs": {"/var/lib/postgresql": "rw", "/run/evote-secrets": "rw"},
                       "Privileged": False, "NetworkMode": "bridge"}, "Mounts": [],
        "NetworkSettings": {"Ports": {"5432/tcp": [{"HostIp": "127.0.0.1", "HostPort": "35432"}]}}}


@pytest.mark.parametrize("change", ["name", "label", "image", "address", "extra-port", "volume", "bind", "privileged", "host-network", "missing-tmpfs"])
def test_container_ownership_and_mount_proof(monkeypatch, change):
    info = container_info()
    if change == "name": info["Name"] = "/other"
    elif change == "label": info["Config"]["Labels"] = {}
    elif change == "image": info["Config"]["Image"] = "postgres:latest"
    elif change == "address": info["HostConfig"]["PortBindings"]["5432/tcp"][0]["HostIp"] = "0.0.0.0"
    elif change == "extra-port": info["HostConfig"]["PortBindings"]["5433/tcp"] = []
    elif change in ("volume", "bind"): info["Mounts"] = [{"Type": change}]
    elif change == "privileged": info["HostConfig"]["Privileged"] = True
    elif change == "host-network": info["HostConfig"]["NetworkMode"] = "host"
    else: info["HostConfig"]["Tmpfs"] = {}
    monkeypatch.setattr(ci, "docker", Mock(return_value=json.dumps([info])))
    with pytest.raises(AssertionError):
        ci.owned_container("a"*64, "owned", "marker")


def test_tmpfs_secret_uses_stdin_and_exact_owned_container_is_removed_after_failure(monkeypatch):
    monkeypatch.setattr(ci, "require_ci", Mock())
    commands = []
    def docker(*args, **kwargs):
        commands.append((args, kwargs))
        return "a"*64 if args[0] == "run" else ""
    monkeypatch.setattr(ci, "docker", docker)
    proof = Mock(return_value=container_info())
    monkeypatch.setattr(ci, "owned_container", proof)
    with pytest.raises(RuntimeError, match="injected"):
        with ci.ephemeral_postgres() as (selected, secret):
            selected.validate()
            assert secret.get_secret_value() not in str([args for args, _ in commands])
            writes = [(args, kwargs) for args, kwargs in commands if args[0] == "exec"]
            assert len(writes) == 1 and writes[0][1]["input_text"] == secret.get_secret_value()
            run = next(args for args, _ in commands if args[0] == "run")
            assert "--tmpfs" in run and "--mount" not in run and "--volume" not in run
            assert "127.0.0.1::5432" in run and not any(arg.startswith("POSTGRES_PASSWORD=") for arg in run)
            raise RuntimeError("injected")
    assert commands[-1][0] == ("rm", "--force", "--volumes", "a"*64)
    assert proof.call_count == 2


def test_connections_are_marked_loopback_only_and_never_accept_user_database_names(monkeypatch):
    monkeypatch.setattr(ci, "require_ci", Mock())
    conn = Mock()
    connect = Mock(return_value=conn)
    marker = Mock()
    monkeypatch.setattr(ci.psycopg, "connect", connect)
    monkeypatch.setattr(integration, "verify_database", marker)
    selected = target()
    ci.connect(selected, "voting_ballot_login", SecretStr("SYNTHETIC"))
    kwargs = connect.call_args.kwargs
    assert kwargs["dbname"] == selected.database and kwargs["host"] == "127.0.0.1"
    assert kwargs["port"] == selected.port and kwargs["user"] == "voting_ballot_login"
    marker.assert_called_once_with(conn, selected.database, selected.marker)
    for database in ("ra_db", "voting_db", "voting_demo_test_not_ci"):
        with pytest.raises(AssertionError):
            ci.connect(ci.Target(database, str(uuid4()), 35432), "postgres", SecretStr("SYNTHETIC"))
    with pytest.raises(AssertionError):
        ci.connect(selected, "voting_owner", SecretStr("SYNTHETIC"))
    with pytest.raises(AssertionError):
        ci.connect(selected, "voting_ballot_login", SecretStr("SYNTHETIC"), maintenance=True)
    assert connect.call_count == 1


def test_wrong_marker_closes_connection(monkeypatch):
    monkeypatch.setattr(ci, "require_ci", Mock())
    conn = Mock()
    monkeypatch.setattr(ci.psycopg, "connect", Mock(return_value=conn))
    monkeypatch.setattr(integration, "verify_database", Mock(side_effect=AssertionError("marker")))
    with pytest.raises(AssertionError, match="marker"):
        ci.connect(target(), "voting_ballot_login", SecretStr("SYNTHETIC"))
    conn.close.assert_called_once()


def test_bootstrap_roles_memberships_and_test_only_password_authentication(monkeypatch):
    monkeypatch.setattr(ci, "require_ci", Mock())
    admin, setup = MagicMock(), MagicMock()
    for conn in (admin, setup): conn.__enter__.return_value = conn
    admin.execute.return_value.fetchone.side_effect = [("postgres", "postgres", "postgres"), ("180007",), None]
    setup.execute.return_value.fetchone.return_value = (0,)
    connector = Mock(side_effect=[admin, setup, ci.psycopg.OperationalError("SYNTHETIC_CANARY")])
    monkeypatch.setattr(ci, "connect", connector)
    ci.bootstrap_database(target(), SecretStr("SYNTHETIC_BOOTSTRAP"), passwords())
    statements = [str(call.args[0]) for call in admin.execute.call_args_list]
    assert sum("CREATE ROLE" in value for value in statements) == 10
    assert "GRANT voting_owner TO voting_migrator_login WITH INHERIT FALSE, SET TRUE" in statements
    assert "GRANT voting_ballot_service TO voting_ballot_login WITH INHERIT TRUE, SET FALSE" in statements
    assert not any("voting_owner TO voting_ballot_login" in value for value in statements)
    assert any("COMMENT ON DATABASE" in value for value in statements)
    assert any("CONNECTION LIMIT" in value and "Literal(40)" in value for value in statements)


def test_freshness_guard_rejects_existing_non_system_database(monkeypatch):
    monkeypatch.setattr(ci, "require_ci", Mock())
    admin = MagicMock()
    admin.__enter__.return_value = admin
    admin.execute.return_value.fetchone.side_effect = [("postgres", "postgres", "postgres"), ("180007",), (1,)]
    monkeypatch.setattr(ci, "connect", Mock(return_value=admin))
    with pytest.raises(AssertionError, match="Nonfresh"):
        ci.bootstrap_database(target(), SecretStr("SYNTHETIC_BOOTSTRAP"), passwords())
    assert not any("CREATE ROLE" in str(call.args[0]) for call in admin.execute.call_args_list)


def test_trust_authentication_is_refused(monkeypatch):
    monkeypatch.setattr(ci, "require_ci", Mock())
    admin, setup, wrong = MagicMock(), MagicMock(), MagicMock()
    for conn in (admin, setup): conn.__enter__.return_value = conn
    admin.execute.return_value.fetchone.side_effect = [("postgres", "postgres", "postgres"), ("180007",), None]
    setup.execute.return_value.fetchone.return_value = (0,)
    monkeypatch.setattr(ci, "connect", Mock(side_effect=[admin, setup, wrong]))
    with pytest.raises(AssertionError, match="Incorrect CI password"):
        ci.bootstrap_database(target(), SecretStr("SYNTHETIC_BOOTSTRAP"), passwords())
    wrong.close.assert_called_once()


def test_real_migration_chain_uses_only_existing_guarded_environment(monkeypatch):
    monkeypatch.setattr(ci, "require_ci", Mock())
    engine = MagicMock()
    connection = engine.begin.return_value.__enter__.return_value
    selected = target()
    connection.exec_driver_sql.return_value.one.return_value = (selected.database, "voting_migrator_login", "voting_migrator_login", 5432)
    connection.exec_driver_sql.return_value.scalar_one.return_value = 0
    monkeypatch.setattr(ci, "create_engine", Mock(return_value=engine))
    marker = Mock()
    monkeypatch.setattr(integration, "verify_database", marker)
    def upgrade(config, head):
        assert head == "d8f27a4c610b"
        assert Path(config.get_main_option("script_location")) == ci.ROOT/"scripts/ci_voting_migrations"
        assert Path(config.get_main_option("version_locations")) == ci.ROOT/"migrations/voting/versions"
        assert config.get_main_option("sqlalchemy.url") is None
        assert config.attributes == {"connection": connection, "disposable_database": selected.database,
                                     "disposable_marker": selected.marker}
    monkeypatch.setattr(ci.command, "upgrade", Mock(side_effect=upgrade))
    ci.migrate(selected, SecretStr("SYNTHETIC"))
    ci.command.upgrade.assert_called_once()
    marker.assert_called_once_with(connection.connection.driver_connection, selected.database, selected.marker)
    engine.dispose.assert_called_once()


@pytest.mark.parametrize("leftovers", [False, True])
def test_actual_harness_entrypoint_receives_only_in_memory_passwords_and_checks_cleanup(monkeypatch, leftovers):
    monkeypatch.setattr(ci, "require_ci", Mock())
    selected, generated = target(), passwords()
    conn = MagicMock()
    conn.__enter__.return_value = conn
    conn.execute.return_value.fetchone.return_value = (ci.HEAD,)
    monkeypatch.setattr(integration, "factory", Mock(return_value=lambda: conn))
    monkeypatch.setattr(integration, "main", Mock())
    before = {table: [] for table in ci.TABLES}
    after = {**before, "accepted_ballots": ["leftover"]} if leftovers else before
    monkeypatch.setattr(ci, "snapshot", Mock(side_effect=[before, after]))
    if leftovers:
        with pytest.raises(AssertionError, match="cleanup"):
            ci.run_harness(selected, generated)
    else:
        ci.run_harness(selected, generated)
    args = integration.main.call_args.kwargs
    assert selected.database in args["argv"] and selected.marker in args["argv"]
    assert all(value.get_secret_value() not in str(args["argv"]) for value in generated.values())
    assert args["password_prompt"]("fixture") is generated["voting_migrator_login"]
    assert args["password_prompt"]("runtime") is generated["voting_ballot_login"]


def test_password_adapter_retains_all_manual_safety_checks(monkeypatch):
    selected, generated = target(), passwords()
    collector = Mock(side_effect=[generated[role] for role in ci.LOGINS])
    monkeypatch.setattr(integration, "factory", Mock())
    monkeypatch.setattr(integration, "run", Mock())
    args = ["--allow-disposable-database", "--database", selected.database, "--marker", selected.marker,
            "--port", str(selected.port)]
    integration.main(argv=args, password_prompt=collector)
    assert collector.call_count == 2
    integration.run.assert_called_once()
    args[2] = "voting_db"
    collector.reset_mock()
    with pytest.raises(SystemExit):
        integration.main(argv=args, password_prompt=collector)
    collector.assert_not_called()


def test_lock_observation_refreshes_activity_snapshot_without_releasing_transaction(monkeypatch):
    conn = Mock()
    conn.execute.return_value.fetchone.side_effect = [(False,), (True,)]
    monkeypatch.setattr(integration.time, "sleep", Mock())
    integration.await_lock_wait(conn, 1234)
    calls = conn.execute.call_args_list
    assert len(calls) == 4
    assert calls[0].args[0] == calls[2].args[0] == "SELECT pg_catalog.pg_stat_clear_snapshot()"
    assert "pg_blocking_pids" in calls[1].args[0] and "pg_blocking_pids" in calls[3].args[0]
    conn.commit.assert_not_called()
    conn.rollback.assert_not_called()


def test_workflow_is_branch_scoped_locked_hosted_and_contains_no_secrets_or_uploads():
    workflow = yaml.safe_load((ci.ROOT/".github/workflows/voting-postgres-integration.yml").read_text())
    assert workflow["on"]["push"]["branches"] == ["feat/anonymous-voting-backend"]
    assert workflow["permissions"] == {"contents": "read"}
    job = workflow["jobs"]["voting-postgres-integration"]
    assert job["runs-on"] == "ubuntu-24.04" and "feat/anonymous-voting-backend" in job["if"]
    assert "continue-on-error" not in job
    assert all(not step.get("continue-on-error") for step in job["steps"])
    assert not any("upload-artifact" in step.get("uses", "") for step in job["steps"])
    assert "secrets." not in str(workflow)
    commands = "\n".join(step.get("run", "") for step in job["steps"])
    assert "pip install --no-deps -r backend/voting/requirements.lock.txt" in commands
    assert "-m pip check" in commands and "--verify-dependencies" in commands
    assert "--allow-ephemeral-ci-database" in commands
    assert "pytest tests/ crypto_interop/ -q" in commands
    for step in job["steps"]:
        if "uses" in step:
            assert len(step["uses"].split("@")[1]) == 40


@pytest.mark.parametrize("state", [None, "42501", "P4204", "unsafe\nSYNTHETIC_CANARY"])
def test_error_diagnostics_do_not_reveal_secret_text(state):
    error = RuntimeError("password query SYNTHETIC_CANARY")
    error.sqlstate = state
    message = ci.failure_message(error)
    assert "SYNTHETIC_CANARY" not in message and "password" not in message and "query" not in message
    assert ("SQLSTATE" in message) == (state in ("42501", "P4204"))
