"""Database-free tests of CI confinement. Every database/Docker call is a double."""
import json
from pathlib import Path
import ast
import runpy
import secrets
from types import SimpleNamespace
from unittest.mock import MagicMock,Mock
from uuid import uuid4

import pytest
from pydantic import SecretStr
import yaml

from scripts import ra_gate2_ci as ci
from scripts import ra_credential_disposable_integration as integration


def target():
    return ci.Target("ra_demo_test_ci_"+uuid4().hex,str(uuid4()),35432)


def passwords():
    return {role:SecretStr(secrets.token_urlsafe(48)) for role in ci.LOGINS}


def test_coordinator_refuses_local_execution_before_docker_or_credentials(monkeypatch):
    monkeypatch.delenv("GITHUB_ACTIONS",raising=False)
    monkeypatch.setattr(ci,"docker",Mock(side_effect=AssertionError("Docker forbidden")))
    monkeypatch.setattr(ci.psycopg,"connect",Mock(side_effect=AssertionError("Database forbidden")))
    monkeypatch.setattr("sys.argv",["ci","--allow-ephemeral-ci-database","--signer-binary","fake","--node","fake"])
    with pytest.raises(AssertionError,match="GitHub-hosted Linux"):
        ci.main()
    ci.docker.assert_not_called()
    ci.psycopg.connect.assert_not_called()


@pytest.mark.parametrize("change",[{"RUNNER_ENVIRONMENT":"self-hosted"},{"RUNNER_OS":"Windows"},
    {"PGPASSWORD":"synthetic-canary"},{"RUNNER_TEMP":"relative"},{"DOCKER_HOST":"tcp://untrusted.invalid:2375"}])
def test_host_guard_rejects_unsafe_environments(monkeypatch,tmp_path,change):
    monkeypatch.setattr(ci.sys,"platform","linux")
    for name,value in {"GITHUB_ACTIONS":"true","RUNNER_ENVIRONMENT":"github-hosted","RUNNER_OS":"Linux",
                       "RUNNER_TEMP":str(tmp_path)}.items():
        monkeypatch.setenv(name,value)
    for name,value in change.items():
        monkeypatch.setenv(name,value)
    with pytest.raises(AssertionError):
        ci.require_ci()


def test_docker_uses_only_hosted_local_daemon_and_hides_error_output(monkeypatch,capsys):
    monkeypatch.setattr(ci,"require_ci",Mock())
    run=Mock(return_value=SimpleNamespace(returncode=1,stdout="synthetic-private-canary",stderr="synthetic-private-canary"))
    monkeypatch.setattr(ci.subprocess,"run",run)
    with pytest.raises(AssertionError,match="Ephemeral Docker operation failed") as caught:
        ci.docker("inspect","a"*64)
    assert run.call_args.args[0][:3]==["docker","--host","unix:///var/run/docker.sock"]
    assert "synthetic-private-canary" not in str(caught.value)
    assert "synthetic-private-canary" not in capsys.readouterr().out


def test_target_cannot_redirect_to_existing_database(monkeypatch):
    connector=Mock()
    monkeypatch.setattr(ci.psycopg,"connect",connector)
    for database in ("ra_db","voting_db","ra_demo_test_not_ci"):
        with pytest.raises(AssertionError):
            ci.connect(ci.Target(database,str(uuid4()),35432),"postgres",SecretStr("synthetic"))
    connector.assert_not_called()


def test_connect_is_loopback_fixed_roles_and_explicit_password_only(monkeypatch):
    connector=Mock()
    monkeypatch.setattr(ci.psycopg,"connect",connector)
    selected=target()
    password=SecretStr(secrets.token_urlsafe(48))
    ci.connect(selected,"ra_issuance_login",password)
    values=connector.call_args.kwargs
    assert values["host"]=="127.0.0.1" and values["port"]==selected.port
    assert values["dbname"]==selected.database and values["user"]=="ra_issuance_login"
    assert values["password"]==password.get_secret_value() and values["sslmode"]=="disable"
    with pytest.raises(AssertionError):
        ci.connect(selected,"ra_owner",password)
    with pytest.raises(AssertionError):
        ci.connect(selected,"ra_migrator_login",password,database="ra_db")
    assert connector.call_count==1


def container_info():
    return {"Id":"a"*64,"Name":"/owned","Config":{"Labels":{"secure-evoting-gate2":"marker"},
        "Image":ci.POSTGRES_IMAGE},"HostConfig":{"PortBindings":{"5432/tcp":[{"HostIp":"127.0.0.1"}]}},
        "NetworkSettings":{"Ports":{"5432/tcp":[{"HostIp":"127.0.0.1","HostPort":"35432"}]}}}


@pytest.mark.parametrize("field",["name","label","image","address","extra_port"])
def test_container_proof_rejects_unowned_or_exposed_service(monkeypatch,field):
    info=container_info()
    if field=="name": info["Name"]="/unrelated"
    if field=="label": info["Config"]["Labels"]={}
    if field=="image": info["Config"]["Image"]="postgres:latest"
    if field=="address": info["NetworkSettings"]["Ports"]["5432/tcp"][0]["HostIp"]="0.0.0.0"
    if field=="extra_port": info["HostConfig"]["PortBindings"]["5433/tcp"]=[]
    monkeypatch.setattr(ci,"docker",Mock(return_value=json.dumps([info])))
    with pytest.raises(AssertionError):
        ci.container_port("a"*64,"owned","marker")


def test_ephemeral_password_not_in_command_and_owned_container_is_cleaned(monkeypatch,tmp_path):
    monkeypatch.setattr(ci,"require_ci",lambda:tmp_path)
    commands=[]
    def docker(*args,**kwargs):
        commands.append(args)
        return "a"*64 if args[0]=="run" else ""
    monkeypatch.setattr(ci,"docker",docker)
    proof=Mock(return_value=35432)
    monkeypatch.setattr(ci,"container_port",proof)
    with pytest.raises(RuntimeError,match="injected"):
        with ci.ephemeral_postgres() as (selected,password):
            selected.validate()
            secret_file=next(tmp_path.glob("evote-gate2-ci-*/bootstrap-password"))
            assert secret_file.read_text()==password.get_secret_value()
            assert password.get_secret_value() not in str(commands)
            assert "POSTGRES_PASSWORD=" not in str(commands)
            assert "127.0.0.1::5432" in str(commands)
            raise RuntimeError("injected")
    assert commands[-1]==("rm","--force","--volumes","a"*64)
    assert proof.call_count==2
    assert not list(tmp_path.glob("evote-gate2-ci-*"))


def test_provisioning_is_generated_roles_and_marked_database_without_runtime_owner_membership(monkeypatch):
    selected=target(); generated=passwords()
    admin,setup,runtime=MagicMock(),MagicMock(),MagicMock()
    for conn in (admin,setup,runtime): conn.__enter__.return_value=conn
    admin.execute.return_value.fetchone.side_effect=[("postgres","postgres","postgres"),("180007",),None]
    setup.execute.return_value.fetchone.return_value=(0,)
    runtime.execute.return_value.fetchone.return_value=(selected.database,"ra_issuance_login","ra_issuance_login")
    wrong=ci.psycopg.OperationalError("sanitized test error")
    connector=Mock(side_effect=[admin,setup,wrong,runtime])
    monkeypatch.setattr(ci,"connect",connector)
    monkeypatch.setattr(ci,"require_ci",Mock())
    marker=Mock()
    monkeypatch.setattr(ci,"verify_disposable_database",marker)
    ci.bootstrap_database(selected,SecretStr("synthetic-bootstrap"),generated)
    statements=[str(call.args[0]) for call in admin.execute.call_args_list]
    assert any("CREATE DATABASE" in statement for statement in statements)
    assert any("COMMENT ON DATABASE" in statement for statement in statements)
    assert sum("CREATE ROLE" in statement for statement in statements)==8
    assert [value for value in statements if value.startswith("GRANT ra_owner")]==[
        "GRANT ra_owner TO ra_migrator_login WITH INHERIT FALSE, SET TRUE"]
    assert not any("ra_owner TO ra_issuance_login" in value or "ra_owner TO ra_auth_login" in value for value in statements)
    assert marker.call_count==2


def test_provisioning_fails_if_wrong_password_is_accepted(monkeypatch):
    selected=target()
    admin,setup,wrong=MagicMock(),MagicMock(),MagicMock()
    for conn in (admin,setup): conn.__enter__.return_value=conn
    admin.execute.return_value.fetchone.side_effect=[("postgres","postgres","postgres"),("180007",),None]
    setup.execute.return_value.fetchone.return_value=(0,)
    monkeypatch.setattr(ci,"connect",Mock(side_effect=[admin,setup,wrong]))
    monkeypatch.setattr(ci,"require_ci",Mock())
    monkeypatch.setattr(ci,"verify_disposable_database",Mock())
    with pytest.raises(AssertionError,match="Incorrect CI password"):
        ci.bootstrap_database(selected,SecretStr("synthetic-bootstrap"),passwords())
    wrong.close.assert_called_once()


def test_real_alembic_chain_uses_ci_environment_and_shared_guarded_connection(monkeypatch):
    selected=target()
    engine=MagicMock(); connection=engine.begin.return_value.__enter__.return_value
    connection.exec_driver_sql.return_value.one.return_value=(selected.database,"ra_migrator_login","ra_migrator_login",5432)
    connection.exec_driver_sql.return_value.scalar_one.return_value=0
    monkeypatch.setattr(ci,"require_ci",Mock())
    monkeypatch.setattr(ci,"create_engine",Mock(return_value=engine))
    marker=Mock(); monkeypatch.setattr(ci,"verify_disposable_database",marker)
    def upgrade(config,head):
        assert head==ci.HEAD and Path(config.get_main_option("script_location"))==ci.ROOT/"scripts/ci_ra_migrations"
        assert Path(config.get_main_option("version_locations"))==ci.ROOT/"migrations/ra/versions"
        assert config.attributes["connection"] is connection
        assert config.get_main_option("sqlalchemy.url") is None
        config.attributes["disposable_connection_guard"](connection)
    command=Mock(side_effect=upgrade); monkeypatch.setattr(ci.command,"upgrade",command)
    ci.migrate(selected,SecretStr("synthetic-migrator"))
    command.assert_called_once()
    marker.assert_called_once_with(connection.connection.driver_connection,selected.database,selected.marker)
    engine.dispose.assert_called_once()


def test_ci_alembic_environment_requires_connection_and_guard(monkeypatch):
    from alembic import context
    config=SimpleNamespace(attributes={})
    monkeypatch.setattr(context,"config",config,raising=False)
    monkeypatch.setattr(context,"is_offline_mode",lambda:False)
    with pytest.raises(RuntimeError,match="Verified disposable CI connection"):
        runpy.run_path(str(ci.ROOT/"scripts/ci_ra_migrations/env.py"))


def test_ci_alembic_environment_checks_guard_before_role_switch_or_ddl(monkeypatch):
    from alembic import context
    connection=Mock()
    guard=Mock(side_effect=AssertionError("wrong database marker"))
    monkeypatch.setattr(context,"config",SimpleNamespace(attributes={"connection":connection,
                        "disposable_connection_guard":guard}),raising=False)
    monkeypatch.setattr(context,"is_offline_mode",lambda:False)
    with pytest.raises(AssertionError,match="marker"):
        runpy.run_path(str(ci.ROOT/"scripts/ci_ra_migrations/env.py"))
    connection.exec_driver_sql.assert_not_called()


def test_manual_harness_in_memory_password_adapter_preserves_target_validation(monkeypatch):
    generated=passwords(); selected=target()
    prompt=Mock(side_effect=[generated["ra_issuance_login"],generated["ra_migrator_login"]])
    fixture_factory=Mock(); runtime_factory=Mock(); exercise=Mock()
    monkeypatch.setattr(integration,"database_factory",fixture_factory)
    monkeypatch.setattr(integration,"issuance_factory",runtime_factory)
    monkeypatch.setattr(integration,"exercise",exercise)
    arguments=["--disposable-fixture-writes","--database",selected.database,"--disposable-marker",selected.marker,
        "--port",str(selected.port),"--node","test-node","--signer-binary","test-signer"]
    integration.main(argv=arguments,password_prompt=prompt)
    assert fixture_factory.call_args.args==(generated["ra_migrator_login"],)
    assert runtime_factory.call_args.args==(generated["ra_issuance_login"],)
    exercise.assert_called_once()
    arguments[2]="ra_db"
    prompt.reset_mock()
    with pytest.raises(AssertionError): integration.main(argv=arguments,password_prompt=prompt)
    prompt.assert_not_called()


def test_ci_cleanup_check_detects_leftovers_and_preserves_unrelated_rows(monkeypatch):
    selected=target(); generated=passwords(); conn=MagicMock()
    conn.__enter__.return_value=conn
    conn.execute.return_value.fetchone.side_effect=[(ci.HEAD,),None]
    monkeypatch.setattr(ci,"require_ci",Mock())
    monkeypatch.setattr(integration,"database_factory",Mock(return_value=lambda:conn))
    harness=Mock(); monkeypatch.setattr(integration,"main",harness)
    monkeypatch.setattr(ci,"snapshot",Mock(side_effect=[{}, {"sentinel":[1]}, {"sentinel":[1],"leaked":[2]}]))
    with pytest.raises(AssertionError,match="cleanup"):
        ci.run_harness(selected,generated,Path("test-signer"),Path("test-node"))
    argv=harness.call_args.kwargs["argv"]
    assert selected.database in argv and selected.marker in argv
    assert all(value.get_secret_value() not in str(argv) for value in generated.values())


def test_committed_cleanup_success_requires_identical_sentinel_snapshot(monkeypatch):
    selected=target(); generated=passwords(); conn=MagicMock()
    conn.__enter__.return_value=conn
    conn.execute.return_value.fetchone.side_effect=[(ci.HEAD,),None]
    monkeypatch.setattr(ci,"require_ci",Mock())
    monkeypatch.setattr(integration,"database_factory",Mock(return_value=lambda:conn))
    harness=Mock(); monkeypatch.setattr(integration,"main",harness)
    monkeypatch.setattr(ci,"snapshot",Mock(side_effect=[{}, {"sentinel":[1]}, {"sentinel":[1]}]))
    ci.run_harness(selected,generated,Path("test-signer"),Path("test-node"))
    provider=harness.call_args.kwargs["password_prompt"]
    assert provider("runtime") is generated["ra_issuance_login"]
    assert provider("fixture") is generated["ra_migrator_login"]


def test_dedicated_postgres_job_waits_for_crypto_and_never_uploads_generated_secrets():
    workflow=yaml.safe_load((ci.ROOT/".github/workflows/rsabssa-interop.yml").read_text(encoding="utf8"))
    assert workflow["permissions"]=={"contents":"read"}
    job=workflow["jobs"]["ra-postgres-integration"]
    assert job["needs"]=="crypto-interop" and job["runs-on"]=="ubuntu-24.04"
    assert "feat/ra-credential-issuance-recovery" in job["if"]
    steps=job["steps"]
    command="\n".join(step.get("run","") for step in steps)
    assert "scripts/ra_gate2_ci.py" in command and "--allow-ephemeral-ci-database" in command
    assert "alembic -c alembic_ra.ini" not in command and "PGPASSWORD" not in command
    assert "continue-on-error" not in job and all(not step.get("continue-on-error",False) for step in steps)
    assert not any("upload-artifact" in step.get("uses","") for step in steps)
    assert "secrets." not in str(job)


@pytest.mark.parametrize("state",[None,"42501","P0001","unsafe-sensitive-error\ncanary"])
def test_ci_failures_report_only_sanitized_sqlstate(state):
    error=RuntimeError("synthetic sensitive query/password canary")
    error.sqlstate=state
    text=ci.failure_message(error)
    assert "canary" not in text and "password" not in text and "query" not in text
    assert "SQLSTATE" in text if state in ("42501","P0001") else "SQLSTATE" not in text


def test_forward_migration_only_corrects_legacy_varchar_result_expression():
    versions=ci.ROOT/"migrations/ra/versions"
    def definition(path):
        tree=ast.parse(path.read_text(encoding="utf8"))
        return next(node.args[0].value for node in ast.walk(tree)
            if isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute) and node.func.attr=="execute"
            and node.args and isinstance(node.args[0],ast.Constant)
            and "FUNCTION ra_credential._request(" in str(node.args[0].value))
    original=definition(versions/"7b2d91a6c840_ra_credential_reservations.py")
    corrected=definition(versions/"c84e13b9702d_ra_credential_result_type.py")
    assert corrected.replace("CREATE OR REPLACE FUNCTION","CREATE FUNCTION").replace(
        "b.storage_key_id::text","b.storage_key_id")==original
    source=(versions/"c84e13b9702d_ra_credential_result_type.py").read_text(encoding="utf8")
    assert 'down_revision="7b2d91a6c840"' in source
    assert "GRANT " not in source and "CREATE TABLE" not in source and "CREATE ROLE" not in source
    assert "a.grantee<>p.proowner" in source and "Forward-only" in source
    baseline=(versions/"e52b0a9227ef_create_ra_schema_baseline.py").read_text(encoding="utf8")
    assert "storage_key_id VARCHAR(128)" in baseline


def test_ci_and_manual_harness_require_same_corrected_migration_head():
    assert ci.HEAD==integration.HEAD=="c84e13b9702d"
