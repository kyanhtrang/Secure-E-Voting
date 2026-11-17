"""Database-free tests of the REAL gate's safety boundary, not E2E PASS evidence."""

from contextlib import contextmanager
import io
import json
from pathlib import Path
from unittest.mock import MagicMock, Mock
from uuid import uuid4

import pytest
import yaml

from scripts import real_voting_e2e as gate


def test_local_entrypoint_fails_before_files_processes_or_database(monkeypatch, capsys):
    monkeypatch.setattr(gate.sys, "platform", "win32")
    monkeypatch.setattr(gate.sys, "argv", ["gate", "--allow-ephemeral-ci-databases",
        "--node", "never-open", "--signer-binary", "never-open"])
    connect = Mock(side_effect=AssertionError("Must not connect"))
    spawn = Mock(side_effect=AssertionError("Must not spawn"))
    monkeypatch.setattr(gate.psycopg,"connect",connect)
    monkeypatch.setattr(gate.subprocess,"Popen",spawn)
    with pytest.raises(SystemExit) as caught: gate.main()
    assert str(caught.value) == "FAIL: real_voting_e2e stage=preflight category=assertion_error sqlstate=unavailable"
    connect.assert_not_called(); spawn.assert_not_called()
    assert "never-open" not in capsys.readouterr().out


@pytest.mark.parametrize("key,value", [("PGHOST","untrusted"),("DOCKER_HOST","untrusted"),
    ("RA_DEMO_DB_PASSWORD","SECRET_CANARY"),("VITE_ENABLE_VOTING","true")])
def test_inherited_connection_or_service_configuration_refused(monkeypatch,tmp_path,key,value):
    monkeypatch.setattr(gate.sys,"platform","linux")
    for name in list(gate.os.environ):
        if name.startswith(("PG","DOCKER_","RA_DEMO_","VOTING_DEMO_","VITE_")):
            monkeypatch.delenv(name)
    for name,val in {"GITHUB_ACTIONS":"true","RUNNER_ENVIRONMENT":"github-hosted",
        "RUNNER_OS":"Linux","RUNNER_TEMP":str(tmp_path),key:value}.items():monkeypatch.setenv(name,val)
    with pytest.raises(AssertionError):gate.require_ci()


def target():
    return gate.ra_ci.Target("ra_demo_test_ci_"+uuid4().hex,str(uuid4()),23456)


@pytest.mark.parametrize("field,replacement", [(0,"ra_db"),(1,"ra_owner"),(2,"ra_owner"),
    (3,"postgres"),(4,"wrong marker"),(5,170000)])
def test_every_runtime_connection_rechecks_database_owner_marker_role_and_version(monkeypatch,field,replacement):
    monkeypatch.setattr(gate,"require_ci",lambda:None)
    selected=target()
    row=[selected.database,"ra_auth_login","ra_auth_login","ra_owner",
         "secure-evoting-disposable:"+selected.marker,180000]
    row[field]=replacement
    conn=Mock();conn.execute.return_value.fetchone.return_value=tuple(row)
    with pytest.raises(AssertionError):
        gate.guarded(lambda:conn,selected,"ra_owner","ra_auth_login")()
    conn.close.assert_called_once()


def test_fixture_can_only_switch_to_its_expected_owner(monkeypatch):
    monkeypatch.setattr(gate,"require_ci",lambda:None)
    selected=target();conn=Mock()
    conn.execute.return_value.fetchone.return_value=(selected.database,"ra_migrator_login","ra_owner",
        "ra_owner","secure-evoting-disposable:"+selected.marker,180001)
    assert gate.guarded(lambda:conn,selected,"ra_owner","ra_migrator_login",fixture=True)() is conn
    conn.close.assert_not_called()


def test_guard_refuses_host_before_calling_underlying_factory(monkeypatch):
    def refuse():raise AssertionError("Hosted only")
    monkeypatch.setattr(gate,"require_ci",refuse)
    connect=Mock()
    with pytest.raises(AssertionError):gate.guarded(connect,target(),"ra_owner","ra_auth_login")()
    connect.assert_not_called()


@pytest.mark.parametrize("extra", ["auth_password","issuance_password","encrypted_key","unlock","auth_config"])
def test_voting_process_configuration_refuses_ra_credentials_and_key_material(extra):
    selected=gate.vote_ci.Target("voting_demo_test_ci_"+uuid4().hex,str(uuid4()),23456)
    config={"target":vars(selected),"pin":gate.b64encode(bytes(32)),"password":"synthetic"}
    assert gate.service_configuration("voting",config)[0]==selected
    with pytest.raises(AssertionError):gate.service_configuration("voting",{**config,extra:"SECRET_CANARY"})


def test_voting_process_cannot_be_configured_for_ra_database():
    with pytest.raises(AssertionError):gate.service_configuration("voting",{
        "target":vars(target()),"pin":gate.b64encode(bytes(32)),"password":"synthetic"})


def test_service_child_mode_keeps_readiness_stdout_free_of_dependency_logs(monkeypatch):
    monkeypatch.setattr(gate.sys,"argv",["gate","--allow-ephemeral-ci-databases","--serve-role","voting"])
    monkeypatch.setattr(gate,"require_ci",Mock())
    monkeypatch.setattr(gate.signal,"signal",Mock())
    monkeypatch.setattr(gate.logging,"disable",Mock())
    verify=Mock();serve=Mock()
    monkeypatch.setattr(gate.vote_ci,"verify_dependencies",verify)
    monkeypatch.setattr(gate,"serve",serve)
    gate.main()
    serve.assert_called_once_with("voting");verify.assert_not_called()


@pytest.mark.parametrize("event", ["done","unknown","failure","duplicate"])
def test_browser_protocol_cannot_skip_assertions_or_emit_untrusted_diagnostics(monkeypatch,event,capsys):
    messages=[{"event":"done"}] if event=="done" else (
        [{"event":"failure","stage":"SECRET_CANARY"}] if event=="failure" else
        [{"event":"catalogue"},{"event":"catalogue"}] if event=="duplicate" else [{"event":"SECRET_CANARY"}])
    process=Mock(stdin=io.StringIO(),stdout=io.StringIO(''.join(json.dumps(m)+'\n' for m in messages)))
    process.wait.return_value=0
    @contextmanager
    def child(*_args,**_kwargs):yield process
    monkeypatch.setattr(gate,"child",child)
    monkeypatch.setattr(gate,"assert_database",Mock())
    with pytest.raises(AssertionError):gate.browser(Path("node"),{"scenario":"accepted"},None,None,None,["browser"])
    assert "SECRET_CANARY" not in capsys.readouterr().out


def test_fixed_diagnostics_never_include_exception_text_or_unknown_stage():
    error=RuntimeError("password=SECRET_CANARY bearer=SECRET_CANARY")
    assert gate.failure("SECRET_CANARY",error) == "FAIL: real_voting_e2e stage=preflight category=unexpected_error sqlstate=unavailable"


def test_child_cleanup_terminates_process_and_closes_pipes_even_on_failure(monkeypatch):
    process=Mock(stdin=io.StringIO(),stdout=io.StringIO())
    process.poll.return_value=None
    monkeypatch.setattr(gate.subprocess,"Popen",Mock(return_value=process))
    with pytest.raises(AssertionError):
        with gate.child(["test-tool"]):raise AssertionError("Injected child failure")
    process.terminate.assert_called_once()
    process.wait.assert_called_once_with(timeout=10)
    assert process.stdin.closed and process.stdout.closed


def test_cleanup_is_uuid_scoped_and_rechecked_in_new_transactions(monkeypatch):
    ra_conn,vote_conn=MagicMock(),MagicMock()
    ra_conn.__enter__.return_value=ra_conn;vote_conn.__enter__.return_value=vote_conn
    db=Mock(ra_fixture=Mock(return_value=ra_conn),voting_fixture=Mock(return_value=vote_conn))
    ra_snapshot=Mock(return_value={});vote_snapshot=Mock(return_value={})
    monkeypatch.setattr(gate.ra_ci,"snapshot",ra_snapshot)
    monkeypatch.setattr(gate.vote_ci,"snapshot",vote_snapshot)
    voter,election=uuid4(),uuid4()
    gate.cleanup(db,voter,election)
    assert db.ra_fixture.call_count==db.voting_fixture.call_count==2
    assert ra_snapshot.call_count==vote_snapshot.call_count==2
    for call in ra_conn.execute.call_args_list:
        query,parameters=call.args
        assert "WHERE" in query and (parameters==([voter],) or parameters==(election,))
    assert len(vote_conn.execute.call_args_list)==4
    for call in vote_conn.execute.call_args_list:
        assert "WHERE election_id=%s" in call.args[0] and call.args[1]==(election,)


@pytest.mark.parametrize("mode", ["query_denied","success","factory_denied","unexpected"])
def test_negative_acl_probe_requires_actual_42501_and_rolls_back_unexpected_success(mode):
    conn=MagicMock();conn.__enter__.return_value=conn
    factory=Mock(return_value=conn)
    if mode=="query_denied":conn.execute.side_effect=gate.psycopg.errors.InsufficientPrivilege()
    elif mode=="factory_denied":factory.side_effect=gate.psycopg.errors.InsufficientPrivilege()
    elif mode=="unexpected":conn.execute.side_effect=RuntimeError("SECRET_CANARY")
    if mode=="query_denied":gate.deny(factory,"DELETE FROM private_table")
    else:
        with pytest.raises((AssertionError,RuntimeError)):gate.deny(factory,"DELETE FROM private_table")
    if mode=="success":assert conn.__exit__.call_args.args[0] is AssertionError


def test_new_workflow_requires_all_regression_and_real_gate_steps_and_only_public_artifacts():
    config=yaml.safe_load((gate.ROOT/".github/workflows/real-voting-e2e.yml").read_text())
    assert config["permissions"]=={"contents":"read"}
    job=config["jobs"]["real-voting-e2e"]
    assert job["runs-on"]=="ubuntu-24.04"
    steps=job["steps"]; commands='\n'.join(step.get("run","") for step in steps)
    for required in ("-m pytest tests/ crypto_interop/ -q","npm run test:browser","npm run test:voting-browser",
        "npm test","npm run build","go test -count=1 ./...","./cmd/ra-credential-signer",
        "scripts/real_voting_e2e.py","--allow-ephemeral-ci-databases"):
        assert required in commands
    assert not any(step.get("continue-on-error") for step in steps)
    upload=steps[-1]
    assert upload["with"]["path"]=="${{ runner.temp }}/real-voting-preview/*.png"
    assert "always()" not in str(upload)
    assert upload["with"]["if-no-files-found"]=="error"
    driver=(gate.ROOT/"frontend/tests/real-voting.mjs").read_text()
    assert "route.fulfill" not in driver and "generateKey" not in driver
    assert "trace:" not in driver and "recordVideo" not in driver
    assert "route.fetch()" in driver and "route.abort('failed')" in driver


def test_first_publication_triggers_only_the_exact_feature_branch_push_or_manual_dispatch():
    config=yaml.safe_load((gate.ROOT/".github/workflows/real-voting-e2e.yml").read_text())
    assert set(config["on"])=={"push","workflow_dispatch"}
    assert config["on"]["push"]=={"branches":["feat/voter-voting-ui"]}
    assert not config["on"]["workflow_dispatch"]  # No database/credential/target inputs.
    job=config["jobs"]["real-voting-e2e"]
    assert "if" not in job and "needs" not in job


def test_runner_python_path_is_initialized_on_runner_before_subsequent_steps():
    config=yaml.safe_load((gate.ROOT/".github/workflows/real-voting-e2e.yml").read_text())
    job=config["jobs"]["real-voting-e2e"]
    assert "EVOTE_TEST_PYTHON" not in job["env"]
    assert not any("${{" in str(value) for value in job["env"].values())
    install=next(step for step in job["steps"] if step.get("name")=="Install and verify locked dependencies")
    script=install["run"]
    assert 'e2e_python="$RUNNER_TEMP/real-e2e-python/bin/python"' in script
    assert "printf 'EVOTE_TEST_PYTHON=%s\\n'" in script and '>> "$GITHUB_ENV"' in script
    assert '"$e2e_python" -m pip' in script
    assert '"$EVOTE_TEST_PYTHON"' not in script  # GITHUB_ENV applies only to later steps.
    assert job["steps"].index(install) < next(i for i,step in enumerate(job["steps"])
        if '"$EVOTE_TEST_PYTHON"' in step.get("run",""))
