"""Database-free composition regressions; not evidence of a real hosted E2E PASS."""
import ast
from contextlib import contextmanager
from copy import deepcopy
import io
import json
from pathlib import Path
import re
from unittest.mock import Mock
from uuid import uuid4

import httpx
import pytest
import rfc8785
import yaml

from scripts import full_election_e2e as gate
from tests.board_helpers import evidence


def test_local_refusal_happens_before_credentials_keys_docker_or_processes(monkeypatch):
    monkeypatch.setattr(gate.sys,"platform","win32")
    connect,read,docker,spawn = Mock(),Mock(),Mock(),Mock()
    monkeypatch.setattr(gate.guard.psycopg,"connect",connect)
    monkeypatch.setattr(Path,"read_bytes",read)
    monkeypatch.setattr(gate.real.vote_ci,"docker",docker)
    monkeypatch.setattr(gate.real.subprocess,"Popen",spawn)
    with pytest.raises(SystemExit) as result:
        gate.main(["--allow-ephemeral-ci-databases","--node","unopened","--signer-binary","unopened"])
    assert str(result.value) == "FAIL: full_election_e2e stage=preflight category=assertion_error sqlstate=unavailable"
    for call in (connect,read,docker,spawn): call.assert_not_called()


@pytest.mark.parametrize("prefix",["BOARD_DEMO_","PUBLICATION_DEMO_"])
def test_inherited_publication_destinations_are_refused(prefix,monkeypatch,tmp_path):
    monkeypatch.setattr(gate.journey,"require_ci",lambda:tmp_path)
    monkeypatch.setenv(prefix+"PASSWORD","SECRET_CANARY")
    with pytest.raises(AssertionError): gate.require_ci()


@pytest.mark.parametrize("role,field",[("board","key"),("board","unlock"),("board","evidence"),("board","ra"),
    ("publisher","tally_key"),("publisher","auth_password"),("publisher","authority_key")])
def test_child_rejects_cross_service_key_and_database_fields_before_io(role,field,monkeypatch,tmp_path):
    monkeypatch.setattr(gate,"require_ci",lambda:tmp_path)
    designated=Mock();monkeypatch.setattr(gate.guard,"designated",designated)
    with pytest.raises(AssertionError): gate.configuration(role,dict.fromkeys(gate.FIELDS[role]|{field},"SECRET_CANARY"))
    designated.assert_not_called()


@pytest.mark.parametrize("database",["ra_db","voting_db","voting_demo_test_wrong"])
def test_disposable_guard_still_rejects_unowned_destinations(database):
    with pytest.raises(AssertionError): gate.guard.designated("voting",dict(database=database,marker=str(uuid4()),port=12345,
        container_id="a"*64,container_name="evote-voting-ci-"+"b"*32))


def test_provisioning_verifies_ownership_before_creating_roles_then_reuses_reviewed_chain(monkeypatch):
    events=[]
    owned=Mock();owned.verify.side_effect=lambda:events.append("verified")
    monkeypatch.setattr(gate.guard.admin_ci,"provision_role",lambda *args:events.append(args[-2]))
    monkeypatch.setattr(gate.board_ci,"migrate",lambda *args:events.append("migrated"))
    passwords={"voting_migrator_login":gate.SecretStr("synthetic-only")}
    stage=["preflight"]
    gate.Publication(stage).provision(owned,gate.SecretStr("synthetic-bootstrap"),passwords)
    assert events == ["verified","voting_publication_login","voting_board_login","migrated"]
    assert stage == ["publication_migration"]
    assert all(isinstance(p,gate.SecretStr) for p in passwords.values())


def test_child_protocol_is_private_bounded_and_always_shutdown(monkeypatch):
    monkeypatch.setattr(gate,"configuration",Mock())
    process=Mock(stdin=io.StringIO(),stdout=io.StringIO('{"origin":"http://127.0.0.1:12345"}\n'))
    process.wait.return_value=0
    commands=[]
    @contextmanager
    def child(command,**kwargs): commands.append(command);yield process
    monkeypatch.setattr(gate.real,"child",child)
    with pytest.raises(RuntimeError):
        with gate.service_process("publisher",{"synthetic":"SECRET_CANARY"}) as origin:
            assert origin == "http://127.0.0.1:12345"
            raise RuntimeError("SECRET_CANARY")
    assert process.stdin.getvalue() == '{"synthetic":"SECRET_CANARY"}\n{"stop":true}\n'
    assert "SECRET_CANARY" not in json.dumps(commands)
    process.wait.assert_called_once_with(timeout=25)


def test_http_clients_do_not_inherit_proxy_redirects_cookies_or_identity(monkeypatch):
    original=httpx.Client
    seen=[]
    def respond(request):
        seen.append(request)
        return httpx.Response(200,headers={"Cache-Control":"no-store","Set-Cookie":"identity=canary"},content=b'{"ok":true}')
    factories=[]
    def client(**kwargs):
        factories.append(kwargs)
        return original(transport=httpx.MockTransport(respond),**kwargs)
    monkeypatch.setattr(gate.httpx,"Client",client)
    assert gate.http("http://127.0.0.1:12345","/api/v1/board") == {"ok":True}
    gate.http("http://127.0.0.1:12345","/api/v1/board")
    assert all(not kw["trust_env"] and not kw["follow_redirects"] for kw in factories)
    assert all("cookie" not in req.headers and "authorization" not in req.headers for req in seen)


@pytest.mark.parametrize("status",[401,409,500,599])
def test_http_failure_is_fixed_and_allowlisted_without_body(monkeypatch,status):
    original=httpx.Client
    monkeypatch.setattr(gate.httpx,"Client",lambda **kwargs:original(transport=httpx.MockTransport(
        lambda request:httpx.Response(status,content=b'SECRET_CANARY')),**kwargs))
    with pytest.raises(AssertionError) as result: gate.http("http://127.0.0.1:12345","/api/v1/board")
    output=gate.failure("public_verification",result.value)
    assert "SECRET_CANARY" not in output
    assert "http_status="+str(status if status in gate.real.HTTP_STATUSES else "unavailable") in output


def test_public_response_size_is_bounded(monkeypatch):
    original=httpx.Client
    monkeypatch.setattr(gate,"MAX_BYTES",16)
    monkeypatch.setattr(gate.httpx,"Client",lambda **kwargs:original(transport=httpx.MockTransport(
        lambda request:httpx.Response(200,headers={"Cache-Control":"no-store"},content=b'"'+b'a'*16+b'"')),**kwargs))
    with pytest.raises(AssertionError): gate.http("http://127.0.0.1:12345","/api/v1/board")


def test_independent_verification_uses_existing_real_signatures_and_rejects_all_negative_copies(tmp_path,monkeypatch):
    value=evidence(tmp_path)
    extension=gate.Publication(["preflight"])
    extension.directory,extension.trust,extension.election=tmp_path,value.trust,value.election
    extension.trust_config=dict(authority=gate.b64encode(value.trust.authority),evidence=gate.b64encode(value.trust.evidence),
        evidence_key_id=value.trust.evidence_key_id,publication=gate.b64encode(value.trust.publication),publication_key_id=value.trust.publication_key_id)
    calls=[]
    def run(command,**kwargs):
        # Exercise the actual existing CLI parser/verifier, without starting a DB.
        from scripts.verify_publication import main
        capture=io.StringIO()
        from contextlib import redirect_stdout
        with redirect_stdout(capture): status=main(command[2:])
        calls.append(command)
        return Mock(returncode=status,stdout=capture.getvalue(),stderr="")
    monkeypatch.setattr(gate.real.subprocess,"run",run)
    receipts=[r["receipt_hash"] for r in value.bundle["snapshot"]["ballots"]][:2]
    extension.independent_checks(value.bundle,receipts)
    assert len(calls) == 2
    assert all("--trusted-keys" in call for call in calls)
    assert (tmp_path/"public-trust.json").read_bytes() == rfc8785.dumps(extension.trust_config)
    assert (tmp_path/"public-bundle.json").read_bytes() == rfc8785.dumps(value.bundle)


def test_assertion_diagnostics_and_checkpoints_cannot_echo_arbitrary_data(capsys):
    assert gate.failure("SECRET_CANARY",RuntimeError("SECRET_CANARY")) == "FAIL: full_election_e2e stage=preflight category=unexpected_error sqlstate=unavailable"
    with pytest.raises(AssertionError): gate.checkpoint("SECRET_CANARY",["preflight"])
    assert capsys.readouterr().out == ""


def test_extension_does_not_change_default_gate_and_publishes_before_original_browser_recovery():
    import inspect
    assert inspect.signature(gate.journey.run).parameters["publication"].default is None
    source=inspect.getsource(gate.journey.run)
    assert source.index("tally_ci.migrate(") < source.index("publication.provision(") < source.index("guard.create_election(")
    assert source.index("published.reject_voter(") < source.index("receipt = browsers.enter_context(")
    assert source.index('checkpoint("configuration_rejected")') < source.index("published.finish(") < source.index('stage[0] = "receipts"')
    tree=ast.parse(Path(gate.__file__).read_text(encoding="utf8"))
    strings=[n.value.lower() for n in ast.walk(tree) if isinstance(n,ast.Constant) and isinstance(n.value,str)]
    assert not any("insert into voting.accepted_ballots" in s for s in strings)
    assert "tally_ci.seed" not in Path(gate.__file__).read_text(encoding="utf8")
    assert not {"key","unlock","evidence"} & gate.FIELDS["board"]


def test_workflow_is_scoped_pinned_and_requires_all_regressions_before_full_election():
    text=(gate.ROOT/".github/workflows/full-election-e2e.yml").read_text(encoding="utf8")
    workflow=yaml.safe_load(text)
    assert workflow["on"] == {"push":{"branches":["test/full-election-e2e"]},"workflow_dispatch":None}
    assert workflow["permissions"] == {"contents":"read"}
    job=workflow["jobs"]["full-election-e2e"]
    assert job["runs-on"] == "ubuntu-24.04"
    scripts=[s.get("run","") for s in job["steps"]]
    index=next(i for i,s in enumerate(scripts) if "scripts/full_election_e2e.py" in s)
    for command in ("go test -count=1 ./...","crypto_interop/gate.py","-m pytest tests/ crypto_interop/ -q","pending_state.test.js","npm test",
        "npm run check","npm run build","test:browser","test:voting-browser","test:admin-browser","test:tally-browser","test:board-browser",
        "scripts/tally_postgres_ci.py --allow-ephemeral-ci-database","scripts/board_postgres_ci.py --allow-ephemeral-ci-database"):
        assert any(command in script for script in scripts[:index])
    assert "secrets." not in text and "upload-artifact" not in text and "continue-on-error" not in text
    assert all(len(step["uses"].split("@")[1]) == 40 for step in job["steps"] if "uses" in step)
    assert any(step.get("if") == "always()" for step in job["steps"])


def test_acl_assertion_matches_each_actual_reviewed_function_search_path():
    # Cross-check the runtime ACL assertion against the actual unchanged revision,
    # rather than incorrectly assuming every function has the same search path.
    source=ast.parse(Path(gate.__file__).read_text(encoding="utf8"))
    method=next(n for n in ast.walk(source) if isinstance(n,ast.FunctionDef) and n.name == "acl")
    assignment=next(n for n in ast.walk(method) if isinstance(n,ast.Assign) and isinstance(n.targets[0],ast.Name) and n.targets[0].id == "paths")
    expected=eval(compile(ast.Expression(assignment.value),"<test-paths>","eval"),{"__builtins__":{},"dict":dict})
    migration=gate.ROOT/"migrations/board/versions/f8b31c2d970a_publication_board.py"
    actual=dict(re.findall(r"CREATE FUNCTION voting_board\.(\w+)\([^\n]*\nSET search_path=([^\n]+?) AS",migration.read_text(encoding="utf8")))
    assert set(actual) == set(expected)
    assert {k:v.replace(" ","") for k,v in expected.items()} == actual
