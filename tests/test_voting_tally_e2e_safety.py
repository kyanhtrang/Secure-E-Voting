"""Database-free coordinator regressions; these are not real E2E evidence."""
from contextlib import contextmanager
from copy import deepcopy
import hashlib
import io
import json
from pathlib import Path
from unittest.mock import Mock
from uuid import uuid4

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
import pytest
import rfc8785
import yaml

from scripts import voting_tally_e2e as gate


def test_local_refusal_precedes_database_key_and_process_access(monkeypatch):
    monkeypatch.setattr(gate.sys, "platform", "win32")
    connect, spawn, read = Mock(), Mock(), Mock()
    monkeypatch.setattr(gate.guard.psycopg, "connect", connect)
    monkeypatch.setattr(gate.real.subprocess, "Popen", spawn)
    monkeypatch.setattr(Path, "read_bytes", read)
    with pytest.raises(SystemExit) as result:
        gate.main(["--allow-ephemeral-ci-databases", "--node", "unopened", "--signer-binary", "unopened"])
    assert str(result.value) == "FAIL: voting_tally_e2e stage=preflight category=assertion_error sqlstate=unavailable"
    connect.assert_not_called(); spawn.assert_not_called(); read.assert_not_called()


def test_inherited_tally_configuration_refused(monkeypatch, tmp_path):
    monkeypatch.setattr(gate.guard, "require_ci", lambda: tmp_path)
    monkeypatch.setenv("TALLY_DEMO_DB_PASSWORD", "SECRET_CANARY")
    with pytest.raises(AssertionError): gate.require_ci()


@pytest.mark.parametrize("name", ["ra_db", "voting_db", "voting_demo_test_invalid"])
def test_disposable_target_guards_preserved(name):
    with pytest.raises(AssertionError):
        gate.guard.designated("voting", dict(database=name, marker=str(uuid4()), port=23456,
            container_id="a"*64,container_name="evote-voting-ci-"+"b"*32))


@pytest.mark.parametrize("field", ["ra_password", "admin_password", "authority_key", "auth_config"])
def test_tally_rejects_cross_service_configuration_before_io(field, monkeypatch):
    read = Mock(); monkeypatch.setattr(Path,"read_bytes",read)
    with pytest.raises(AssertionError): gate.tally_configuration(dict.fromkeys(gate.TALLY_FIELDS | {field}, "SECRET_CANARY"))
    read.assert_not_called()


def test_retained_encrypted_tally_key_matches_approved_public_key(tmp_path):
    pin, snapshot_pin, catalogue, files = gate.keys(tmp_path)
    assert pin != snapshot_pin and set(files) == {"authority","ra","tally","snapshot"}
    for name, field in (("ra","ra_key"),("tally","tally_key")):
        path, password = files[name]
        encoded = path.read_bytes()
        assert encoded.startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----")
        with pytest.raises((ValueError,TypeError)): serialization.load_pem_private_key(encoded,password=None)
        private = serialization.load_pem_private_key(encoded,password=password.get_secret_value().encode())
        raw = gate.real.public(private)
        assert private.key_size == 3072 and private.public_key().public_numbers().e == 65537
        assert catalogue["accepted"][field]["spki"] == gate.b64encode(raw)
        assert catalogue["accepted"][field]["fingerprint"] == hashlib.sha256(raw).hexdigest()
    assert "PRIVATE" not in json.dumps(catalogue) and "unlock" not in json.dumps(catalogue)
    for role in ("admin","ra","voting"):
        assert not {"tally_key","tally_unlock","snapshot_key","snapshot_unlock"} & gate.guard.ROLE_FIELDS[role]


@pytest.mark.parametrize("subject",["demo-voter-001","demo-voter-002"])
def test_hosted_ra_composition_preserves_real_routers_sessions_and_both_fixture_identities(subject,monkeypatch,tmp_path):
    from backend.ra.login_router import get_ra_auth_service
    from backend.ra.demo_auth_runtime import compose_demo_services
    monkeypatch.setattr(gate,"require_ci",lambda:tmp_path)
    password,env=gate.real.synthetic_environment(gate.SecretStr("synthetic-only"))
    env["RA_DEMO_SUBJECT"]=subject
    connect=Mock()
    app=gate.ra_app(dict(auth_config=env,election_id=str(uuid4()),voter_id=str(uuid4())),connect,Mock(),bytes(32))
    auth=app.dependency_overrides[get_ra_auth_service]()
    identity=auth._service.verifier.verify_credentials(env["RA_DEMO_USERNAME"],password)
    assert identity.provider == "demo-local" and identity.subject == subject
    assert auth._service.verifier.verify_credentials(env["RA_DEMO_USERNAME"],password+"x") is None
    # FastAPI may retain included routers lazily; force construction through its TestClient.
    from fastapi.testclient import TestClient
    with TestClient(app,base_url="http://127.0.0.1",client=("127.0.0.1",45000)) as client:
        result=client.get("/api/v1/ra/auth/me")
        assert result.status_code == 401 and result.headers["cache-control"] == "no-store"
        result=client.post("/api/v1/ra/auth/login",json={"username":env["RA_DEMO_USERNAME"],"password":password+"x"})
        assert result.status_code == 401 and password not in result.text
    connect.assert_not_called()
    if subject == "demo-voter-002":
        with pytest.raises(ValueError): compose_demo_services(env,connection_factory=connect)


@pytest.mark.parametrize("field,value",[("RA_DEMO_SUBJECT","untrusted"),("RA_DEMO_PROVIDER","other"),("RA_DEMO_AUTH_ENABLED","false"),("RA_ENVIRONMENT","production")])
def test_hosted_ra_adapter_refuses_other_identity_or_nonlocal_activation(field,value,monkeypatch,tmp_path):
    monkeypatch.setattr(gate,"require_ci",lambda:tmp_path)
    _,env=gate.real.synthetic_environment(gate.SecretStr("synthetic-only"));env[field]=value
    connect=Mock()
    with pytest.raises((AssertionError,RuntimeError,ValueError)):
        gate.ra_app(dict(auth_config=env,election_id=str(uuid4())),connect,Mock(),bytes(32))
    connect.assert_not_called()


def test_private_pipe_stop_protocol_is_compact():
    process = Mock(stdin=io.StringIO())
    gate.send(process,{"stop":True})
    assert process.stdin.getvalue() == '{"stop":true}\n'


def test_browser_waits_for_committed_tally_before_receipt_recovery(monkeypatch):
    process = Mock(stdin=io.StringIO(),stdout=io.StringIO(json.dumps({"event":"accepted","receipt_hash":"a"*64})+'\n'+json.dumps({"event":"recovered"})+'\n'))
    process.wait.return_value = 0
    @contextmanager
    def child(*args,**kwargs): yield process
    monkeypatch.setattr(gate.real,"child",child)
    with gate.browser(Path("node"),{"origin":"http://127.0.0.1:12345"}) as receipt:
        assert receipt == "a"*64
        assert '"ok"' not in process.stdin.getvalue()
    assert process.stdin.getvalue().endswith('{"ok":true}\n')
    process.wait.assert_called_once()


def test_browser_abort_does_not_acknowledge_tally_success(monkeypatch):
    process = Mock(stdin=io.StringIO(),stdout=io.StringIO(json.dumps({"event":"accepted","receipt_hash":"a"*64})+'\n'))
    @contextmanager
    def child(*args,**kwargs): yield process
    monkeypatch.setattr(gate.real,"child",child)
    with pytest.raises(RuntimeError):
        with gate.browser(Path("node"),{}): raise RuntimeError("SECRET_CANARY")
    assert '"ok"' not in process.stdin.getvalue()


def test_tally_child_stops_even_when_parent_assertion_fails(monkeypatch):
    monkeypatch.setattr(gate,"tally_configuration",Mock())
    process=Mock(stdin=io.StringIO(),stdout=io.StringIO('{"origin":"http://127.0.0.1:12345"}\n'))
    process.wait.return_value=0
    commands=[]
    @contextmanager
    def child(command,**kwargs):
        commands.append(command)
        yield process
    monkeypatch.setattr(gate.real,"child",child)
    with pytest.raises(RuntimeError):
        with gate.tally_process({"synthetic":"SECRET_CANARY"}) as origin:
            assert origin == "http://127.0.0.1:12345"
            raise RuntimeError("SECRET_CANARY")
    assert process.stdin.getvalue().endswith('{"stop":true}\n')
    assert "SECRET_CANARY" in process.stdin.getvalue() and "SECRET_CANARY" not in json.dumps(commands)
    process.wait.assert_called_once()


@pytest.mark.parametrize("code", ["CONFLICT","UNAVAILABLE","SECRET_CANARY"])
def test_error_classification_must_match_without_echoing_response(code,monkeypatch):
    response=Mock(status_code=503,headers={"Cache-Control":"no-store"},content=json.dumps({"code":code,"detail":"SECRET_CANARY"}).encode())
    client=Mock();client.__enter__=Mock(return_value=client);client.__exit__=Mock(return_value=False)
    client.request.return_value=response
    monkeypatch.setattr(gate.httpx,"Client",Mock(return_value=client))
    with pytest.raises(AssertionError) as result:
        gate.tally_http("http://127.0.0.1:12345","elections/"+str(uuid4())+"/report",503,error_code="INTEGRITY")
    assert "SECRET_CANARY" not in str(result.value)


def test_error_classification_accepts_expected_sanitized_integrity_failure(monkeypatch):
    response=Mock(status_code=503,headers={"Cache-Control":"no-store"},content=b'{"code":"INTEGRITY","detail":"Restricted tally request rejected"}')
    client=Mock();client.__enter__=Mock(return_value=client);client.__exit__=Mock(return_value=False)
    client.request.return_value=response
    factory=Mock(return_value=client);monkeypatch.setattr(gate.httpx,"Client",factory)
    assert gate.tally_http("http://127.0.0.1:12345","elections/"+str(uuid4())+"/report",503,error_code="INTEGRITY") is None
    assert factory.call_args.kwargs["trust_env"] is False and factory.call_args.kwargs["follow_redirects"] is False


def test_browser_diagnostics_are_allowlisted(capsys):
    process=Mock(stdout=io.StringIO('{"event":"failure","stage":"issue"}\n'))
    with pytest.raises(AssertionError): gate.browser_event(process)
    assert capsys.readouterr().out == "FAIL: voting_tally_e2e browser_stage=issue\n"
    process=Mock(stdout=io.StringIO('{"event":"failure","stage":"SECRET_CANARY"}\n'))
    assert gate.browser_event(process)["stage"] == "SECRET_CANARY"
    assert capsys.readouterr().out == ""
    assert "SECRET_CANARY" not in gate.failure("SECRET_CANARY",RuntimeError("SECRET_CANARY"))


def aggregate():
    authority=ed25519.Ed25519PrivateKey.generate()
    election=uuid4()
    candidates=[{"candidate_id":str(uuid4()),"candidate_name":"Synthetic"} for _ in range(2)]
    candidates.sort(key=lambda c:c["candidate_id"])
    report=dict(report_version=1,election_id=str(election),election_config_digest="a"*64,snapshot_digest="b"*64,
        algorithm_version="evote-tally-v1",accepted_total=2,valid_total=2,invalid_total=0,counted_total=2,
        candidate_counts=[dict(candidate_id=c["candidate_id"],vote_count=1) for c in candidates],
        invalid_reasons=dict(KEY_WRAP=0,AEAD=0,PLAINTEXT=0))
    raw=rfc8785.dumps(report)
    result=dict(report=report,report_digest=hashlib.sha256(raw).hexdigest(),
        signature=gate.b64encode(authority.sign(b"EVOTE-TALLY-REPORT-v1\0"+raw)),signing_key_id="combined-test-snapshot",candidates=candidates)
    pin=authority.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
    return authority,election,candidates,result,pin


def test_aggregate_independently_verifies_signature_counts_and_context():
    _,election,candidates,result,pin=aggregate()
    gate.verify_report(result,election,"a"*64,candidates,pin)
    for field in ("signature","report_digest"):
        bad=deepcopy(result);bad[field]="A"*len(bad[field])
        with pytest.raises(Exception): gate.verify_report(bad,election,"a"*64,candidates,pin)
    with pytest.raises(AssertionError): gate.verify_report(result,uuid4(),"a"*64,candidates,pin)
    with pytest.raises(AssertionError): gate.verify_report(result,election,"c"*64,candidates,pin)


@pytest.mark.parametrize("change", ["accepted_total","candidate_counts","serial","plaintext","algorithm_version","report_version"])
def test_even_signed_wrong_counts_or_individual_data_are_rejected(change):
    authority,election,candidates,result,pin=aggregate()
    report=result["report"]
    if change == "accepted_total": report[change]=3
    elif change == "candidate_counts": report[change][0]["vote_count"]=2
    elif change == "algorithm_version": report[change]="unreviewed"
    elif change == "report_version": report[change]=True
    else: report[change]="SECRET_CANARY"
    raw=rfc8785.dumps(report)
    result.update(report_digest=hashlib.sha256(raw).hexdigest(),signature=gate.b64encode(authority.sign(b"EVOTE-TALLY-REPORT-v1\0"+raw)))
    with pytest.raises(AssertionError): gate.verify_report(result,election,"a"*64,candidates,pin)


def test_workflow_is_separate_scoped_and_runs_all_existing_regressions_first():
    text=(gate.ROOT/".github/workflows/voting-tally-integration.yml").read_text(encoding="utf8")
    workflow=yaml.safe_load(text)
    assert workflow["on"] == {"push":{"branches":["test/voting-tally-integration"]},"workflow_dispatch":None}
    assert workflow["permissions"] == {"contents":"read"}
    job=workflow["jobs"]["voting-tally-integration"]
    assert job["runs-on"] == "ubuntu-24.04"
    scripts=[s.get("run","") for s in job["steps"]]
    index=next(i for i,s in enumerate(scripts) if "scripts/voting_tally_e2e.py" in s)
    for command in ("go test -count=1 ./...","-m pytest tests/ crypto_interop/ -q","npm test","test:browser",
        "test:voting-browser","test:admin-browser","test:tally-browser","pending_state.test.js","npm run build"):
        assert any(command in s for s in scripts[:index])
    assert "secrets." not in text and "upload-artifact" not in text and "continue-on-error" not in text
    assert any("scripts/tally_postgres_ci.py --allow-ephemeral-ci-database" in s for s in scripts[:index])
    assert any(s.get("if")=="always()" for s in job["steps"])


def test_composition_has_no_ballot_seeding_or_production_overrides():
    source=(gate.ROOT/"scripts/voting_tally_e2e.py").read_text(encoding="utf8")
    driver=(gate.ROOT/"frontend/tests/real-voting-tally.mjs").read_text(encoding="utf8")
    assert source.count("ephemeral_postgres()") == 2
    assert "tally_ci.migrate(vt" in source and "guard.create_election(" in source
    import ast
    sql=[node.args[0].value.lower() for node in ast.walk(ast.parse(source))
        if isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute) and node.func.attr=="execute"
        and node.args and isinstance(node.args[0],ast.Constant) and isinstance(node.args[0].value,str)]
    assert not any("insert into voting.accepted_ballots" in query for query in sql)
    assert "tally_ci.seed" not in source
    assert '"INSERT INTO voting.accepted_ballots DEFAULT VALUES"' in source  # Explicit denial, never a fixture write.
    assert "real.deny(tally_ci.runtime" in source
    assert "private_key_reference" in source and "guard.publisher_denied(db)" in source
    assert 'for index, voter in enumerate((first,second))' in source
    for role in ("admin","voting"): assert 'guard.service_process("'+role+'"' in source
    assert "ra_process(dict(" in source and "real.LocalCIRCLSigner(" in source
    assert "route(" not in driver and "route.fulfill" not in driver and "screenshot" not in driver
    assert "credentials:'omit'" in driver and "ra_identity_canary" in driver
    assert "expect((await issued).status()).toBe(201)" in driver
    assert "expect(response.status()).toBe(201)" in driver
    assert "console.log" not in driver and "error.message" not in driver
