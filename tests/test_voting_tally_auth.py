"""Database-free RPC-client/HTTP safety regressions, NOT PostgreSQL E2E evidence.

The RPC double models a contract to test argument binding and error handling.
Actual SQL/ACL/TTL behavior is asserted by check_authentication/check_acl in CI.
"""
from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import secrets
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock
from uuid import uuid4

from fastapi.testclient import TestClient
import pytest

from backend.ra.auth_service import AuthenticationDenied
from backend.ra.credential_service import IssuedCredential
from backend.ra.demo_session_service import DemoSessionService
from backend.ra.session_service import InvalidRASession, RASessionRecord
from scripts import voting_tally_auth as auth, voting_tally_e2e as gate


class RPC:
    def __init__(self):
        self.identities = {subject:uuid4() for subject in auth.SUBJECTS}
        self.records, self.calls = {}, []

    @contextmanager
    def connect(self): yield self

    def execute(self, query, params):
        self.calls.append((query,params))
        voter = params[0]
        if "find_voter" in query:
            row = (voter if params[1] == "demo-local" and self.identities.get(params[2]) == voter else None,)
        elif "issue_session" in query:
            if voter not in self.identities.values(): row = (False,)
            else:
                now = datetime.now(timezone.utc)
                self.records[params[1]] = RASessionRecord(params[1],voter,now,now+timedelta(minutes=15))
                row = (True,)
        else:
            record = self.records.get(params[1])
            own = record is not None and record.voter_id == voter
            if "find_session" in query:
                row = (record.voter_id,record.created_at,record.expires_at,record.revoked_at) if own else None
            elif "revoke_session" in query:
                row = (own and record.revoked_at is None,)
                if row[0]: self.records[params[1]] = replace(record,revoked_at=datetime.now(timezone.utc))
            else: raise AssertionError("Unexpected RPC")
        return Mock(fetchone=Mock(return_value=row))


def make_clients(monkeypatch,tmp_path):
    monkeypatch.setattr(gate,"require_ci",lambda:tmp_path)
    rpc, rows = RPC(), []
    for subject in auth.SUBJECTS:
        password,env = gate.real.synthetic_environment(gate.SecretStr("synthetic-only"))
        env.update(RA_DEMO_SUBJECT=subject,RA_DEMO_USERNAME="synthetic-"+subject)
        service = Mock()
        service.issue.return_value = IssuedCredential(secrets.token_bytes(384),"unit-test-only",False)
        config = dict(auth_config=env,election_id=str(uuid4()),voter_id=str(rpc.identities[subject]))
        app = gate.ra_app(config,rpc.connect,service,bytes(32))
        client = TestClient(app,base_url="http://127.0.0.1",client=("127.0.0.1",45000))
        response = client.post("/api/v1/ra/auth/login",json={"username":env["RA_DEMO_USERNAME"],"password":password})
        assert response.status_code == 200
        rows.append((client,response.json()["access_token"],rpc.identities[subject],service))
    return rpc,rows


def header(token): return {"Authorization":"Bearer "+token}


def request_body():
    return dict(election_id=str(uuid4()),request_id=str(uuid4()),blinded_msg=gate.b64encode(bytes(384)))


def test_two_actual_authentication_services_bind_distinct_rpc_identities_and_ascii_digests(monkeypatch,tmp_path):
    rpc,rows = make_clients(monkeypatch,tmp_path)
    assert rows[0][1] != rows[1][1] and rows[0][2] != rows[1][2]
    for client,token,voter,_ in rows:
        response = client.get("/api/v1/ra/auth/me",headers=header(token))
        assert response.status_code == 200 and response.json() == {"voter_id":str(voter)}
        digest = hashlib.sha256(token.encode("ascii")).hexdigest()
        assert digest in rpc.records and rpc.records[digest].voter_id == voter
        assert rpc.records[digest].expires_at-rpc.records[digest].created_at == timedelta(minutes=15)
        assert any("issue_session" in query and params == (voter,digest) for query,params in rpc.calls)
        assert all(token not in str(params) for _,params in rpc.calls)


def test_cross_voter_me_logout_catalogue_and_issuance_fail_without_delegation(monkeypatch,tmp_path):
    _,rows = make_clients(monkeypatch,tmp_path)
    for i,(client,token,voter,service) in enumerate(rows):
        other = rows[1-i][1]
        for path in ("auth/me","elections"):
            assert client.get("/api/v1/ra/"+path,headers=header(other)).status_code == 401
        assert client.post("/api/v1/ra/auth/logout",headers=header(other)).status_code == 401
        assert client.post("/api/v1/ra/credentials/issue",headers=header(other),json=request_body()).status_code == 401
        service.issue.assert_not_called()
        assert client.get("/api/v1/ra/auth/me",headers=header(token)).json() == {"voter_id":str(voter)}


@pytest.mark.parametrize("expired",[False,True])
def test_expired_or_revoked_sessions_cannot_resolve_or_reach_issuance(expired,monkeypatch,tmp_path):
    rpc,rows = make_clients(monkeypatch,tmp_path)
    for client,token,_,service in rows:
        if expired:
            digest = DemoSessionService._digest(token)
            now = datetime.now(timezone.utc)
            rpc.records[digest] = replace(rpc.records[digest],created_at=now-timedelta(minutes=16),expires_at=now-timedelta(minutes=1))
        else:
            assert client.post("/api/v1/ra/auth/logout",headers=header(token)).status_code == 204
            assert rpc.records[DemoSessionService._digest(token)].revoked_at is not None
        assert client.get("/api/v1/ra/auth/me",headers=header(token)).status_code == 401
        assert client.post("/api/v1/ra/credentials/issue",headers=header(token),json=request_body()).status_code == 401
        service.issue.assert_not_called()


def test_both_bound_issuance_adapters_delegate_original_blinded_bytes_only_for_their_own_tokens(monkeypatch,tmp_path):
    _,rows = make_clients(monkeypatch,tmp_path)
    for client,token,_,service in rows:
        body = request_body()
        assert client.post("/api/v1/ra/credentials/issue",headers=header(token),json=body).status_code == 201
        args = service.issue.call_args.args
        assert args[0] == token and args[1:3] == (gate.UUID(body["election_id"]),gate.UUID(body["request_id"]))
        assert args[3] == bytes(384)  # No digest substituted for blinded bytes.


def test_third_identity_and_wrong_voter_issuance_rejected_without_session_write():
    rpc = RPC()
    voter = rpc.identities[auth.SUBJECTS[0]]
    store = auth.SessionStore(rpc.connect,voter,auth.SUBJECTS[0])
    assert store.find_active_voter_id("demo-local","demo-voter-003") is None
    with pytest.raises(AuthenticationDenied): store.issue_ra_session(uuid4())
    third = auth.SessionStore(rpc.connect,uuid4(),auth.SUBJECTS[0])
    with pytest.raises(AuthenticationDenied): third.issue_ra_session(third.voter_id)
    with pytest.raises(ValueError): auth.SessionStore(rpc.connect,uuid4(),"demo-voter-003")
    assert not rpc.records


@pytest.mark.parametrize("token",["malformed","A"*42,"A"*43+"=","\u2603"*43])
def test_malformed_tokens_never_reach_rpc(token):
    connect = Mock()
    session = auth.BoundSessions(auth.SessionStore(connect,uuid4(),auth.SUBJECTS[0]))
    with pytest.raises(InvalidRASession): session.resolve_voter_id(token)
    with pytest.raises(InvalidRASession): session.revoke_ra_session(token)
    connect.assert_not_called()


def test_session_is_not_disclosed_if_commit_fails():
    conn = MagicMock();conn.__enter__.return_value=conn
    conn.execute.return_value.fetchone.return_value=(True,)
    conn.__exit__.side_effect=RuntimeError("SYNTHETIC_COMMIT_FAILURE")
    store = auth.SessionStore(Mock(return_value=conn),uuid4(),auth.SUBJECTS[0])
    with pytest.raises(RuntimeError,match="SYNTHETIC_COMMIT_FAILURE"): store.issue_ra_session(store.voter_id)


@pytest.mark.parametrize("bad",[None,(),(uuid4(),)])
def test_unexpected_identity_response_fails_closed(bad):
    conn = MagicMock();conn.__enter__.return_value=conn
    conn.execute.return_value.fetchone.return_value=bad
    store = auth.SessionStore(Mock(return_value=conn),uuid4(),auth.SUBJECTS[0])
    with pytest.raises(RuntimeError): store.find_active_voter_id("demo-local",auth.SUBJECTS[0])


def installation_fixture(monkeypatch):
    monkeypatch.setattr(auth.guard,"require_ci",Mock())
    target=SimpleNamespace(database="ra_demo_test_ci_"+uuid4().hex,marker=str(uuid4()))
    owned=SimpleNamespace(kind="ra",target=target,verify=Mock())
    conn=MagicMock();conn.__enter__.return_value=conn
    identity=(target.database,"ra_migrator_login","ra_owner","ra_owner","secure-evoting-disposable:"+target.marker,180000)
    return owned,conn,identity


@pytest.mark.parametrize("field",[0,1,2,3,4,5])
def test_installer_refuses_any_connection_identity_mismatch_before_ddl(monkeypatch,field):
    owned,conn,identity=installation_fixture(monkeypatch)
    row=list(identity);row[field]="UNEXPECTED" if field != 5 else 170000
    conn.execute.return_value.fetchone.return_value=tuple(row)
    with pytest.raises(AssertionError): auth.install(owned,Mock(return_value=conn),dict(zip(auth.SUBJECTS,(uuid4(),uuid4()))))
    assert conn.execute.call_count == 1
    assert "CREATE" not in conn.execute.call_args.args[0]
    assert conn.__exit__.call_args.args[0] is AssertionError


def test_container_refusal_prevents_fixture_connection(monkeypatch):
    owned,_,_=installation_fixture(monkeypatch)
    owned.verify.side_effect=AssertionError("Unowned container")
    fixture=Mock()
    with pytest.raises(AssertionError):auth.install(owned,fixture,dict(zip(auth.SUBJECTS,(uuid4(),uuid4()))))
    fixture.assert_not_called()


def test_installer_rejects_existing_schema_before_ddl(monkeypatch):
    owned,conn,identity=installation_fixture(monkeypatch)
    def execute(query,*params):
        if "current_database" in query:return Mock(fetchone=Mock(return_value=identity))
        if "version_num" in query:return Mock(fetchall=Mock(return_value=[("bf932d0f8702",)]))
        if "to_regnamespace" in query:return Mock(fetchone=Mock(return_value=("ra_e2e_auth",)))
        raise AssertionError("No DDL allowed")
    conn.execute.side_effect=execute
    with pytest.raises(AssertionError,match="Existing E2E schema refused"):
        auth.install(owned,Mock(return_value=conn),dict(zip(auth.SUBJECTS,(uuid4(),uuid4()))))


@pytest.mark.parametrize("unsafe",["definer","owner","search_path","execute_grant","table_grant","schema_grant"])
def test_acl_inspection_fails_closed_on_unsafe_definitions_or_default_grants(unsafe):
    conn=Mock()
    def execute(query):
        if "p.proname,p.prosecdef" in query:
            rows=[(name.split('(')[0],True,True,['search_path=pg_catalog, ra_e2e_auth, ra, pg_temp']) for name in auth.SIGNATURES]
            if unsafe in {"definer","owner","search_path"}:
                row=list(rows[0]);row[{"definer":1,"owner":2,"search_path":3}[unsafe]] = ['search_path=public'] if unsafe == "search_path" else False
                rows[0]=tuple(row)
            return Mock(fetchall=Mock(return_value=rows))
        bad=(unsafe == "execute_grant" and "pg_proc" in query
            or unsafe == "table_grant" and "pg_class" in query
            or unsafe == "schema_grant" and "SELECT count(*) FROM pg_namespace" in query)
        return Mock(fetchone=Mock(return_value=(int(bad),)))
    conn.execute.side_effect=execute
    with pytest.raises(AssertionError): auth.check_function_acl(conn)


def test_installation_rolls_back_all_fixture_ddl_if_final_acl_check_fails(monkeypatch):
    owned,conn,identity=installation_fixture(monkeypatch)
    identities=dict(zip(auth.SUBJECTS,(uuid4(),uuid4())))
    def execute(query,*params):
        if "current_database" in query:return Mock(fetchone=Mock(return_value=identity))
        if "version_num" in query:return Mock(fetchall=Mock(return_value=[("bf932d0f8702",)]))
        if "to_regnamespace" in query:return Mock(fetchone=Mock(return_value=(None,)))
        if "SELECT voter_id,auth_provider" in query:return Mock(fetchall=Mock(return_value=[(v,"demo-local",s,True) for s,v in identities.items()]))
        return Mock()
    conn.execute.side_effect=execute
    monkeypatch.setattr(auth,"check_function_acl",Mock(side_effect=AssertionError("Unsafe synthetic grant")))
    with pytest.raises(AssertionError):auth.install(owned,Mock(return_value=conn),identities)
    queries=[call.args[0] for call in conn.execute.call_args_list]
    assert auth.DDL in queries and queries.index(auth.DDL) == 4
    assert conn.__exit__.call_args.args[0] is AssertionError
    conn.commit.assert_not_called()


def test_all_new_rpc_grants_are_narrow_and_no_production_function_is_replaced():
    source=Path(auth.__file__).read_text(encoding="utf8")
    assert "CREATE OR REPLACE" not in auth.DDL and "CREATE ROLE" not in auth.DDL
    assert auth.DDL.count("SECURITY DEFINER SET search_path=pg_catalog,ra_e2e_auth,ra,pg_temp") == 4
    assert "REVOKE ALL ON ALL FUNCTIONS IN SCHEMA ra_e2e_auth FROM PUBLIC" in auth.DDL
    assert "GRANT USAGE ON SCHEMA ra_e2e_auth TO ra_auth_login" in auth.DDL
    assert "GRANT EXECUTE ON FUNCTION ra_e2e_auth." in source and '" TO ra_auth_login"' in source
    assert "GRANT SELECT" not in source and "GRANT INSERT" not in source
    assert "FOR SHARE OF v" in auth.DDL and "ra.create_session(digest,found_voter,created,created+interval '15 minutes')" in auth.DDL
    assert "s.voter_id=a.voter_id" in auth.DDL and "RETURN FOUND" in auth.DDL
    assert "has_function_privilege(current_user,p.oid,'EXECUTE')" in source and "guard.real.deny(factory,statement)" in source


@pytest.mark.parametrize("filename,expected",[
    ("f3c2a1d4e6b8_ra_demo_auth_e2e.py","c380db8fcafd4d476661445d6ebb65aea3d4c073d2424880724ff8c008b60a45"),
    ("a9c31d5e8b72_ra_demo_session_issuance.py","735850c30670e064d080e1228b2a1ce3a92066e4d1482200c81595d7389fbed9")])
def test_applied_demo_sql_remains_exactly_the_reviewed_single_subject_revision(filename,expected):
    text=(gate.ROOT/"migrations/ra/versions"/filename).read_text(encoding="utf8")
    assert hashlib.sha256(text.encode()).hexdigest() == expected  # Normalize checkout line endings.
    assert "demo-voter-001" in text and "demo-voter-002" not in text


def test_all_required_real_ci_authentication_assertions_and_fixed_checkpoints_are_wired():
    source=Path(gate.__file__).read_text(encoding="utf8")
    assert "e2e_auth.install(ra,db.ra_fixture" in source and "e2e_auth.check_authentication(voter_services" in source
    assert "e2e_auth.check_session(db.ra_fixture,voter,voter_token)" in source and "e2e_auth.check_acl(db.ra_auth" in source
    for stage in ("voter_a_authenticated","voter_b_authenticated","accepted_first","accepted_second"):
        assert stage in gate.STAGES
        assert "SECRET_CANARY" not in gate.failure(stage,RuntimeError("SECRET_CANARY"))
    tests=Path(auth.__file__).read_text(encoding="utf8")
    for required in ("demo-voter-003","SQL accepted cross-voter lookup","SQL accepted cross-voter revocation",
                     "Demo issuance boundary widened","Expiry fixture scope mismatch","DB revocation not committed"):
        assert required in tests
