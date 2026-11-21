"""Catalogue-projection tests of the actual ACL assertions, never live PG evidence.

The data describes reviewed role/membership/function properties. Each negative
test changes a property and runs Publication.acl unchanged; direct SQL uses the
real strict deny helper against error/success outcomes, not a patched PASS.
"""
from contextlib import contextmanager
import re
from types import SimpleNamespace
from uuid import uuid4

import psycopg
import pytest

from scripts import full_election_e2e as gate


ROLES = ("voting_board_login", "voting_publication_login", "voting_admin_login", "voting_tally_login", "voting_ballot_login")
FORBIDDEN = {"SELECT * FROM voting.accepted_ballots", "DELETE FROM voting.publications",
    "SELECT * FROM voting_board.evidence", "SET ROLE voting_owner"}


class Result:
    def __init__(self, rows): self.rows = rows
    def fetchone(self): return self.rows[0] if self.rows else None
    def fetchall(self): return self.rows


class Catalogue:
    def __init__(self):
        self.principal = uuid4()
        # Exact projected tuples of real pg_roles / pg_auth_members columns.
        self.roles = {role:(role,True,True,role == "voting_ballot_login") for role in ROLES}
        self.memberships = {role:[] for role in ROLES}
        self.memberships["voting_ballot_login"] = [("voting_ballot_service","voting_ballot_login",False,True,False)]
        self.service = (True,True)
        self.create = dict.fromkeys(ROLES,0)
        self.execute = {role:[] for role in ROLES}
        self.execute["voting_board_login"] = [("read_public",),("catalogue",)]
        self.execute["voting_publication_login"] = [("publication_input",),("finish",)]
        migration = gate.ROOT/"migrations/board/versions/f8b31c2d970a_publication_board.py"
        paths = re.findall(r"CREATE FUNCTION voting_board\.(\w+)\([^\n]*\nSET search_path=([^\n]+?) AS",migration.read_text(encoding="utf8"))
        self.metadata = [(name,"voting_owner",True,["search_path="+path.replace(",",", ")]) for name,path in paths]
        assert len(self.metadata) == 8
        self.public = 0
        self.audit = [(self.principal,"ADMIN")]
        self.denials, self.transaction_errors, self.queries = [], [], []
        self.direct_outcome = psycopg.errors.InsufficientPrivilege

    @contextmanager
    def connect(self, role):
        try: yield Connection(self,role)
        except Exception as error:
            self.transaction_errors.append(type(error))
            raise

    def publication(self):
        publication = gate.Publication(["preflight"])
        publication.principal,publication.election = self.principal,uuid4()
        for field,role in zip(("reader","publisher","admin","tally"),ROLES):
            setattr(publication,field,lambda role=role:self.connect(role))
        publication.db = SimpleNamespace(voting_runtime=lambda:self.connect("voting_ballot_login"),
            voting_fixture=lambda:self.connect("fixture"))
        return publication


class Connection:
    def __init__(self, catalogue, role): self.data,self.role = catalogue,role
    def execute(self, query, parameters=None):
        data,role = self.data,self.role
        data.queries.append((role,query,parameters))
        if query in FORBIDDEN:
            data.denials.append((role,query))
            if data.direct_outcome is not None: raise data.direct_outcome("SECRET_CANARY")
            return Result([])  # An unauthorized success MUST fail the real deny helper.
        if query.startswith("SELECT current_user,rolcanlogin,"): return Result([data.roles[role]])
        if query.startswith("SELECT parent.rolname,child.rolname,"): return Result(data.memberships[role])
        if query.startswith("SELECT NOT(rolcanlogin OR rolinherit"): return Result([data.service])
        if query.startswith("SELECT count(*) FROM pg_namespace"): return Result([(data.create[role],)])
        if query.startswith("SELECT p.proname FROM pg_proc"): return Result(data.execute[role])
        if query.startswith("SELECT count(*) FROM pg_proc"): return Result([(data.public,)])
        if query.startswith("SELECT p.proname,pg_get_userbyid"): return Result(data.metadata)
        if query.startswith("SELECT actor_principal_id,actor_type"): return Result(data.audit)
        raise AssertionError("Unmodelled SQL contract")


def test_legitimate_restricted_roles_and_exact_ballot_membership_pass(capsys):
    data = Catalogue()
    publication = data.publication()
    publication.acl()
    assert capsys.readouterr().out == "PASS: full_election_e2e checkpoint=board_acl\n"
    assert set(data.denials) == {(role,query) for role in ROLES for query in FORBIDDEN}
    assert len(data.denials) == 20
    assert data.transaction_errors == [psycopg.errors.InsufficientPrivilege]*20
    # The old assertion rejected this reviewed, deliberately inherited capability.
    assert data.roles["voting_ballot_login"][-1] is True
    assert data.memberships["voting_ballot_login"]


def reject(data, identifier):
    publication = data.publication()
    with pytest.raises(AssertionError) as result: publication.acl()
    assert result.value.board_acl_check == identifier
    assert gate.failure(publication.stage[0],result.value) == (
        "FAIL: full_election_e2e stage=board_acl check="+identifier+" category=assertion_error sqlstate=unavailable")


@pytest.mark.parametrize("role",ROLES)
def test_unexpected_membership_in_either_direction_fails(role):
    for edge in (("voting_owner",role,False,False,True),(role,"unexpected_login",False,True,False)):
        data = Catalogue();data.memberships[role].append(edge)
        reject(data,"board_acl_role_attributes")


@pytest.mark.parametrize("options",[(True,True,False),(False,False,False),(False,True,True)])
def test_ballot_membership_admin_inherit_and_set_options_are_exact(options):
    data = Catalogue()
    data.memberships["voting_ballot_login"] = [("voting_ballot_service","voting_ballot_login",*options)]
    reject(data,"board_acl_role_attributes")


@pytest.mark.parametrize("mutation",["missing_membership","wrong_parent","duplicate_grant","unsafe_service","service_membership","missing_inherit","unexpected_inherit","elevated","wrong_login"])
def test_role_policy_rejects_missing_extra_or_escalating_capabilities(mutation):
    data = Catalogue()
    if mutation == "missing_membership": data.memberships["voting_ballot_login"] = []
    elif mutation == "wrong_parent": data.memberships["voting_ballot_login"] = [("voting_owner","voting_ballot_login",False,True,False)]
    elif mutation == "duplicate_grant": data.memberships["voting_ballot_login"] *= 2
    elif mutation == "unsafe_service": data.service = (False,True)
    elif mutation == "service_membership": data.service = (True,False)
    elif mutation == "missing_inherit": data.roles["voting_ballot_login"] = ("voting_ballot_login",True,True,False)
    elif mutation == "unexpected_inherit": data.roles["voting_board_login"] = ("voting_board_login",True,True,True)
    elif mutation == "elevated": data.roles["voting_admin_login"] = ("voting_admin_login",True,False,False)
    else: data.roles["voting_board_login"] = ("voting_owner",True,True,False)
    reject(data,"board_acl_role_attributes")


@pytest.mark.parametrize("role",ROLES)
def test_any_unexpected_schema_create_or_board_execute_fails(role):
    for field,identifier in (("create","board_acl_schema_create"),("execute","board_acl_function_execute")):
        data = Catalogue()
        if field == "create": data.create[role] = 1
        else: data.execute[role].append(("_actor",))
        reject(data,identifier)


@pytest.mark.parametrize("mutation",["wrong_owner","invoker","wrong_path","extra_guc","missing_function","extra_function"])
def test_owner_definer_and_exact_proconfig_invariant_remains_strict(mutation):
    data = Catalogue()
    name,owner,secure,config = data.metadata[0]
    if mutation == "wrong_owner": owner = "voting_admin_login"
    elif mutation == "invoker": secure = False
    elif mutation == "wrong_path": config = ["search_path=public, pg_catalog, pg_temp"]
    elif mutation == "extra_guc": config.append("row_security=off")
    elif mutation == "missing_function": data.metadata.pop()
    else: data.metadata.append(("unexpected",owner,secure,config))
    data.metadata[0] = (name,owner,secure,config)
    reject(data,"board_acl_function_metadata")


def test_public_execution_is_still_forbidden():
    data = Catalogue();data.public = 1
    reject(data,"board_acl_public_grants")


@pytest.mark.parametrize("mutation",["wrong_id","wrong_type","missing","duplicate"])
def test_publication_audit_actor_must_be_exact(mutation):
    data = Catalogue()
    if mutation == "wrong_id": data.audit = [(uuid4(),"ADMIN")]
    elif mutation == "wrong_type": data.audit = [(data.principal,"TALLY_OPERATOR")]
    elif mutation == "missing": data.audit = []
    else: data.audit *= 2
    reject(data,"board_acl_audit_actor")


@pytest.mark.parametrize("outcome",[None,psycopg.errors.ReadOnlySqlTransaction,psycopg.errors.UndefinedTable,RuntimeError])
def test_direct_sql_success_wrong_sqlstate_or_exception_never_counts_as_denial(outcome):
    data = Catalogue();data.direct_outcome = outcome
    publication = data.publication()
    with pytest.raises(Exception) as result: publication.acl()
    assert result.value.board_acl_check == "board_acl_direct_sql"
    message = gate.failure("board_acl",result.value)
    assert "check=board_acl_direct_sql" in message and "SECRET_CANARY" not in message
    assert "category="+("database_error" if outcome and issubclass(outcome,psycopg.Error) else "assertion_error") in message


@pytest.mark.parametrize("identifier",sorted(gate.ACL_CHECKS))
def test_each_diagnostic_preserves_exception_identity_and_never_echoes_contents(identifier):
    error = psycopg.errors.InsufficientPrivilege("SECRET_CANARY")
    with pytest.raises(psycopg.errors.InsufficientPrivilege) as result:
        with gate.acl_check(identifier): raise error
    assert result.value is error
    assert gate.failure("board_acl",error) == f"FAIL: full_election_e2e stage=board_acl check={identifier} category=database_error sqlstate=42501"


@pytest.mark.parametrize("state",["SECRET_CANARY","ZZZZZ","P6405",None])
def test_acl_sqlstates_are_explicitly_allowlisted(state):
    error = RuntimeError("SECRET_CANARY")
    error.board_acl_check,error.sqlstate,error.http_status = "board_acl_direct_sql",state,503
    assert gate.failure("board_acl",error) == "FAIL: full_election_e2e stage=board_acl check=board_acl_direct_sql category=assertion_error sqlstate=unavailable"


@pytest.mark.parametrize("identifier",["SECRET_CANARY",{},None])
def test_unknown_diagnostic_cannot_enter_output(identifier):
    error = RuntimeError("SECRET_CANARY");error.board_acl_check = identifier
    assert "SECRET_CANARY" not in gate.failure("board_acl",error)
    with pytest.raises(AssertionError):
        with gate.acl_check(identifier): pytest.fail("Unknown diagnostic accepted")


def test_instrumentation_does_not_add_sql_or_transaction_control():
    import inspect
    source = inspect.getsource(gate.acl_check)
    assert not any(word in source for word in (".execute(",".commit(",".rollback(",".connect("))
    assert "raise  # Preserve" in source
    # Root-cause evidence is the unchanged trusted provisioning contract, not an
    # assumption that every service must have identical role attributes.
    provisioning = (gate.ROOT/"scripts/voting_postgres_ci.py").read_text(encoding="utf8")
    assert '("INHERIT", 40) if role == "voting_ballot_login"' in provisioning
    assert 'GRANT voting_ballot_service TO voting_ballot_login WITH INHERIT TRUE, SET FALSE' in provisioning


def test_outer_connection_diagnostic_does_not_overwrite_precise_inner_check():
    with pytest.raises(AssertionError) as result:
        with gate.acl_check("board_acl_role_attributes"):
            with gate.acl_check("board_acl_schema_create"):
                raise AssertionError("SECRET_CANARY")
    assert result.value.board_acl_check == "board_acl_schema_create"


def test_connection_failure_has_a_fixed_diagnostic_without_connection_details():
    publication = Catalogue().publication()
    @contextmanager
    def unavailable():
        raise psycopg.OperationalError("SECRET_CANARY")
        yield  # Context manager never yields a connection.
    publication.reader = unavailable
    with pytest.raises(psycopg.OperationalError) as result: publication.acl()
    assert gate.failure("board_acl",result.value) == (
        "FAIL: full_election_e2e stage=board_acl check=board_acl_role_attributes category=database_error sqlstate=unavailable")
