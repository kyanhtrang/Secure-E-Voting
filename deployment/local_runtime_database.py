"""Local-profile factories only. No discovery, provisioning, role switching or DSNs.

The trusted controller verifies the live VM/container before constructing these
factories. Applications receive only their own credential and public plan. Every
new SQL connection independently checks the destination and effective privileges.
"""
from copy import deepcopy
import os

import psycopg
from pydantic import SecretStr

from deployment.local_demo_policy import (
    ROLE_DATABASE, SERVICES, ReviewRefused, database_spec, require,
    safe_environment, validate_database_identity, validate_plan,
)

IDENTITY_SQL = """SELECT current_database(),session_user,current_user,
 pg_catalog.pg_get_userbyid(d.datdba),pg_catalog.shobj_description(d.oid,'pg_database'),
 pg_catalog.current_setting('server_version_num')::integer
 FROM pg_catalog.pg_database d WHERE datname=current_database()"""

# Exact signatures, not just names: an overload must never acquire execution.
RPCS = {
 'ra_auth_login': {
  'ra_demo.find_active_demo_voter_id(text,text)', 'ra_demo.issue_demo_session(text,uuid)',
  'ra_demo.find_active_demo_session(text)', 'ra_demo.revoke_demo_session(text)',
  'ra_e2e_auth.find_voter(uuid,text,text)', 'ra_e2e_auth.issue_session(uuid,text)',
  'ra_e2e_auth.find_session(uuid,text)', 'ra_e2e_auth.revoke_session(uuid,text)'},
 'ra_issuance_login': {
  'ra_credential.policy_for_session(text,uuid)',
  'ra_credential.reserve_request(text,uuid,uuid,bytea,bytea)',
  'ra_credential.lock_request(text,uuid,uuid,bytea,bytea)',
  'ra_credential.complete_request(text,uuid,uuid,bytea,bytea,bytea,bytea,text)'},
 'ra_election_publisher_login': {
  'ra_admin.prepare(uuid,bytea,bytea,bytea,text,uuid)', 'ra_admin.reconcile(uuid,bytea,boolean,uuid)'},
 'voting_ballot_login': {
  'voting.ballot_policy(uuid)',
  'voting.accept_anonymous_ballot(uuid,bytea,bytea,bytea,bytea,bytea)',
  'voting.recover_ballot_receipt(uuid,bytea,bytea,bytea,bytea,bytea)'},
 'voting_admin_login': {
  'voting_admin.login_session(uuid,bytea)', 'voting_admin.session(bytea)', 'voting_admin.logout(bytea)',
  'voting_admin.read_elections(bytea,uuid)', 'voting_admin.audit(bytea,uuid)',
  'voting_admin.operation(bytea,uuid,boolean)', 'voting_admin.mutate(bytea,uuid,text,jsonb)'},
 'voting_tally_login': {
  'voting_tally.login_session(uuid,bytea)', 'voting_tally.session(bytea)', 'voting_tally.logout(bytea)',
  'voting_tally.list_elections(bytea)', 'voting_tally.view_report(bytea,uuid)',
  'voting_tally.claim(bytea,uuid)', 'voting_tally.work(bytea,uuid,uuid,bigint)',
  'voting_tally.seal(bytea,uuid,uuid,bigint,jsonb)',
  'voting_tally.complete(bytea,uuid,uuid,bigint,bytea,bytea)',
  'voting_tally.fail(bytea,uuid,uuid,bigint,text)'},
 'voting_publication_login': {'voting_board.publication_input(bytea,uuid)', 'voting_board.finish(bytea,uuid,bytea,bytea,bytea)'},
 'voting_board_login': {'voting_board.read_public(uuid)', 'voting_board.catalogue(uuid,integer)'},
}


def expected_path(signature, kind):
    schema, name = signature.split('.')[0], signature.split('.')[1].split('(')[0]
    if schema == 'ra_e2e_auth': return 'pg_catalog,ra_e2e_auth,ra,pg_temp'
    if schema == 'ra_admin': return 'pg_catalog,ra_admin,ra,pg_temp'
    if schema == 'voting_admin':
        return 'pg_catalog,voting_admin,pg_temp' if name in {'login_session','session','logout','operation'} else 'pg_catalog,voting_admin,voting,pg_temp'
    if schema == 'voting_tally':
        if name in {'login_session','session','logout'}: return 'pg_catalog,voting_tally,pg_temp'
        if name in {'claim','complete','list_elections'}: return 'pg_catalog,voting_tally,voting,voting_admin,pg_temp'
        return 'pg_catalog,voting_tally,voting,pg_temp'
    if schema == 'voting_board':
        return 'pg_catalog,voting_board,voting,voting_admin,voting_tally,pg_temp' if name == 'finish' else 'pg_catalog,voting_board,voting,pg_temp'
    return 'pg_catalog,'+kind+',pg_temp'


def check_acl(conn, login, kind):
    """PG18 role membership semantics, mixed relation types and exact RPC set."""
    ballot = login == 'voting_ballot_login'
    require(conn.execute("""SELECT rolcanlogin,rolinherit,
      rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls
      FROM pg_catalog.pg_roles WHERE rolname=current_user""").fetchone() == (True, ballot, False), 'ROLE')
    memberships = conn.execute("""SELECT parent.rolname,child.rolname,m.admin_option,m.inherit_option,m.set_option
      FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles parent ON parent.oid=m.roleid
      JOIN pg_catalog.pg_roles child ON child.oid=m.member
      WHERE child.rolname=current_user OR parent.rolname=current_user""").fetchall()
    require(memberships == ([('voting_ballot_service',login,False,True,False)] if ballot else []), 'ROLE')
    if ballot:
        require(conn.execute("""SELECT NOT(rolcanlogin OR rolinherit OR rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls),
          NOT EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members WHERE member=r.oid
           OR (roleid=r.oid AND member<>(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=current_user)))
          FROM pg_catalog.pg_roles r WHERE rolname='voting_ballot_service'""").fetchone() == (True,True), 'ROLE')
    schemas = ['ra','ra_demo','ra_credential','ra_admin','ra_e2e_auth'] if kind == 'ra' else ['voting','voting_admin','voting_tally','voting_board']
    usage = conn.execute("""SELECT nspname FROM pg_catalog.pg_namespace
      WHERE nspname=ANY(%s::text[]) AND pg_catalog.has_schema_privilege(current_user,oid,'USAGE')""", (schemas+['public'],)).fetchall()
    expected_usage = {'ra_demo','ra_e2e_auth'} if login == 'ra_auth_login' else {
        'ra_issuance_login':'ra_credential','ra_election_publisher_login':'ra_admin','voting_ballot_login':'voting',
        'voting_admin_login':'voting_admin','voting_tally_login':'voting_tally','voting_publication_login':'voting_board',
        'voting_board_login':'voting_board'}[login]
    if isinstance(expected_usage,str): expected_usage = {expected_usage}
    require({r[0] for r in usage} == expected_usage and len(usage) == len(expected_usage), 'ROLE')
    # Reject unknown user schemas, TEMP database privilege, and CREATE anywhere.
    require(conn.execute("""SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_namespace n
       WHERE n.nspname !~ '^pg_' AND n.nspname<>'information_schema'
       AND (NOT(n.nspname=ANY(%s::text[])) OR pg_catalog.has_schema_privilege(current_user,n.oid,'CREATE')))
       OR pg_catalog.has_database_privilege(current_user,current_database(),'CREATE,TEMP')""", (schemas+['public'],)).fetchone() == (False,), 'ROLE')
    require(conn.execute("""SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_class c
      JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=ANY(%s::text[])
      AND CASE WHEN c.relkind IN ('r','p','v','m','f') THEN
       pg_catalog.has_table_privilege(current_user,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
       OR pg_catalog.has_any_column_privilege(current_user,c.oid,'SELECT,INSERT,UPDATE,REFERENCES')
      WHEN c.relkind='S' THEN pg_catalog.has_sequence_privilege(current_user,c.oid,'USAGE,SELECT,UPDATE') ELSE false END)""", (schemas+['public'],)).fetchone() == (False,), 'ROLE')
    rows = conn.execute("""SELECT n.nspname||'.'||p.proname||'('||pg_catalog.oidvectortypes(p.proargtypes)||')',
      p.prosecdef,pg_catalog.pg_get_userbyid(p.proowner),p.proconfig
      FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
      WHERE n.nspname=ANY(%s::text[]) AND pg_catalog.has_function_privilege(current_user,p.oid,'EXECUTE')""", (schemas+['public'],)).fetchall()
    normalize = lambda text: text.replace(' ', '').replace('timestampwithtimezone','timestamptz')
    require(len(rows) == len(RPCS[login]) and {normalize(r[0]) for r in rows} == RPCS[login], 'ROLE')
    owner = kind+'_owner'
    for signature, definer, actual_owner, settings in rows:
        path = expected_path(signature,kind)
        require(definer is True and actual_owner == owner and settings is not None
            and [s.replace(' ','') for s in settings] == ['search_path='+path], 'ROLE')
    require(conn.execute("""SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_proc p
      JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
      CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(p.proacl,pg_catalog.acldefault('f',p.proowner))) a
      WHERE n.nspname=ANY(%s::text[]) AND a.grantee=0 AND a.privilege_type='EXECUTE')""", (schemas,)).fetchone() == (False,), 'ROLE')


def connection_factory(plan, service, login, password, *, boundary):
    """boundary is the controller's live-identity check, never an HTTP input.

    No privileged login is accepted, even during fixture work. The separate
    installer owns its setup connection; runtime never gets that capability.
    """
    validate_plan(plan)
    require(service in SERVICES and login in SERVICES[service]['roles'] and login in RPCS, 'ROLE')
    require(isinstance(password,SecretStr) and bool(password.get_secret_value()), 'CONFIG')
    require(callable(boundary), 'OWNERSHIP')
    frozen = deepcopy(plan)
    kind = ROLE_DATABASE[login]
    spec = database_spec(frozen,kind)
    def connect():
        conn = None
        try:
            safe_environment(os.environ)
            boundary()
            # Suppress libpq's implicit service/password-file discovery too.
            conn = psycopg.connect(host=spec['host'],hostaddr='127.0.0.1',port=spec['port'],dbname=spec['name'],
                user=login,password=password.get_secret_value(),service='',passfile='/dev/null',sslmode='disable',
                connect_timeout=5,application_name='evote-guarded-local',
                options='-c statement_timeout=30000 -c lock_timeout=3000 -c search_path=pg_catalog')
            if login == 'voting_board_login': conn.execute('SET TRANSACTION READ ONLY')
            validate_database_identity(frozen,service,login,conn.execute(IDENTITY_SQL).fetchone())
            check_acl(conn,login,kind)
            if login != 'voting_board_login': conn.commit()
            return conn
        except BaseException:
            if conn is not None: conn.close()
            raise ReviewRefused('IDENTITY') from None
    return connect
