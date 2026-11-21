"""Two-voter authentication capability ONLY for the owned hosted E2E database.

Not an Alembic revision, production launcher, or general authentication endpoint.
The fixture installs this schema transactionally after checking the owned target.
"""
from datetime import datetime, timedelta
import secrets
from uuid import UUID, uuid4

from backend.ra.auth_service import AuthenticationDenied
from backend.ra.demo_session_service import DemoSessionService
from backend.ra.session_service import InvalidRASession, RASessionRecord
from scripts import admin_voter_e2e as guard

SUBJECTS = ("demo-voter-001", "demo-voter-002")
SIGNATURES = ("find_voter(uuid,text,text)", "issue_session(uuid,text)",
              "find_session(uuid,text)", "revoke_session(uuid,text)")
DDL = """
CREATE SCHEMA ra_e2e_auth AUTHORIZATION ra_owner;
REVOKE ALL ON SCHEMA ra_e2e_auth FROM PUBLIC;
CREATE TABLE ra_e2e_auth.voters (
 voter_id uuid PRIMARY KEY REFERENCES ra.voters(voter_id),
 provider text NOT NULL CHECK(provider='demo-local'),
 subject text UNIQUE NOT NULL CHECK(subject IN ('demo-voter-001','demo-voter-002'))
);
REVOKE ALL ON TABLE ra_e2e_auth.voters FROM PUBLIC,ra_auth_login;
CREATE FUNCTION ra_e2e_auth.find_voter(expected uuid,provider text,subject text) RETURNS uuid
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,ra_e2e_auth,ra,pg_temp AS $rpc$
 SELECT v.voter_id FROM ra_e2e_auth.voters a JOIN ra.voters v USING(voter_id)
 WHERE session_user='ra_auth_login' AND a.voter_id=expected AND a.provider=$2 AND a.subject=$3
 AND v.auth_provider=a.provider AND v.auth_subject=a.subject AND v.is_active
$rpc$;
CREATE FUNCTION ra_e2e_auth.issue_session(expected uuid,digest text) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,ra_e2e_auth,ra,pg_temp AS $rpc$
DECLARE found_voter uuid; created timestamptz;
BEGIN
 IF session_user<>'ra_auth_login' OR digest IS NULL OR digest !~ '^[0-9a-f]{64}$' THEN RETURN false; END IF;
 SELECT v.voter_id INTO found_voter FROM ra_e2e_auth.voters a JOIN ra.voters v USING(voter_id)
 WHERE a.voter_id=expected AND v.auth_provider=a.provider AND v.auth_subject=a.subject AND v.is_active
 FOR SHARE OF v;
 IF NOT FOUND THEN RETURN false; END IF;
 created:=pg_catalog.clock_timestamp();
 PERFORM ra.create_session(digest,found_voter,created,created+interval '15 minutes');
 RETURN true;
END $rpc$;
CREATE FUNCTION ra_e2e_auth.find_session(expected uuid,digest text)
RETURNS TABLE(voter_id uuid,created_at timestamptz,expires_at timestamptz,revoked_at timestamptz)
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,ra_e2e_auth,ra,pg_temp AS $rpc$
 SELECT s.voter_id,s.created_at,s.expires_at,s.revoked_at FROM ra.find_active_session(digest) s
 JOIN ra_e2e_auth.voters a ON a.voter_id=s.voter_id JOIN ra.voters v ON v.voter_id=a.voter_id
 WHERE session_user='ra_auth_login' AND a.voter_id=expected
 AND v.auth_provider=a.provider AND v.auth_subject=a.subject AND v.is_active
$rpc$;
CREATE FUNCTION ra_e2e_auth.revoke_session(expected uuid,digest text) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,ra_e2e_auth,ra,pg_temp AS $rpc$
BEGIN
 IF session_user<>'ra_auth_login' OR digest IS NULL OR digest !~ '^[0-9a-f]{64}$' THEN RETURN false; END IF;
 UPDATE ra.ra_sessions s SET revoked_at=GREATEST(pg_catalog.clock_timestamp(),s.created_at)
 FROM ra_e2e_auth.voters a JOIN ra.voters v USING(voter_id)
 WHERE a.voter_id=expected AND s.voter_id=a.voter_id AND s.token_digest=digest AND s.revoked_at IS NULL
 AND v.auth_provider=a.provider AND v.auth_subject=a.subject;
 RETURN FOUND;
END $rpc$;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA ra_e2e_auth FROM PUBLIC;
GRANT USAGE ON SCHEMA ra_e2e_auth TO ra_auth_login;
"""


def install(owned, fixture, identities):
    guard.require_ci()
    guard.check(owned.kind == "ra" and set(identities) == set(SUBJECTS)
        and all(isinstance(v, UUID) for v in identities.values()) and len(set(identities.values())) == 2,
        "Two distinct generated voters required")
    owned.verify()  # Container identity/image/tmpfs/loopback check BEFORE connection or DDL.
    with fixture() as conn:
        row = conn.execute("""SELECT current_database(),session_user,current_user,pg_get_userbyid(d.datdba),
            shobj_description(d.oid,'pg_database'),current_setting('server_version_num')::integer
            FROM pg_database d WHERE datname=current_database()""").fetchone()
        guard.check(row[:5] == (owned.target.database,"ra_migrator_login","ra_owner","ra_owner",
            "secure-evoting-disposable:"+owned.target.marker) and 180000 <= row[5] < 190000,
            "Unsafe E2E auth installation target")
        guard.check(conn.execute("SELECT version_num FROM ra.alembic_version").fetchall() == [("bf932d0f8702",)],
            "Expected reviewed RA migration head")
        guard.check(conn.execute("SELECT to_regnamespace('ra_e2e_auth')").fetchone() == (None,), "Existing E2E schema refused")
        rows = conn.execute("SELECT voter_id,auth_provider,auth_subject,is_active FROM ra.voters WHERE voter_id=ANY(%s::uuid[])",
            (list(identities.values()),)).fetchall()
        guard.check(set(rows) == {(v,"demo-local",s,True) for s,v in identities.items()}, "Fixture identity mismatch")
        conn.execute(DDL)
        for subject in SUBJECTS:
            conn.execute("INSERT INTO ra_e2e_auth.voters(voter_id,provider,subject) VALUES(%s,'demo-local',%s)",
                (identities[subject],subject))
        for signature in SIGNATURES:  # Fixed identifiers only; never input-derived SQL.
            conn.execute("GRANT EXECUTE ON FUNCTION ra_e2e_auth."+signature+" TO ra_auth_login")
        check_function_acl(conn)  # Unexpected owner default grants abort the whole installation.


def check_function_acl(conn):
    rows = conn.execute("""SELECT p.proname,p.prosecdef,p.proowner='ra_owner'::regrole,p.proconfig
        FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='ra_e2e_auth'""").fetchall()
    guard.check({r[0] for r in rows} == {s.split('(')[0] for s in SIGNATURES} and len(rows) == 4
        and all(r[1:3] == (True,True) and r[3] is not None
            and [v.replace(' ','') for v in r[3]] == ['search_path=pg_catalog,ra_e2e_auth,ra,pg_temp'] for r in rows),
        "Unsafe E2E function definition")
    guard.check(conn.execute("""SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
        CROSS JOIN LATERAL aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a
        WHERE n.nspname='ra_e2e_auth' AND (a.grantee NOT IN (p.proowner,'ra_auth_login'::regrole)
          OR (a.grantee='ra_auth_login'::regrole AND a.is_grantable))""").fetchone() == (0,),
        "Unexpected E2E function grant")
    guard.check(conn.execute("""SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
        CROSS JOIN LATERAL aclexplode(COALESCE(c.relacl,acldefault('r',c.relowner))) a
        WHERE n.nspname='ra_e2e_auth' AND c.relkind='r' AND a.grantee<>c.relowner""").fetchone() == (0,),
        "Unexpected E2E table grant")
    guard.check(conn.execute("""SELECT count(*) FROM pg_namespace n
        CROSS JOIN LATERAL aclexplode(COALESCE(n.nspacl,acldefault('n',n.nspowner))) a
        WHERE n.nspname='ra_e2e_auth' AND (n.nspowner<>'ra_owner'::regrole OR
          a.grantee NOT IN(n.nspowner,'ra_auth_login'::regrole) OR
          (a.grantee='ra_auth_login'::regrole AND (a.privilege_type<>'USAGE' OR a.is_grantable)))""").fetchone() == (0,),
        "Unexpected E2E schema grant")


class SessionStore:
    """The expected identity comes from the private fixture config, never HTTP."""
    def __init__(self, connect, voter_id, subject):
        if not isinstance(voter_id,UUID) or subject not in SUBJECTS: raise ValueError("Invalid E2E identity")
        self.connect, self.voter_id, self.subject = connect, voter_id, subject

    def find_active_voter_id(self, provider, subject):
        with self.connect() as conn:
            row = conn.execute("SELECT ra_e2e_auth.find_voter(%s::uuid,%s::text,%s::text)",
                (self.voter_id,provider,subject)).fetchone()
        if row != (None,) and row != (self.voter_id,): raise RuntimeError("Invalid E2E identity response")
        return row[0]

    def issue_ra_session(self, voter_id):
        if voter_id != self.voter_id: raise AuthenticationDenied()
        token = secrets.token_urlsafe(32)
        digest = DemoSessionService._digest(token)  # Canonical token + SHA256(ASCII), no fallback.
        with self.connect() as conn:
            row = conn.execute("SELECT ra_e2e_auth.issue_session(%s::uuid,%s::text)",(self.voter_id,digest)).fetchone()
            if row is None or len(row) != 1 or row[0] is not True: raise AuthenticationDenied()
        return token  # Commit precedes disclosure.

    def find_session(self, digest):
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM ra_e2e_auth.find_session(%s::uuid,%s::text)",(self.voter_id,digest)).fetchone()
        if row is None: return None
        if (len(row) != 4 or row[0] != self.voter_id or any(not isinstance(v,datetime) for v in row[1:3])
            or row[3] is not None and not isinstance(row[3],datetime)): raise RuntimeError("Invalid E2E session response")
        return RASessionRecord(digest,*row)

    def revoke_session(self, digest, _revoked_at):
        with self.connect() as conn:
            row = conn.execute("SELECT ra_e2e_auth.revoke_session(%s::uuid,%s::text)",(self.voter_id,digest)).fetchone()
        if row is None or len(row) != 1 or type(row[0]) is not bool: raise RuntimeError("Invalid E2E revocation response")
        return row[0]


class BoundSessions(DemoSessionService):
    def resolve_voter_id(self, token):
        voter = super().resolve_voter_id(token)
        if voter != self.store.voter_id: raise InvalidRASession()
        return voter

    def revoke_ra_session(self, token):
        self.resolve_voter_id(token)  # Reject cross-voter/expired/revoked bearer substitution.
        return super().revoke_ra_session(token)


class BoundIssuance:
    def __init__(self, service, sessions): self.service, self.sessions = service, sessions
    def issue(self, token, *args):
        self.sessions.resolve_voter_id(token)
        return self.service.issue(token,*args)


def check_acl(auth, unrelated, fixture):
    with fixture() as conn: check_function_acl(conn)
    for factory in (auth,*unrelated):
        with factory() as conn:
            login = conn.execute("SELECT current_user").fetchone()[0]
            actual = conn.execute("""SELECT p.proname FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
                WHERE n.nspname='ra_e2e_auth' AND has_function_privilege(current_user,p.oid,'EXECUTE')""").fetchall()
            guard.check({r[0] for r in actual} == ({s.split('(')[0] for s in SIGNATURES} if login == 'ra_auth_login' else set()),
                "Unexpected effective E2E execution")
            guard.check(conn.execute("""SELECT has_schema_privilege(current_user,'ra_e2e_auth','CREATE')
                OR EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
                 WHERE n.nspname='ra_e2e_auth' AND CASE WHEN c.relkind IN ('r','p','v','m','f') THEN
                  has_table_privilege(current_user,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
                  OR has_any_column_privilege(current_user,c.oid,'SELECT,INSERT,UPDATE,REFERENCES')
                  WHEN c.relkind='S' THEN has_sequence_privilege(current_user,c.oid,'USAGE,SELECT,UPDATE') ELSE false END)""").fetchone() == (False,),
                "Unexpected E2E table access")
        guard.real.deny(factory,"SELECT * FROM ra_e2e_auth.voters")
        if factory is not auth:
            for statement in ("SELECT ra_e2e_auth.find_voter('00000000-0000-4000-8000-000000000001'::uuid,'demo-local','demo-voter-001')",
                "SELECT ra_e2e_auth.issue_session('00000000-0000-4000-8000-000000000001'::uuid,repeat('0',64))",
                "SELECT * FROM ra_e2e_auth.find_session('00000000-0000-4000-8000-000000000001'::uuid,repeat('0',64))",
                "SELECT ra_e2e_auth.revoke_session('00000000-0000-4000-8000-000000000001'::uuid,repeat('0',64))"):
                guard.real.deny(factory,statement)


def check_session(fixture, voter, token):
    digest = DemoSessionService._digest(token)
    with fixture() as conn:
        row = conn.execute("""SELECT voter_id,expires_at-created_at,revoked_at,
            created_at<=clock_timestamp(),expires_at>clock_timestamp() FROM ra.ra_sessions WHERE token_digest=%s""",(digest,)).fetchone()
        guard.check(row == (voter,timedelta(minutes=15),None,True,True), "E2E digest/voter/DB lifetime mismatch")


def check_authentication(services, fixture, auth, election):
    """Real HTTP/SQL regressions in the owned database; never log private inputs."""
    guard.check(len(services) == 2 and len({s[1] for s in services}) == len({s[2] for s in services}) == 2,
        "Independent voters and sessions required")
    probe = dict(election_id=str(election),request_id=str(uuid4()),blinded_msg=guard.b64encode(bytes(384)))
    for index, (origin, token, voter, username, password) in enumerate(services):
        other_token = services[1-index][1]
        for path in ("/auth/me","/elections"):
            guard.http(origin,"/api/v1/ra"+path,401,token=other_token)
        guard.http(origin,"/api/v1/ra/auth/logout",401,method="POST",token=other_token)
        guard.http(origin,"/api/v1/ra/credentials/issue",401,method="POST",data=probe,token=other_token)
        guard.check(guard.http(origin,"/api/v1/ra/auth/me",200,token=token) == {"voter_id":str(voter)},
            "Cross-voter logout changed another session")
        with auth() as conn:
            digest = DemoSessionService._digest(other_token)
            guard.check(conn.execute("SELECT * FROM ra_e2e_auth.find_session(%s::uuid,%s::text)",(voter,digest)).fetchall() == [],
                "SQL accepted cross-voter lookup")
            guard.check(conn.execute("SELECT ra_e2e_auth.revoke_session(%s::uuid,%s::text)",(voter,digest)).fetchone() == (False,),
                "SQL accepted cross-voter revocation")
        for expired in (False,True):
            extra = guard.http(origin,"/api/v1/ra/auth/login",200,method="POST",data={"username":username,"password":password})["access_token"]
            check_session(fixture,voter,extra)
            if expired:
                with fixture() as conn:
                    changed = conn.execute("""UPDATE ra.ra_sessions SET created_at=clock_timestamp()-interval '16 minutes',
                        expires_at=clock_timestamp()-interval '1 minute' WHERE voter_id=%s AND token_digest=%s""",
                        (voter,DemoSessionService._digest(extra))).rowcount
                    guard.check(changed == 1,"Expiry fixture scope mismatch")
            else:
                guard.http(origin,"/api/v1/ra/auth/logout",204,method="POST",token=extra)
                with fixture() as conn:
                    guard.check(conn.execute("SELECT revoked_at>=created_at FROM ra.ra_sessions WHERE token_digest=%s",
                        (DemoSessionService._digest(extra),)).fetchone() == (True,),"DB revocation not committed")
            for path in ("/auth/me","/elections"):
                guard.http(origin,"/api/v1/ra"+path,401,token=extra)
            guard.http(origin,"/api/v1/ra/credentials/issue",401,method="POST",data=probe,token=extra)
    third, digest = uuid4(), DemoSessionService._digest(secrets.token_urlsafe(32))
    with fixture() as conn:
        conn.execute("INSERT INTO ra.voters(voter_id,auth_provider,auth_subject,is_active) VALUES(%s,'demo-local','demo-voter-003',true)",(third,))
    with auth() as conn:
        guard.check(conn.execute("SELECT ra_e2e_auth.find_voter(%s::uuid,'demo-local','demo-voter-003')",(third,)).fetchone() == (None,),"Third identity allowed")
        guard.check(conn.execute("SELECT ra_e2e_auth.issue_session(%s::uuid,%s::text)",(third,digest)).fetchone() == (False,),"Third session allowed")
        guard.check(conn.execute("SELECT * FROM ra_e2e_auth.find_session(%s::uuid,%s::text)",(third,digest)).fetchall() == [],"Third lookup allowed")
        guard.check(conn.execute("SELECT ra_e2e_auth.revoke_session(%s::uuid,%s::text)",(third,digest)).fetchone() == (False,),"Third revocation allowed")
        # Original single-subject demo RPCs remain unchanged and cannot handle voter B.
        second_digest = DemoSessionService._digest(services[1][1])
        guard.check(conn.execute("SELECT ra_demo.find_active_demo_voter_id('demo-local','demo-voter-002')").fetchone() == (None,),"Demo identity boundary widened")
        guard.check(conn.execute("SELECT * FROM ra_demo.find_active_demo_session(%s::text)",(second_digest,)).fetchall() == [],"Demo session boundary widened")
        guard.check(conn.execute("SELECT ra_demo.revoke_demo_session(%s::text)",(second_digest,)).fetchone() == (False,),"Demo revocation boundary widened")
    denied = None
    try:
        with auth() as conn:
            try: conn.execute("SELECT ra_demo.issue_demo_session(%s::text,%s::uuid)",(digest,services[1][2]))
            except guard.psycopg.errors.InsufficientPrivilege as error:
                denied = error
                raise
            raise AssertionError("Demo issuance boundary widened")
    except guard.psycopg.errors.InsufficientPrivilege as error:
        guard.check(error is denied and error.sqlstate == "42501","Unexpected demo denial")
    with fixture() as conn:
        guard.check(conn.execute("SELECT count(*) FROM ra.ra_sessions WHERE voter_id=%s",(third,)).fetchone() == (0,),"Third identity persisted a session")
        guard.check(conn.execute("SELECT count(*) FROM ra_e2e_auth.voters").fetchone() == (2,),"E2E allowlist widened")
