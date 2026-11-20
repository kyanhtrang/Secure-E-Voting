"""Opt-in admin branch, forward from reviewed Voting head. No role provisioning."""
from alembic import op

revision = "af821c9e7601"
down_revision = "d8f27a4c610b"
branch_labels = None
depends_on = None


def upgrade():
    op.execute("""
DO $$ BEGIN
 IF (SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname=current_database()) IS DISTINCT FROM 'voting_owner'
 THEN RAISE EXCEPTION 'Unexpected database owner'; END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='voting_admin_login' AND rolcanlogin AND NOT
   (rolinherit OR rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls))
 OR EXISTS(SELECT 1 FROM pg_auth_members WHERE member=(SELECT oid FROM pg_roles WHERE rolname='voting_admin_login'))
 THEN RAISE EXCEPTION 'Provision an isolated voting_admin_login separately'; END IF;
 IF pg_has_role('voting_admin_login','voting_owner','MEMBER') OR
   has_schema_privilege('voting_admin_login','voting','CREATE') OR has_schema_privilege('voting_admin_login','public','CREATE')
 THEN RAISE EXCEPTION 'Unsafe admin role'; END IF;
 IF EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='voting'
  AND CASE WHEN c.relkind IN ('r','p','v','m','f') THEN
   has_table_privilege('voting_admin_login',c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
   OR has_any_column_privilege('voting_admin_login',c.oid,'SELECT,INSERT,UPDATE,REFERENCES') ELSE false END)
 THEN RAISE EXCEPTION 'Admin table access must be revoked separately'; END IF;
IF EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
  WHERE n.nspname IN ('voting','voting_credential','voting_demo') AND
  has_function_privilege('voting_admin_login',p.oid,'EXECUTE')) THEN
  RAISE EXCEPTION 'Unexpected baseline function execution privilege'; END IF;
 IF EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='voting'
  AND CASE WHEN c.relkind='S' THEN has_sequence_privilege('voting_admin_login',c.oid,'USAGE,SELECT,UPDATE') ELSE false END)
 THEN RAISE EXCEPTION 'Unexpected sequence access'; END IF;
END $$;
SET LOCAL ROLE voting_owner;
CREATE SCHEMA voting_admin AUTHORIZATION voting_owner;
REVOKE ALL ON SCHEMA voting_admin FROM PUBLIC;
CREATE TABLE voting_admin.principals(
 admin_id uuid PRIMARY KEY, role text NOT NULL CHECK(role='ELECTION_ADMIN'), is_active boolean NOT NULL DEFAULT false);
CREATE TABLE voting_admin.sessions(
 digest bytea PRIMARY KEY CHECK(octet_length(digest)=32), admin_id uuid NOT NULL REFERENCES voting_admin.principals,
 created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
 expires_at timestamptz NOT NULL DEFAULT statement_timestamp()+interval '15 minutes', revoked_at timestamptz,
 CHECK(expires_at>created_at AND expires_at<=created_at+interval '15 minutes'));
CREATE TABLE voting_admin.controls(
 election_id uuid PRIMARY KEY REFERENCES voting.elections, revision integer NOT NULL DEFAULT 1 CHECK(revision>0),
 phase text NOT NULL DEFAULT 'DRAFT' CHECK(phase IN ('DRAFT','FINALIZING','FROZEN','OPEN','CLOSED')),
 keyset_id text UNIQUE, manifest_bytes bytea CHECK(octet_length(manifest_bytes) BETWEEN 1 AND 131072),
 config_hash bytea CHECK(octet_length(config_hash)=32), ra_ready boolean NOT NULL DEFAULT false);
REVOKE ALL ON ALL TABLES IN SCHEMA voting_admin FROM PUBLIC,voting_admin_login;

CREATE FUNCTION voting_admin._actor(d bytea) RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,voting_admin,pg_temp AS $f$
DECLARE id uuid;
BEGIN
 IF session_user<>'voting_admin_login' THEN RAISE EXCEPTION USING ERRCODE='P4301',MESSAGE='Admin session required'; END IF;
 SELECT p.admin_id INTO id FROM voting_admin.sessions s JOIN voting_admin.principals p USING(admin_id)
 WHERE s.digest=d AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp()
 AND p.is_active AND p.role='ELECTION_ADMIN' FOR SHARE OF s,p;
 IF id IS NULL THEN RAISE EXCEPTION USING ERRCODE='P4301',MESSAGE='Admin session required'; END IF;
 RETURN id;
END $f$;
CREATE FUNCTION voting_admin.login_session(id uuid,d bytea) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,voting_admin,pg_temp AS $f$
BEGIN
 IF session_user<>'voting_admin_login' OR d IS NULL OR octet_length(d)<>32 OR NOT EXISTS
  (SELECT 1 FROM voting_admin.principals p WHERE p.admin_id=id AND p.is_active AND p.role='ELECTION_ADMIN' FOR SHARE)
 THEN RAISE EXCEPTION USING ERRCODE='P4301',MESSAGE='Admin authorization required'; END IF;
 INSERT INTO voting_admin.sessions(digest,admin_id) VALUES(d,id);
 RETURN jsonb_build_object('admin_id',id,'role','ELECTION_ADMIN');
END $f$;
CREATE FUNCTION voting_admin.session(d bytea) RETURNS jsonb LANGUAGE sql SECURITY DEFINER
SET search_path=pg_catalog,voting_admin,pg_temp AS $f$
 SELECT jsonb_build_object('admin_id',voting_admin._actor(d),'role','ELECTION_ADMIN')
$f$;
CREATE FUNCTION voting_admin.logout(d bytea) RETURNS void LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,voting_admin,pg_temp AS $f$
BEGIN
 PERFORM voting_admin._actor(d);
 UPDATE voting_admin.sessions SET revoked_at=clock_timestamp() WHERE digest=d;
END $f$;
CREATE FUNCTION voting_admin._lock(e uuid) RETURNS void LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,voting_admin,pg_temp AS $f$
BEGIN
 IF e IS NULL OR NOT pg_try_advisory_xact_lock(hashtextextended(e::text,8301)) THEN
  RAISE EXCEPTION USING ERRCODE='P4303',MESSAGE='Election operation in progress'; END IF;
END $f$;
CREATE FUNCTION voting_admin.operation(d bytea,e uuid,release boolean) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,voting_admin,pg_temp AS $f$
BEGIN
 PERFORM voting_admin._actor(d);
 IF e IS NULL THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='Invalid election'; END IF;
 IF release THEN RETURN pg_advisory_unlock(hashtextextended(e::text,8301)); END IF;
 RETURN pg_try_advisory_lock(hashtextextended(e::text,8301));
END $f$;
CREATE FUNCTION voting_admin.read_elections(d bytea,e uuid) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,voting_admin,voting,pg_temp AS $f$
DECLARE result jsonb;
BEGIN
 PERFORM voting_admin._actor(d);
 SELECT COALESCE(jsonb_agg(x.data ORDER BY x.id),'[]'::jsonb) INTO result FROM (
  SELECT v.election_id id,jsonb_build_object('election_id',v.election_id,'title',v.title,'status',v.status,
   'opens_at',to_char(v.opens_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"'),
   'closes_at',to_char(v.closes_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"'),
   'revision',c.revision,'phase',c.phase,'ra_ready',c.ra_ready,'keyset_id',c.keyset_id,
   'config_hash',encode(c.config_hash,'hex'),'manifest_hex',encode(c.manifest_bytes,'hex'),
   'signature_hex',encode(f.config_signature,'hex'),
   'candidates',(SELECT COALESCE(jsonb_agg(jsonb_build_object('candidate_id',k.candidate_id,
     'candidate_name',k.candidate_name) ORDER BY k.candidate_id),'[]'::jsonb)
     FROM voting.candidates k WHERE k.election_id=v.election_id)) data
  FROM voting.elections v JOIN voting_admin.controls c USING(election_id)
  LEFT JOIN voting.election_configs f USING(election_id) WHERE e IS NULL OR v.election_id=e
  ORDER BY v.election_id LIMIT 200) x;
 IF e IS NOT NULL AND jsonb_array_length(result)=0 THEN RAISE EXCEPTION USING ERRCODE='P4304',MESSAGE='Election absent'; END IF;
 RETURN result;
END $f$;
CREATE FUNCTION voting_admin.audit(d bytea,e uuid) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,voting_admin,voting,pg_temp AS $f$
DECLARE result jsonb;
BEGIN
 PERFORM voting_admin._actor(d);
 SELECT COALESCE(jsonb_agg(to_jsonb(x)),'[]'::jsonb) INTO result FROM
  (SELECT event_type,outcome,reason_code,occurred_at,actor_type,actor_principal_id
   FROM voting.voting_audit_events WHERE election_id=e ORDER BY occurred_at DESC,audit_event_id LIMIT 100) x;
 RETURN result;
END $f$;
CREATE FUNCTION voting_admin.mutate(d bytea,id uuid,cmd text,data jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,voting_admin,voting,pg_temp AS $f$
DECLARE actor uuid; v voting.elections%ROWTYPE; c voting_admin.controls%ROWTYPE;
 event text; reason text; raw bytea; m jsonb; roster jsonb;
BEGIN
 actor:=voting_admin._actor(d); PERFORM voting_admin._lock(id);
 IF cmd='create' THEN
  INSERT INTO voting.elections(election_id,title,opens_at,closes_at)
    VALUES(id,data->>'title',(data->>'opens_at')::timestamptz,(data->>'closes_at')::timestamptz);
  INSERT INTO voting_admin.controls(election_id) VALUES(id);
  event:='ELECTION_CREATED';
 ELSE
  SELECT * INTO v FROM voting.elections WHERE election_id=id FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P4304',MESSAGE='Election absent'; END IF;
  SELECT * INTO c FROM voting_admin.controls WHERE election_id=id FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P4303',MESSAGE='Unmanaged election'; END IF;
  IF cmd IN ('edit','candidate','remove','reserve') THEN
   IF (data->>'revision')::integer IS DISTINCT FROM c.revision THEN
    RAISE EXCEPTION USING ERRCODE='P4303',MESSAGE='Stale election revision'; END IF;
   IF c.phase<>'DRAFT' OR v.status<>'DRAFT' THEN
    IF cmd='reserve' AND c.keyset_id=data->>'keyset_id' AND c.manifest_bytes=decode(data->>'manifest_hex','hex') THEN
      RETURN voting_admin.read_elections(d,id)->0;
    END IF;
    RAISE EXCEPTION USING ERRCODE='P4303',MESSAGE='Configuration locked';
   END IF;
   IF cmd='edit' THEN
    UPDATE voting.elections SET title=data->>'title',opens_at=(data->>'opens_at')::timestamptz,
     closes_at=(data->>'closes_at')::timestamptz WHERE election_id=id;
    event:='ELECTION_CREATED'; reason:='DRAFT_UPDATED';
   ELSIF cmd='candidate' THEN
    IF EXISTS(SELECT 1 FROM voting.candidates WHERE election_id=id AND candidate_id=(data->>'candidate_id')::uuid) THEN
     UPDATE voting.candidates SET candidate_name=data->>'candidate_name' WHERE election_id=id AND candidate_id=(data->>'candidate_id')::uuid;
     event:='CANDIDATE_UPDATED';
    ELSE
     IF (SELECT count(*) FROM voting.candidates WHERE election_id=id)>=1000 THEN
      RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='Candidate limit'; END IF;
     INSERT INTO voting.candidates(election_id,candidate_id,candidate_name) VALUES(id,(data->>'candidate_id')::uuid,data->>'candidate_name');
     event:='CANDIDATE_CREATED';
    END IF;
   ELSIF cmd='remove' THEN
    DELETE FROM voting.candidates WHERE election_id=id AND candidate_id=(data->>'candidate_id')::uuid;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P4304',MESSAGE='Candidate absent'; END IF;
    event:='CANDIDATE_DELETED';
   ELSE
    raw:=decode(data->>'manifest_hex','hex');m:=convert_from(raw,'UTF8')::jsonb;
    SELECT COALESCE(jsonb_agg(jsonb_build_object('candidate_id',candidate_id,'candidate_name',candidate_name) ORDER BY candidate_id),'[]'::jsonb)
     INTO roster FROM voting.candidates WHERE election_id=id;
    IF (m->>'election_id') IS DISTINCT FROM id::text OR (m->>'opens_at')::timestamptz IS DISTINCT FROM v.opens_at
     OR (m->>'closes_at')::timestamptz IS DISTINCT FROM v.closes_at OR m->'candidates' IS DISTINCT FROM roster
     OR jsonb_array_length(roster)=0 OR data->>'keyset_id' IS NULL
    THEN RAISE EXCEPTION USING ERRCODE='P4303',MESSAGE='Draft snapshot mismatch'; END IF;
    UPDATE voting_admin.controls SET phase='FINALIZING',manifest_bytes=raw,config_hash=sha256(raw),keyset_id=data->>'keyset_id' WHERE election_id=id;
    event:='CONFIG_FROZEN'; reason:='SIGNING_RESERVED';
   END IF;
   IF cmd<>'reserve' THEN UPDATE voting_admin.controls SET revision=revision+1 WHERE election_id=id; END IF;
  ELSIF cmd='freeze' THEN
   IF c.phase='FROZEN' THEN RETURN voting_admin.read_elections(d,id)->0; END IF;
   IF c.phase<>'FINALIZING' OR c.config_hash IS DISTINCT FROM decode(data->>'config_hash','hex') THEN
    RAISE EXCEPTION USING ERRCODE='P4303',MESSAGE='Signing reservation mismatch'; END IF;
   INSERT INTO voting.election_configs(election_id,config_bytes,config_digest,config_signature,
    config_signing_key_id,config_signing_key_fingerprint,evidence_reference)
    VALUES(id,c.manifest_bytes,c.config_hash,decode(data->>'signature_hex','hex'),'admin-manifest-authority',
     decode(data->>'authority_fingerprint','hex'),'local-admin-verified');
   UPDATE voting.elections SET election_config_digest=c.config_hash WHERE election_id=id;
   UPDATE voting_admin.controls SET phase='FROZEN' WHERE election_id=id;
   event:='CONFIG_FROZEN'; reason:='MANIFEST_SIGNED';
  ELSIF cmd='open' THEN
   IF v.status='OPEN' AND c.phase='OPEN' THEN RETURN voting_admin.read_elections(d,id)->0; END IF;
   IF v.status<>'DRAFT' OR c.phase<>'FROZEN' OR c.config_hash IS DISTINCT FROM decode(data->>'ra_hash','hex')
    OR clock_timestamp()<v.opens_at OR clock_timestamp()>=v.closes_at THEN
    RAISE EXCEPTION USING ERRCODE='P4303',MESSAGE='Election not ready to open'; END IF;
   UPDATE voting.elections SET status='OPEN' WHERE election_id=id;
   UPDATE voting_admin.controls SET phase='OPEN',ra_ready=false WHERE election_id=id;
   event:='ELECTION_OPENED';
  ELSIF cmd='close' THEN
   IF v.status='CLOSED' AND c.phase='CLOSED' THEN RETURN voting_admin.read_elections(d,id)->0; END IF;
   IF v.status<>'OPEN' OR c.phase<>'OPEN' THEN RAISE EXCEPTION USING ERRCODE='P4303',MESSAGE='Election not open'; END IF;
   UPDATE voting.elections SET status='CLOSED' WHERE election_id=id;
   UPDATE voting_admin.controls SET phase='CLOSED',ra_ready=false WHERE election_id=id;
   event:='ELECTION_CLOSED';
  ELSIF cmd='ack' THEN
   IF c.phase NOT IN ('OPEN','CLOSED') OR c.config_hash IS DISTINCT FROM decode(data->>'ra_hash','hex') THEN
    RAISE EXCEPTION USING ERRCODE='P4303',MESSAGE='Publication mismatch'; END IF;
   UPDATE voting_admin.controls SET ra_ready=true WHERE election_id=id;
   event:='CONFIG_FROZEN'; reason:='RA_RECONCILED';
  ELSE RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='Unknown admin command'; END IF;
 END IF;
 INSERT INTO voting.voting_audit_events(audit_event_id,election_id,actor_type,actor_principal_id,event_type,outcome,reason_code)
 VALUES(gen_random_uuid(),id,'ADMIN',actor,event,'SUCCESS',reason);
 RETURN voting_admin.read_elections(d,id)->0;
END $f$;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA voting_admin FROM PUBLIC;
GRANT USAGE ON SCHEMA voting_admin TO voting_admin_login;
GRANT EXECUTE ON FUNCTION voting_admin.login_session(uuid,bytea),voting_admin.session(bytea),voting_admin.logout(bytea),
 voting_admin.operation(bytea,uuid,boolean),voting_admin.read_elections(bytea,uuid),voting_admin.audit(bytea,uuid),
 voting_admin.mutate(bytea,uuid,text,jsonb) TO voting_admin_login;
DO $acl$ BEGIN
 IF EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
  WHERE n.nspname='voting_admin' AND (NOT p.prosecdef OR p.proowner<>'voting_owner'::regrole OR EXISTS
   (SELECT 1 FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a
    WHERE a.privilege_type='EXECUTE' AND a.grantee<>p.proowner AND NOT
     (a.grantee='voting_admin_login'::regrole AND p.proname IN ('login_session','session','logout','operation','read_elections','audit','mutate')))))
 THEN RAISE EXCEPTION 'Unsafe admin function ACL or owner'; END IF;
 IF EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
  CROSS JOIN LATERAL aclexplode(COALESCE(c.relacl,acldefault('r',c.relowner))) a
  WHERE n.nspname='voting_admin' AND c.relkind IN ('r','p') AND a.grantee<>c.relowner)
 THEN RAISE EXCEPTION 'Unsafe admin table ACL'; END IF;
END $acl$;

""")


def downgrade():
    raise RuntimeError("Admin audit/session/configuration rollback requires explicit review")
