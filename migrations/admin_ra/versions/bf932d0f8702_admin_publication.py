"""Prepare public policy, then first-publish enabled. Preserve one-way RA guard."""
from alembic import op

revision = "bf932d0f8702"
down_revision = "c84e13b9702d"
branch_labels = None
depends_on = None


def upgrade():
    op.execute("""
DO $$ BEGIN
 IF (SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname=current_database()) IS DISTINCT FROM 'ra_owner'
 THEN RAISE EXCEPTION 'Unexpected database owner'; END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='ra_election_publisher_login' AND rolcanlogin AND NOT
  (rolinherit OR rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls))
 OR EXISTS(SELECT 1 FROM pg_auth_members WHERE member=(SELECT oid FROM pg_roles WHERE rolname='ra_election_publisher_login'))
 THEN RAISE EXCEPTION 'Provision restricted ra_election_publisher_login separately'; END IF;
 IF pg_has_role('ra_election_publisher_login','ra_owner','MEMBER') OR
 has_schema_privilege('ra_election_publisher_login','ra','CREATE') OR has_schema_privilege('ra_election_publisher_login','public','CREATE')
 THEN RAISE EXCEPTION 'Unsafe publisher role'; END IF;
IF EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
  WHERE n.nspname IN ('ra','ra_credential','ra_demo') AND
  has_function_privilege('ra_election_publisher_login',p.oid,'EXECUTE')) THEN
  RAISE EXCEPTION 'Unexpected baseline function execution privilege'; END IF;
 IF EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='ra'
  AND CASE WHEN c.relkind='S' THEN has_sequence_privilege('ra_election_publisher_login',c.oid,'USAGE,SELECT,UPDATE') ELSE false END)
 THEN RAISE EXCEPTION 'Unexpected sequence access'; END IF;
 IF EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='ra'
  AND CASE WHEN c.relkind IN ('r','p','v','m','f') THEN
   has_table_privilege('ra_election_publisher_login',c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
   OR has_any_column_privilege('ra_election_publisher_login',c.oid,'SELECT,INSERT,UPDATE,REFERENCES') ELSE false END)
 THEN RAISE EXCEPTION 'Unexpected publisher table access'; END IF;
END $$;
SET LOCAL ROLE ra_owner;
CREATE SCHEMA ra_admin AUTHORIZATION ra_owner;
REVOKE ALL ON SCHEMA ra_admin FROM PUBLIC;
CREATE TABLE ra_admin.publications(
 election_id uuid PRIMARY KEY REFERENCES ra.ra_signing_keys(election_id),manifest_bytes bytea NOT NULL,
 signature bytea NOT NULL CHECK(octet_length(signature)=64),config_hash bytea NOT NULL CHECK(config_hash=sha256(manifest_bytes)),
 actor_id uuid NOT NULL,closed boolean NOT NULL DEFAULT false,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),closed_at timestamptz,
 CHECK(closed=(closed_at IS NOT NULL)),
 CHECK(octet_length(manifest_bytes) BETWEEN 1 AND 131072));
CREATE TABLE ra_admin.events(
 event_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),election_id uuid NOT NULL REFERENCES ra_admin.publications,
 actor_id uuid NOT NULL,action text NOT NULL CHECK(action IN ('PREPARE','ENABLE','CLOSE')),
 config_hash bytea NOT NULL CHECK(octet_length(config_hash)=32),occurred_at timestamptz NOT NULL DEFAULT clock_timestamp());
REVOKE ALL ON ALL TABLES IN SCHEMA ra_admin FROM PUBLIC,ra_election_publisher_login;
CREATE FUNCTION ra_admin._role() RETURNS void LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,ra_admin,ra,pg_temp AS $f$
BEGIN
 IF session_user<>'ra_election_publisher_login' THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='Publisher required'; END IF;
END $f$;
CREATE FUNCTION ra_admin.prepare(id uuid,raw bytea,sig bytea,spki bytea,ref text,actor uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,ra_admin,ra,pg_temp AS $f$
DECLARE m jsonb; k ra.ra_signing_keys%ROWTYPE; p ra_admin.publications%ROWTYPE;
BEGIN
 PERFORM ra_admin._role();
 PERFORM pg_advisory_xact_lock(hashtextextended(id::text,8302));
 m:=convert_from(raw,'UTF8')::jsonb;
 IF id IS NULL OR actor IS NULL OR sig IS NULL OR octet_length(sig)<>64 OR
  (m->>'election_id') IS DISTINCT FROM id::text OR (m->>'profile') IS DISTINCT FROM 'RSABSSA-SHA384-PSS-Randomized'
  OR (m->'ra_key'->>'fingerprint') IS DISTINCT FROM encode(sha256(spki),'hex')
  OR ref IS NULL OR length(ref) NOT BETWEEN 1 AND 255
 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='Invalid public policy'; END IF;
 SELECT * INTO k FROM ra.ra_signing_keys WHERE election_id=id FOR UPDATE;
 IF FOUND THEN
  IF k.ra_key_id IS DISTINCT FROM m->'ra_key'->>'key_id' OR k.public_key_spki_der IS DISTINCT FROM spki
   OR k.key_state NOT IN ('STAGED','ACTIVE') OR k.private_key_reference IS DISTINCT FROM ref THEN RAISE EXCEPTION USING ERRCODE='P4303',MESSAGE='Key conflict'; END IF;
 ELSE
  INSERT INTO ra.ra_signing_keys(ra_key_id,election_id,public_key_spki_der,public_key_fingerprint,private_key_reference)
   VALUES(m->'ra_key'->>'key_id',id,spki,sha256(spki),ref);
 END IF;
 SELECT * INTO p FROM ra_admin.publications WHERE election_id=id FOR UPDATE;
 IF FOUND THEN
  IF p.manifest_bytes IS DISTINCT FROM raw OR p.signature IS DISTINCT FROM sig THEN
   RAISE EXCEPTION USING ERRCODE='P4303',MESSAGE='Publication conflict'; END IF;
 ELSE
  IF EXISTS(SELECT 1 FROM ra.credential_policies WHERE election_id=id)
   OR EXISTS(SELECT 1 FROM ra.blind_issuances WHERE election_id=id)
   OR EXISTS(SELECT 1 FROM ra.credential_reservations WHERE election_id=id) THEN
    RAISE EXCEPTION USING ERRCODE='P4303',MESSAGE='Existing authorization policy'; END IF;
  INSERT INTO ra_admin.publications(election_id,manifest_bytes,signature,config_hash,actor_id) VALUES(id,raw,sig,sha256(raw),actor);
 END IF;
 INSERT INTO ra_admin.events(election_id,actor_id,action,config_hash) VALUES(id,actor,'PREPARE',sha256(raw));
 RETURN jsonb_build_object('config_hash',encode(sha256(raw),'hex'));
END $f$;
CREATE FUNCTION ra_admin.reconcile(id uuid,h bytea,close_it boolean,actor uuid) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,ra_admin,ra,pg_temp AS $f$
DECLARE k ra.ra_signing_keys%ROWTYPE; p ra_admin.publications%ROWTYPE; m jsonb; enabled boolean;
BEGIN
 PERFORM ra_admin._role();PERFORM pg_advisory_xact_lock(hashtextextended(id::text,8302));
 -- Same relative order as issuance: signing key, policy; no voter/eligibility locks.
 SELECT * INTO k FROM ra.ra_signing_keys WHERE election_id=id FOR UPDATE;
 PERFORM 1 FROM ra.credential_policies WHERE election_id=id FOR UPDATE;
 SELECT * INTO p FROM ra_admin.publications WHERE election_id=id FOR UPDATE;
 IF NOT FOUND OR p.config_hash IS DISTINCT FROM h OR actor IS NULL OR close_it IS NULL THEN
  RAISE EXCEPTION USING ERRCODE='P4303',MESSAGE='Unprepared publication'; END IF;
 IF close_it THEN
  UPDATE ra.credential_policies SET issuance_enabled=false WHERE election_id=id;
  UPDATE ra_admin.publications SET closed=true,closed_at=COALESCE(closed_at,clock_timestamp()) WHERE election_id=id;
 ELSE
  IF k.key_state NOT IN ('STAGED','ACTIVE') THEN RAISE EXCEPTION USING ERRCODE='P4303',MESSAGE='Signing key unavailable'; END IF;
  IF p.closed THEN RAISE EXCEPTION USING ERRCODE='P4303',MESSAGE='Closed publication'; END IF;
  m:=convert_from(p.manifest_bytes,'UTF8')::jsonb;
  IF clock_timestamp()<(m->>'opens_at')::timestamptz OR clock_timestamp()>=(m->>'closes_at')::timestamptz THEN RAISE EXCEPTION USING ERRCODE='P4303',MESSAGE='Window elapsed'; END IF;
  IF NOT EXISTS(SELECT 1 FROM ra.credential_policies WHERE election_id=id) THEN
   UPDATE ra.ra_signing_keys SET key_state='ACTIVE',activated_at=clock_timestamp() WHERE election_id=id AND key_state='STAGED';
   INSERT INTO ra.credential_policies(election_id,ra_key_id,manifest_bytes,manifest_signature,config_hash,key_fingerprint,opens_at,closes_at,issuance_enabled)
   VALUES(id,k.ra_key_id,p.manifest_bytes,p.signature,p.config_hash,k.public_key_fingerprint,
     (m->>'opens_at')::timestamptz,(m->>'closes_at')::timestamptz,true);
  END IF;
 END IF;
 SELECT issuance_enabled INTO enabled FROM ra.credential_policies WHERE election_id=id;
 IF NOT close_it AND enabled IS DISTINCT FROM true THEN RAISE EXCEPTION USING ERRCODE='P4303',MESSAGE='Issuance cannot be re-enabled'; END IF;
 INSERT INTO ra_admin.events(election_id,actor_id,action,config_hash) VALUES(id,actor,CASE WHEN close_it THEN 'CLOSE' ELSE 'ENABLE' END,p.config_hash);
 RETURN jsonb_build_object('config_hash',encode(p.config_hash,'hex'),'enabled',COALESCE(enabled,false),'closed',close_it);
END $f$;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA ra_admin FROM PUBLIC;
GRANT USAGE ON SCHEMA ra_admin TO ra_election_publisher_login;
GRANT EXECUTE ON FUNCTION ra_admin.prepare(uuid,bytea,bytea,bytea,text,uuid),ra_admin.reconcile(uuid,bytea,boolean,uuid) TO ra_election_publisher_login;
DO $acl$ BEGIN
 IF EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
  WHERE n.nspname='ra_admin' AND (NOT p.prosecdef OR p.proowner<>'ra_owner'::regrole OR EXISTS
   (SELECT 1 FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a
    WHERE a.privilege_type='EXECUTE' AND a.grantee<>p.proowner AND NOT
     (a.grantee='ra_election_publisher_login'::regrole AND p.proname IN ('prepare','reconcile')))))
 THEN RAISE EXCEPTION 'Unsafe admin function ACL or owner'; END IF;
 IF EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
  CROSS JOIN LATERAL aclexplode(COALESCE(c.relacl,acldefault('r',c.relowner))) a
  WHERE n.nspname='ra_admin' AND c.relkind IN ('r','p') AND a.grantee<>c.relowner)
 THEN RAISE EXCEPTION 'Unsafe admin table ACL'; END IF;
END $acl$;

""")


def downgrade():
    raise RuntimeError("Publication tombstones require explicit retention review")
