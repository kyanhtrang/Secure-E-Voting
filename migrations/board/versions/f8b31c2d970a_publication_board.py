"""Restricted publication and post-publication Board; existing evidence is reused."""
from alembic import op

revision = "f8b31c2d970a"
down_revision = "e6a90c72b541"
branch_labels = None
depends_on = None


def upgrade():
    op.execute("""
DO $preflight$ DECLARE r text; BEGIN
 IF (SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname=current_database()) IS DISTINCT FROM 'voting_owner'
 THEN RAISE EXCEPTION 'Unexpected database owner'; END IF;
 IF EXISTS(SELECT 1 FROM voting.publications) OR EXISTS(SELECT 1 FROM voting.elections WHERE status='PUBLISHED')
 THEN RAISE EXCEPTION 'Existing publication requires separately reviewed evidence migration'; END IF;
 FOREACH r IN ARRAY ARRAY['voting_publication_login','voting_board_login'] LOOP
  IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=r AND rolcanlogin AND NOT
    (rolsuper OR rolinherit OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls))
  OR EXISTS(SELECT 1 FROM pg_auth_members WHERE member=(SELECT oid FROM pg_roles WHERE rolname=r)
       OR roleid=(SELECT oid FROM pg_roles WHERE rolname=r))
  THEN RAISE EXCEPTION 'Provision isolated restricted publication identities'; END IF;
  IF EXISTS(SELECT 1 FROM pg_namespace n WHERE n.nspname IN ('voting','voting_admin','voting_tally','public') AND has_schema_privilege(r,n.oid,'CREATE'))
  OR EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
      WHERE n.nspname IN ('voting','voting_admin','voting_tally') AND has_function_privilege(r,p.oid,'EXECUTE'))
  OR EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname IN ('voting','voting_admin','voting_tally') AND CASE WHEN c.relkind IN ('r','p','v','m','f') THEN
     has_table_privilege(r,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
     OR has_any_column_privilege(r,c.oid,'SELECT,INSERT,UPDATE,REFERENCES')
     WHEN c.relkind='S' THEN has_sequence_privilege(r,c.oid,'USAGE,SELECT,UPDATE') ELSE false END)
  THEN RAISE EXCEPTION 'Unsafe publication runtime ACL'; END IF;
 END LOOP;
END $preflight$;
SET LOCAL ROLE voting_owner;
CREATE SCHEMA voting_board AUTHORIZATION voting_owner;
REVOKE ALL ON SCHEMA voting_board FROM PUBLIC;
CREATE TABLE voting_board.publishers(admin_id uuid PRIMARY KEY REFERENCES voting_admin.principals(admin_id),
 is_active boolean NOT NULL DEFAULT false);
CREATE TABLE voting_board.evidence(publication_id uuid PRIMARY KEY REFERENCES voting.publications(publication_id),
 bundle bytea NOT NULL CHECK(octet_length(bundle) BETWEEN 1 AND 16777216),
 bundle_digest bytea NOT NULL CHECK(bundle_digest=sha256(bundle)));
ALTER TABLE voting_admin.controls DROP CONSTRAINT controls_phase_check;
ALTER TABLE voting_admin.controls ADD CONSTRAINT controls_phase_check
 CHECK(phase IN ('DRAFT','FINALIZING','FROZEN','OPEN','CLOSED','TALLIED','PUBLISHED'));
CREATE FUNCTION voting_board._actor(d bytea) RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,voting_board,voting_admin,pg_temp AS $f$
DECLARE actor uuid;
BEGIN
 IF session_user<>'voting_publication_login' OR d IS NULL OR octet_length(d)<>32
 THEN RAISE EXCEPTION USING ERRCODE='P6401',MESSAGE='Publication authorization required'; END IF;
 SELECT s.admin_id INTO actor FROM voting_admin.sessions s JOIN voting_admin.principals p USING(admin_id)
 WHERE s.digest=d AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() AND p.is_active AND p.role='ELECTION_ADMIN' FOR SHARE OF s,p;
 IF actor IS NULL THEN RAISE EXCEPTION USING ERRCODE='P6401',MESSAGE='Publication authorization required'; END IF;
 IF NOT EXISTS(SELECT 1 FROM voting_board.publishers WHERE admin_id=actor AND is_active FOR SHARE)
 THEN RAISE EXCEPTION USING ERRCODE='P6402',MESSAGE='Publication approval required'; END IF;
 RETURN actor;
END $f$;
CREATE FUNCTION voting_board._input(e uuid) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,voting_board,voting,voting_tally,voting_admin,pg_temp AS $f$
DECLARE s uuid; state text;
BEGIN
 SELECT status INTO state FROM voting.elections WHERE election_id=e FOR UPDATE;
 IF state NOT IN ('TALLIED','PUBLISHED') OR state IS NULL OR NOT EXISTS
  (SELECT 1 FROM voting_admin.controls WHERE election_id=e AND phase=state AND ra_ready)
 THEN RAISE EXCEPTION USING ERRCODE='P6403',MESSAGE='Election not ready for publication'; END IF;
 SELECT r.snapshot_id INTO s FROM voting.tally_reports r JOIN voting.tally_jobs j ON j.tally_job_id=r.tally_id
 JOIN voting_tally.report_evidence proof ON proof.tally_id=r.tally_id AND octet_length(proof.signature)=64
 JOIN voting.final_snapshots f ON f.snapshot_id=r.snapshot_id AND f.election_id=r.election_id
 JOIN voting.elections v ON v.election_id=r.election_id
 WHERE r.election_id=e AND j.election_id=e AND j.status='SUCCEEDED' AND f.status='FINALIZED'
 AND j.snapshot_id=r.snapshot_id AND j.snapshot_digest=r.snapshot_digest AND j.election_config_digest=r.election_config_digest
 AND f.ballot_count=r.accepted_total
 AND r.snapshot_digest=f.snapshot_digest AND r.election_config_digest=v.election_config_digest
 AND f.election_config_digest=r.election_config_digest AND sha256(r.report_bytes)=r.report_digest;
 IF s IS NULL THEN RAISE EXCEPTION USING ERRCODE='P6405',MESSAGE='Committed tally unavailable'; END IF;
 PERFORM voting_tally._assert_snapshot(e,(SELECT bytes FROM voting_tally.snapshot_data WHERE snapshot_id=s));
 RETURN voting_tally._input(e,s);
END $f$;
CREATE FUNCTION voting_board.publication_input(d bytea,e uuid) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,voting_board,voting,pg_temp AS $f$
DECLARE value jsonb; raw bytea;
BEGIN
 PERFORM voting_board._actor(d);
 value:=voting_board._input(e);
 SELECT x.bundle INTO raw FROM voting.publications p JOIN voting_board.evidence x USING(publication_id) WHERE p.election_id=e;
 IF EXISTS(SELECT 1 FROM voting.elections WHERE election_id=e AND status='PUBLISHED') AND raw IS NULL
 THEN RAISE EXCEPTION USING ERRCODE='P6405',MESSAGE='Publication evidence unavailable'; END IF;
 RETURN jsonb_build_object('input',value,'published_hex',encode(raw,'hex'));
END $f$;
CREATE FUNCTION voting_board.finish(d bytea,e uuid,raw bytea,sig bytea,package bytea) RETURNS bytea LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,voting_board,voting,voting_admin,voting_tally,pg_temp AS $f$
DECLARE actor uuid; source jsonb; doc jsonb; m jsonb; report jsonb; original bytea; id uuid:=gen_random_uuid(); r voting.tally_reports%ROWTYPE;
BEGIN
 actor:=voting_board._actor(d);
 source:=voting_board._input(e); -- Election row lock held through commit; immutable snapshot/report reused.
 IF raw IS NULL OR sig IS NULL OR octet_length(sig)<>64 OR octet_length(raw)>131072
 OR package IS NULL OR octet_length(package)>16777216 THEN
  RAISE EXCEPTION USING ERRCODE='P6405',MESSAGE='Publication payload rejected'; END IF;
 doc:=convert_from(package,'UTF8')::jsonb; m:=convert_from(raw,'UTF8')::jsonb;
 report:=convert_from(decode(source->'report'->>'bytes_hex','hex'),'UTF8')::jsonb;
 SELECT * INTO r FROM voting.tally_reports WHERE election_id=e;
 IF doc-'publication' IS DISTINCT FROM jsonb_build_object('version',1,'election_id',e,
  'configuration',jsonb_build_object('manifest',convert_from(decode(source->'config'->>'manifest_hex','hex'),'UTF8')::jsonb,
      'signature',voting_tally._b64(decode(source->'config'->>'signature_hex','hex'))),
  'snapshot',convert_from(decode(source->'snapshot'->>'bytes_hex','hex'),'UTF8')::jsonb,
  'snapshot_evidence',jsonb_build_object('manifest',convert_from(decode(source->'snapshot'->>'manifest_hex','hex'),'UTF8')::jsonb,
      'signature',voting_tally._b64(decode(source->'snapshot'->>'signature_hex','hex'))),
  'tally',jsonb_build_object('report',report,'report_digest',source->'report'->>'digest',
      'signature',voting_tally._b64(decode(source->'report'->>'signature_hex','hex')),'signing_key_id',source->'snapshot'->>'key_id'))
 OR doc->'publication' IS DISTINCT FROM jsonb_build_object('manifest',m,'signature',voting_tally._b64(sig))
 OR m IS DISTINCT FROM jsonb_build_object('manifest_version',1,'election_id',e,
   'election_config_digest',encode(r.election_config_digest,'hex'),'snapshot_digest',encode(r.snapshot_digest,'hex'),
   'tally_report_digest',encode(r.report_digest,'hex'),'accepted_total',r.accepted_total,'valid_total',r.valid_total,
   'invalid_total',r.invalid_total,'counted_total',r.counted_total,'publication_key_id',m->>'publication_key_id','signature_algorithm','Ed25519')
 OR m->>'publication_key_id' IS NULL OR (m->>'publication_key_id') !~ '^[a-z0-9][a-z0-9._-]{0,127}$'
 THEN RAISE EXCEPTION USING ERRCODE='P6405',MESSAGE='Publication does not match committed tally'; END IF;
 SELECT x.bundle INTO original FROM voting.publications p JOIN voting_board.evidence x USING(publication_id) WHERE p.election_id=e;
 IF original IS NOT NULL THEN
  IF original IS DISTINCT FROM package THEN RAISE EXCEPTION USING ERRCODE='P6403',MESSAGE='Conflicting publication'; END IF;
  RETURN original;
 END IF;
 IF EXISTS(SELECT 1 FROM voting.elections WHERE election_id=e AND status<>'TALLIED')
 THEN RAISE EXCEPTION USING ERRCODE='P6403',MESSAGE='Publication state conflict'; END IF;
 actor:=voting_board._actor(d); -- Recheck DB time after lock waits and payload comparison.
 INSERT INTO voting.publications(publication_id,election_id,tally_id,snapshot_id,election_config_digest,snapshot_digest,tally_report_digest,
  manifest_bytes,manifest_signature,publication_key_id,evidence_reference)
 VALUES(id,e,r.tally_id,r.snapshot_id,r.election_config_digest,r.snapshot_digest,r.report_digest,raw,sig,m->>'publication_key_id','database:sha256:'||encode(sha256(package),'hex'));
 INSERT INTO voting_board.evidence(publication_id,bundle,bundle_digest) VALUES(id,package,sha256(package));
 UPDATE voting.elections SET status='PUBLISHED' WHERE election_id=e;
 UPDATE voting_admin.controls SET phase='PUBLISHED' WHERE election_id=e;
 INSERT INTO voting.voting_audit_events(audit_event_id,election_id,actor_type,actor_principal_id,event_type,outcome)
 VALUES(gen_random_uuid(),e,'ADMIN',actor,'ELECTION_PUBLISHED','SUCCESS');
 RETURN package;
END $f$;
CREATE FUNCTION voting_board.read_public(e uuid) RETURNS bytea LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,voting_board,voting,pg_temp AS $f$
DECLARE raw bytea;
BEGIN
 IF session_user<>'voting_board_login' THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='Board identity required'; END IF;
 IF NOT EXISTS(SELECT 1 FROM voting.elections WHERE election_id=e AND status='PUBLISHED')
 THEN RAISE EXCEPTION USING ERRCODE='P6404',MESSAGE='Published election unavailable'; END IF;
 SELECT x.bundle INTO raw FROM voting.elections v JOIN voting.publications p USING(election_id)
 JOIN voting_board.evidence x USING(publication_id) WHERE v.election_id=e AND v.status='PUBLISHED' AND sha256(x.bundle)=x.bundle_digest
 AND p.election_config_digest=v.election_config_digest
 AND (convert_from(x.bundle,'UTF8')::jsonb)->'publication'=jsonb_build_object('manifest',convert_from(p.manifest_bytes,'UTF8')::jsonb,'signature',voting_tally._b64(p.manifest_signature))
 AND (convert_from(p.manifest_bytes,'UTF8')::jsonb)->>'election_config_digest'=encode(p.election_config_digest,'hex')
 AND (convert_from(p.manifest_bytes,'UTF8')::jsonb)->>'snapshot_digest'=encode(p.snapshot_digest,'hex')
 AND (convert_from(p.manifest_bytes,'UTF8')::jsonb)->>'tally_report_digest'=encode(p.tally_report_digest,'hex');
 IF raw IS NULL THEN RAISE EXCEPTION USING ERRCODE='P6405',MESSAGE='Published evidence unavailable'; END IF;
 RETURN raw;
END $f$;
CREATE FUNCTION voting_board.catalogue(after_id uuid,max_rows integer) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,voting_board,voting,pg_temp AS $f$
BEGIN
 IF session_user<>'voting_board_login' THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='Board identity required'; END IF;
 IF max_rows IS NULL OR max_rows NOT BETWEEN 1 AND 51 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='Invalid page'; END IF;
 RETURN (SELECT COALESCE(jsonb_agg(to_jsonb(x)),'[]'::jsonb) FROM
  (SELECT v.election_id,'PUBLISHED'::text AS status FROM voting.elections v JOIN voting.publications p USING(election_id)
   JOIN voting_board.evidence b USING(publication_id) WHERE v.status='PUBLISHED' AND (after_id IS NULL OR v.election_id>after_id)
   ORDER BY v.election_id LIMIT max_rows) x);
END $f$;
CREATE FUNCTION voting_board.immutable() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,voting_board,pg_temp AS $f$
BEGIN RAISE EXCEPTION USING ERRCODE='P6405',MESSAGE='Immutable publication'; END $f$;
CREATE FUNCTION voting_board.terminal_state() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,voting_board,pg_temp AS $f$
DECLARE terminal boolean;
BEGIN
 IF TG_TABLE_NAME='elections' THEN terminal:=OLD.status='PUBLISHED'; ELSE terminal:=OLD.phase='PUBLISHED'; END IF;
 IF terminal THEN
  IF TG_OP='DELETE' OR NEW IS DISTINCT FROM OLD THEN RAISE EXCEPTION USING ERRCODE='P6403',MESSAGE='Publication is terminal'; END IF;
 END IF;
 IF TG_OP='DELETE' THEN RETURN OLD; END IF; RETURN NEW;
END $f$;
CREATE TRIGGER board_immutable_publication BEFORE UPDATE OR DELETE ON voting.publications FOR EACH ROW EXECUTE FUNCTION voting_board.immutable();
CREATE TRIGGER board_immutable_evidence BEFORE UPDATE OR DELETE ON voting_board.evidence FOR EACH ROW EXECUTE FUNCTION voting_board.immutable();
CREATE TRIGGER board_immutable_audit BEFORE UPDATE OR DELETE ON voting.voting_audit_events FOR EACH ROW
 WHEN (OLD.event_type='ELECTION_PUBLISHED') EXECUTE FUNCTION voting_board.immutable();
CREATE TRIGGER board_terminal_election BEFORE UPDATE OR DELETE ON voting.elections FOR EACH ROW EXECUTE FUNCTION voting_board.terminal_state();
CREATE TRIGGER board_terminal_control BEFORE UPDATE OR DELETE ON voting_admin.controls FOR EACH ROW EXECUTE FUNCTION voting_board.terminal_state();
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA voting_board FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA voting_board FROM PUBLIC,voting_board_login,voting_publication_login;
GRANT USAGE ON SCHEMA voting_board TO voting_board_login,voting_publication_login;
GRANT EXECUTE ON FUNCTION voting_board.publication_input(bytea,uuid),voting_board.finish(bytea,uuid,bytea,bytea,bytea) TO voting_publication_login;
GRANT EXECUTE ON FUNCTION voting_board.read_public(uuid),voting_board.catalogue(uuid,integer) TO voting_board_login;
DO $acl$ BEGIN
 IF EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='voting_board' AND
  (p.proowner<>'voting_owner'::regrole OR NOT p.prosecdef OR EXISTS
   (SELECT 1 FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a WHERE a.grantee<>p.proowner AND NOT
    (NOT a.is_grantable AND ((a.grantee='voting_publication_login'::regrole AND p.proname IN ('publication_input','finish'))
      OR (a.grantee='voting_board_login'::regrole AND p.proname IN ('read_public','catalogue')))))))
 OR EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
  CROSS JOIN LATERAL aclexplode(COALESCE(c.relacl,acldefault('r',c.relowner))) a
  WHERE n.nspname='voting_board' AND c.relkind IN ('r','p') AND a.grantee<>c.relowner)
 OR EXISTS(SELECT 1 FROM pg_namespace n CROSS JOIN LATERAL aclexplode(COALESCE(n.nspacl,acldefault('n',n.nspowner))) a
  WHERE n.nspname='voting_board' AND (n.nspowner<>'voting_owner'::regrole OR
   (a.grantee<>n.nspowner AND NOT(a.grantee IN ('voting_board_login'::regrole,'voting_publication_login'::regrole)
     AND a.privilege_type='USAGE' AND NOT a.is_grantable))))
 THEN RAISE EXCEPTION 'Unexpected Board ACL'; END IF;
END $acl$;
""")


def downgrade():
    raise RuntimeError("Publication rollback requires explicit reviewed recovery")
