"""Forward-only private Tally boundary; no role provisioning or public publication."""
from alembic import op

revision = "e6a90c72b541"
down_revision = "af821c9e7601"
branch_labels = None
depends_on = None


def upgrade():
    op.execute("""
DO $$ BEGIN
 IF (SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname=current_database()) IS DISTINCT FROM 'voting_owner'
 OR NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='voting_tally_login' AND rolcanlogin AND NOT
  (rolinherit OR rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls))
 OR EXISTS(SELECT 1 FROM pg_auth_members WHERE member=(SELECT oid FROM pg_roles WHERE rolname='voting_tally_login'))
 THEN RAISE EXCEPTION 'Provision restricted Tally identity separately'; END IF;
 IF EXISTS(SELECT 1 FROM pg_namespace n WHERE n.nspname IN ('voting','voting_admin','public')
  AND has_schema_privilege('voting_tally_login',n.oid,'CREATE'))
 OR EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
  WHERE n.nspname IN ('voting','voting_admin') AND has_function_privilege('voting_tally_login',p.oid,'EXECUTE'))
 OR EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
  WHERE n.nspname IN ('voting','voting_admin') AND CASE WHEN c.relkind IN ('r','p','v','m','f') THEN
   has_table_privilege('voting_tally_login',c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
   OR has_any_column_privilege('voting_tally_login',c.oid,'SELECT,INSERT,UPDATE,REFERENCES')
   WHEN c.relkind='S' THEN has_sequence_privilege('voting_tally_login',c.oid,'USAGE,SELECT,UPDATE') ELSE false END)
 THEN RAISE EXCEPTION 'Unsafe Tally effective privileges'; END IF;
END $$;
SET LOCAL ROLE voting_owner;
CREATE SCHEMA voting_tally AUTHORIZATION voting_owner;
REVOKE ALL ON SCHEMA voting_tally FROM PUBLIC;
CREATE TABLE voting_tally.principals(operator_id uuid PRIMARY KEY,role text NOT NULL CHECK(role='TALLY_OPERATOR'),is_active boolean NOT NULL DEFAULT false);
CREATE TABLE voting_tally.sessions(digest bytea PRIMARY KEY CHECK(octet_length(digest)=32),operator_id uuid NOT NULL REFERENCES voting_tally.principals,
 created_at timestamptz NOT NULL DEFAULT statement_timestamp(),expires_at timestamptz NOT NULL DEFAULT statement_timestamp()+interval '15 minutes',revoked_at timestamptz,
 CHECK(expires_at>created_at AND expires_at<=created_at+interval '15 minutes'));
CREATE TABLE voting_tally.snapshot_data(snapshot_id uuid PRIMARY KEY REFERENCES voting.final_snapshots,
 bytes bytea NOT NULL CHECK(octet_length(bytes) BETWEEN 1 AND 16777216));
CREATE TABLE voting_tally.report_evidence(tally_id uuid PRIMARY KEY REFERENCES voting.tally_reports,
 signature bytea NOT NULL CHECK(octet_length(signature)=64));
REVOKE ALL ON ALL TABLES IN SCHEMA voting_tally FROM PUBLIC,voting_tally_login;
ALTER TABLE voting_admin.controls DROP CONSTRAINT controls_phase_check;
ALTER TABLE voting_admin.controls ADD CONSTRAINT controls_phase_check CHECK(phase IN ('DRAFT','FINALIZING','FROZEN','OPEN','CLOSED','TALLIED'));

CREATE FUNCTION voting_tally._actor(d bytea) RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,voting_tally,pg_temp AS $f$
DECLARE id uuid;
BEGIN
 IF session_user<>'voting_tally_login' THEN RAISE EXCEPTION USING ERRCODE='P5301',MESSAGE='Tally authorization required'; END IF;
 SELECT p.operator_id INTO id FROM voting_tally.sessions s JOIN voting_tally.principals p USING(operator_id)
 WHERE s.digest=d AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() AND p.is_active AND p.role='TALLY_OPERATOR' FOR SHARE OF s,p;
 IF id IS NULL THEN RAISE EXCEPTION USING ERRCODE='P5301',MESSAGE='Tally authorization required'; END IF;
 RETURN id;
END $f$;
CREATE FUNCTION voting_tally.login_session(id uuid,d bytea) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,voting_tally,pg_temp AS $f$
BEGIN
 IF session_user<>'voting_tally_login' OR d IS NULL OR octet_length(d)<>32 OR NOT EXISTS
 (SELECT 1 FROM voting_tally.principals p WHERE p.operator_id=id AND p.is_active AND p.role='TALLY_OPERATOR' FOR SHARE)
 THEN RAISE EXCEPTION USING ERRCODE='P5301',MESSAGE='Tally authorization required'; END IF;
 INSERT INTO voting_tally.sessions(digest,operator_id) VALUES(d,id);
 RETURN jsonb_build_object('operator_id',id,'role','TALLY_OPERATOR');
END $f$;
CREATE FUNCTION voting_tally.session(d bytea) RETURNS jsonb LANGUAGE sql SECURITY DEFINER
SET search_path=pg_catalog,voting_tally,pg_temp AS $f$
 SELECT jsonb_build_object('operator_id',voting_tally._actor(d),'role','TALLY_OPERATOR')
$f$;
CREATE FUNCTION voting_tally.logout(d bytea) RETURNS void LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,voting_tally,pg_temp AS $f$
BEGIN PERFORM voting_tally._actor(d); UPDATE voting_tally.sessions SET revoked_at=clock_timestamp() WHERE digest=d; END $f$;
CREATE FUNCTION voting_tally._lock(e uuid) RETURNS void LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,voting_tally,voting,pg_temp AS $f$
BEGIN
 IF e IS NULL OR NOT pg_try_advisory_xact_lock(hashtextextended(e::text,9301)) THEN
  RAISE EXCEPTION USING ERRCODE='P5302',MESSAGE='Tally operation in progress'; END IF;
 PERFORM 1 FROM voting.elections WHERE election_id=e FOR UPDATE NOWAIT;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P5304',MESSAGE='Election unavailable'; END IF;
END $f$;
CREATE FUNCTION voting_tally._b64(b bytea) RETURNS text LANGUAGE sql IMMUTABLE STRICT SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $f$ SELECT rtrim(translate(replace(encode(b,'base64'),E'\\n',''),'+/','-_'),'=') $f$;
CREATE FUNCTION voting_tally._records(e uuid) RETURNS jsonb LANGUAGE sql SECURITY DEFINER
SET search_path=pg_catalog,voting_tally,voting,pg_temp AS $f$
 SELECT COALESCE(jsonb_agg(jsonb_build_object('election_id',b.election_id,'serial',voting_tally._b64(b.serial),
  'envelope',convert_from(b.envelope,'UTF8')::jsonb,'prepared_msg',voting_tally._b64(b.prepared_msg),
  'signature',voting_tally._b64(b.signature),'receipt_hash',encode(b.receipt_hash,'hex')) ORDER BY b.receipt_hash),'[]'::jsonb)
 FROM voting.accepted_ballots b WHERE b.election_id=e
$f$;
CREATE FUNCTION voting_tally._assert_snapshot(e uuid,raw bytea) RETURNS void LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,voting_tally,voting,pg_temp AS $f$
DECLARE doc jsonb; h bytea;
BEGIN
 SELECT election_config_digest INTO h FROM voting.elections WHERE election_id=e;
 doc:=convert_from(raw,'UTF8')::jsonb;
 IF doc IS DISTINCT FROM jsonb_build_object('schema_version',1,'election_id',e,'election_config_digest',encode(h,'hex'),'ballots',voting_tally._records(e))
 OR EXISTS(SELECT 1 FROM voting.accepted_ballots b WHERE b.election_id=e AND
  (b.envelope_hash IS DISTINCT FROM sha256(b.envelope) OR b.receipt_hash IS DISTINCT FROM voting._ballot_receipt(b.election_id,b.serial,b.envelope,b.prepared_msg,b.signature)))
 THEN RAISE EXCEPTION USING ERRCODE='P5303',MESSAGE='Snapshot dataset mismatch'; END IF;
END $f$;
CREATE FUNCTION voting_tally._input(e uuid,s uuid) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,voting_tally,voting,pg_temp AS $f$
DECLARE result jsonb; f voting.final_snapshots%ROWTYPE;
BEGIN
 SELECT * INTO f FROM voting.final_snapshots WHERE snapshot_id=s AND election_id=e;
 SELECT jsonb_build_object('config',jsonb_build_object('manifest_hex',encode(c.config_bytes,'hex'),'signature_hex',encode(c.config_signature,'hex'),
  'authority_fingerprint',encode(c.config_signing_key_fingerprint,'hex'),'config_hash',encode(c.config_digest,'hex'),
  'opens_at',to_char(v.opens_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"'),
  'closes_at',to_char(v.closes_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"')),
 'snapshot',CASE WHEN f.status='FINALIZED' THEN (SELECT jsonb_build_object('bytes_hex',encode(x.bytes,'hex'),
  'manifest_hex',encode(f.manifest_bytes,'hex'),'signature_hex',encode(f.manifest_signature,'hex'),
  'digest',encode(f.snapshot_digest,'hex'),'key_id',f.signing_key_id) FROM voting_tally.snapshot_data x WHERE x.snapshot_id=s) ELSE NULL END,
 'report',(SELECT jsonb_build_object('bytes_hex',encode(r.report_bytes,'hex'),'digest',encode(r.report_digest,'hex'),
  'signature_hex',encode(p.signature,'hex')) FROM voting.tally_reports r JOIN voting_tally.report_evidence p ON p.tally_id=r.tally_id WHERE r.election_id=e),
 'records',CASE WHEN f.status='PREPARING' THEN (SELECT COALESCE(jsonb_agg(jsonb_build_object('serial_hex',encode(b.serial,'hex'),
  'envelope_hex',encode(b.envelope,'hex'),'envelope_hash',encode(b.envelope_hash,'hex'),'prepared_hex',encode(b.prepared_msg,'hex'),
  'signature_hex',encode(b.signature,'hex'),'receipt_hash',encode(b.receipt_hash,'hex')) ORDER BY b.receipt_hash),'[]'::jsonb)
  FROM voting.accepted_ballots b WHERE b.election_id=e) ELSE NULL END) INTO result
 FROM voting.elections v JOIN voting.election_configs c USING(election_id) WHERE v.election_id=e AND v.election_config_digest=c.config_digest AND sha256(c.config_bytes)=c.config_digest;
 IF result IS NULL OR (f.status='FINALIZED' AND result->'snapshot'='null'::jsonb) THEN
  RAISE EXCEPTION USING ERRCODE='P5303',MESSAGE='Tally input unavailable'; END IF;
 RETURN result;
END $f$;
CREATE FUNCTION voting_tally.claim(d bytea,e uuid) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,voting_tally,voting,voting_admin,pg_temp AS $f$
DECLARE actor uuid; v voting.elections%ROWTYPE; j voting.tally_jobs%ROWTYPE; sid uuid; jid uuid; h bytea; now_at timestamptz;
BEGIN
 actor:=voting_tally._actor(d); PERFORM voting_tally._lock(e);
 SELECT * INTO v FROM voting.elections WHERE election_id=e;
 IF v.status='TALLIED' THEN
  SELECT * INTO j FROM voting.tally_jobs WHERE election_id=e AND status='SUCCEEDED';
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P5303',MESSAGE='Missing successful tally'; END IF;
  RETURN jsonb_build_object('job_id',j.tally_job_id,'fence',j.fencing_token,'completed',true);
 END IF;
 IF v.status<>'CLOSED' OR NOT EXISTS(SELECT 1 FROM voting_admin.controls WHERE election_id=e AND phase='CLOSED' AND ra_ready)
 THEN RAISE EXCEPTION USING ERRCODE='P5302',MESSAGE='Reconciled CLOSED election required'; END IF;
 IF (SELECT count(*) FROM voting.accepted_ballots WHERE election_id=e)>1000 THEN
  RAISE EXCEPTION USING ERRCODE='P5303',MESSAGE='Local tally bound exceeded'; END IF;
 now_at:=clock_timestamp();
 SELECT * INTO j FROM voting.tally_jobs WHERE election_id=e AND status='RUNNING' FOR UPDATE;
 IF FOUND THEN
  IF j.lease_until>now_at THEN RAISE EXCEPTION USING ERRCODE='P5302',MESSAGE='Tally already active'; END IF;
  UPDATE voting.tally_jobs SET status='FAILED',finished_at=now_at,failure_code='LEASE_EXPIRED' WHERE tally_job_id=j.tally_job_id;
  UPDATE voting.final_snapshots SET status='FAILED',failed_at=now_at,failure_code='LEASE_EXPIRED' WHERE snapshot_id=j.snapshot_id AND status='PREPARING';
  INSERT INTO voting.voting_audit_events(audit_event_id,election_id,actor_type,actor_principal_id,event_type,outcome,reason_code)
   VALUES(gen_random_uuid(),e,'TALLY_OPERATOR',actor,'TALLY_JOB_RECOVERED','SUCCESS','LEASE_EXPIRED');
 END IF;
 SELECT snapshot_id,snapshot_digest INTO sid,h FROM voting.final_snapshots WHERE election_id=e AND status='FINALIZED';
 IF NOT FOUND THEN
  sid:=gen_random_uuid();h:=decode(repeat('00',32),'hex');
  INSERT INTO voting.final_snapshots(snapshot_id,election_id,election_config_digest) VALUES(sid,e,v.election_config_digest);
  INSERT INTO voting.voting_audit_events(audit_event_id,election_id,actor_type,actor_principal_id,event_type,outcome)
   VALUES(gen_random_uuid(),e,'TALLY_OPERATOR',actor,'SNAPSHOT_PREPARING','SUCCESS');
 END IF;
 jid:=gen_random_uuid();
 INSERT INTO voting.tally_jobs(tally_job_id,election_id,snapshot_id,election_config_digest,snapshot_digest,algorithm_version,
  status,fencing_token,lease_until,last_heartbeat_at,started_at)
 VALUES(jid,e,sid,v.election_config_digest,h,'evote-tally-v1','RUNNING',v.tally_fencing_token+1,now_at+interval '5 minutes',now_at,now_at);
 UPDATE voting.elections SET active_tally_job_id=jid,tally_fencing_token=tally_fencing_token+1 WHERE election_id=e;
 INSERT INTO voting.voting_audit_events(audit_event_id,election_id,actor_type,actor_principal_id,event_type,outcome)
 VALUES(gen_random_uuid(),e,'TALLY_OPERATOR',actor,'TALLY_JOB_CLAIMED','SUCCESS');
 RETURN jsonb_build_object('job_id',jid,'fence',v.tally_fencing_token+1,'completed',false);
END $f$;
CREATE FUNCTION voting_tally.work(d bytea,e uuid,id uuid,f bigint) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,voting_tally,voting,pg_temp AS $f$
DECLARE j voting.tally_jobs%ROWTYPE; v voting.elections%ROWTYPE;
BEGIN
 PERFORM voting_tally._actor(d);PERFORM voting_tally._lock(e);
 SELECT * INTO v FROM voting.elections WHERE election_id=e;
 SELECT * INTO j FROM voting.tally_jobs WHERE tally_job_id=id AND election_id=e FOR UPDATE;
 IF NOT FOUND OR j.fencing_token IS DISTINCT FROM f OR v.tally_fencing_token IS DISTINCT FROM f
  OR j.election_config_digest IS DISTINCT FROM v.election_config_digest
  OR NOT ((j.status='RUNNING' AND j.lease_until>clock_timestamp() AND v.status='CLOSED' AND v.active_tally_job_id IS NOT DISTINCT FROM id)
      OR (j.status='SUCCEEDED' AND v.status='TALLIED')) THEN
  RAISE EXCEPTION USING ERRCODE='P5302',MESSAGE='Stale tally worker'; END IF;
 RETURN voting_tally._input(e,j.snapshot_id);
END $f$;
CREATE FUNCTION voting_tally.seal(d bytea,e uuid,id uuid,f bigint,data jsonb) RETURNS void LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,voting_tally,voting,pg_temp AS $f$
DECLARE j voting.tally_jobs%ROWTYPE; raw bytea; m jsonb; h bytea; actor uuid;
BEGIN
 actor:=voting_tally._actor(d);PERFORM voting_tally.work(d,e,id,f);
 SELECT * INTO j FROM voting.tally_jobs WHERE tally_job_id=id;
 IF j.status<>'RUNNING' THEN RAISE EXCEPTION USING ERRCODE='P5302',MESSAGE='Tally already complete'; END IF;
 raw:=decode(data->>'bytes_hex','hex'); h:=sha256(raw);m:=convert_from(decode(data->>'manifest_hex','hex'),'UTF8')::jsonb;
 PERFORM voting_tally._assert_snapshot(e,raw);
 IF raw IS NULL OR octet_length(raw)>16777216 OR (data->>'digest') IS DISTINCT FROM encode(h,'hex')
  OR m IS DISTINCT FROM jsonb_build_object('manifest_version',1,'election_id',e,'election_config_digest',encode(j.election_config_digest,'hex'),
   'snapshot_schema_version',1,'snapshot_digest',encode(h,'hex'),'ballot_count',jsonb_array_length((convert_from(raw,'UTF8')::jsonb)->'ballots'),
   'digest_algorithm','SHA-256','signature_algorithm','Ed25519','signing_key_id',data->>'key_id')
 THEN RAISE EXCEPTION USING ERRCODE='P5303',MESSAGE='Snapshot manifest mismatch'; END IF;
 INSERT INTO voting_tally.snapshot_data(snapshot_id,bytes) VALUES(j.snapshot_id,raw);
 UPDATE voting.final_snapshots SET status='FINALIZED',snapshot_digest=h,ballot_count=(SELECT count(*) FROM voting.accepted_ballots WHERE election_id=e),
  snapshot_artifact_ref='private-db:'||j.snapshot_id::text,manifest_bytes=decode(data->>'manifest_hex','hex'),
  manifest_signature=decode(data->>'signature_hex','hex'),signing_key_id=data->>'key_id',evidence_reference='private-file:'||encode(h,'hex'),finalized_at=clock_timestamp()
 WHERE snapshot_id=j.snapshot_id AND status='PREPARING';
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P5303',MESSAGE='Snapshot already sealed'; END IF;
 UPDATE voting.tally_jobs SET snapshot_digest=h WHERE tally_job_id=id;
 INSERT INTO voting.voting_audit_events(audit_event_id,election_id,actor_type,actor_principal_id,event_type,outcome)
 VALUES(gen_random_uuid(),e,'TALLY_OPERATOR',actor,'SNAPSHOT_FINALIZED','SUCCESS');
END $f$;
CREATE FUNCTION voting_tally.complete(d bytea,e uuid,id uuid,f bigint,raw bytea,sig bytea) RETURNS void LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,voting_tally,voting,voting_admin,pg_temp AS $f$
DECLARE actor uuid; j voting.tally_jobs%ROWTYPE; s voting.final_snapshots%ROWTYPE; r jsonb; roster jsonb; total bigint; n integer;
BEGIN
 actor:=voting_tally._actor(d);PERFORM voting_tally.work(d,e,id,f);
 SELECT * INTO j FROM voting.tally_jobs WHERE tally_job_id=id;
 SELECT * INTO s FROM voting.final_snapshots WHERE snapshot_id=j.snapshot_id;
 IF j.status<>'RUNNING' OR s.status<>'FINALIZED' OR j.snapshot_digest IS DISTINCT FROM s.snapshot_digest
  OR s.election_config_digest IS DISTINCT FROM j.election_config_digest OR sig IS NULL OR octet_length(sig)<>64 THEN
  RAISE EXCEPTION USING ERRCODE='P5303',MESSAGE='Finalized input required'; END IF;
 PERFORM voting_tally._assert_snapshot(e,(SELECT bytes FROM voting_tally.snapshot_data WHERE snapshot_id=s.snapshot_id));
 r:=convert_from(raw,'UTF8')::jsonb;
 SELECT jsonb_agg(x->>'candidate_id' ORDER BY x->>'candidate_id') INTO roster
 FROM voting.election_configs c CROSS JOIN LATERAL jsonb_array_elements((convert_from(c.config_bytes,'UTF8')::jsonb)->'candidates') x WHERE c.election_id=e;
 SELECT sum((x->>'vote_count')::bigint),count(*) INTO total,n FROM jsonb_array_elements(r->'candidate_counts') x
 WHERE x=jsonb_build_object('candidate_id',x->>'candidate_id','vote_count',(x->>'vote_count')::bigint) AND (x->>'vote_count')::bigint>=0;
 IF r IS NULL OR r->>'election_id' IS DISTINCT FROM e::text OR r->>'election_config_digest' IS DISTINCT FROM encode(j.election_config_digest,'hex')
 OR r->>'snapshot_digest' IS DISTINCT FROM encode(s.snapshot_digest,'hex') OR r->>'algorithm_version' IS DISTINCT FROM 'evote-tally-v1'
 OR r->'report_version' IS DISTINCT FROM '1'::jsonb OR (r->>'accepted_total')::bigint IS DISTINCT FROM s.ballot_count
 OR (r->>'valid_total')::bigint IS DISTINCT FROM total OR (r->>'counted_total')::bigint IS DISTINCT FROM total
 OR (r->>'invalid_total')::bigint IS DISTINCT FROM s.ballot_count-total OR n IS DISTINCT FROM jsonb_array_length(roster)
 OR (SELECT jsonb_agg(x->>'candidate_id' ORDER BY x->>'candidate_id') FROM jsonb_array_elements(r->'candidate_counts') x) IS DISTINCT FROM roster
 OR (r->'invalid_reasons') IS DISTINCT FROM jsonb_build_object('KEY_WRAP',(r->'invalid_reasons'->>'KEY_WRAP')::bigint,'AEAD',(r->'invalid_reasons'->>'AEAD')::bigint,'PLAINTEXT',(r->'invalid_reasons'->>'PLAINTEXT')::bigint)
 OR (r->'invalid_reasons'->>'KEY_WRAP')::bigint<0 OR (r->'invalid_reasons'->>'AEAD')::bigint<0 OR (r->'invalid_reasons'->>'PLAINTEXT')::bigint<0
 OR (r->'invalid_reasons'->>'KEY_WRAP')::bigint+(r->'invalid_reasons'->>'AEAD')::bigint+(r->'invalid_reasons'->>'PLAINTEXT')::bigint IS DISTINCT FROM (r->>'invalid_total')::bigint
 OR r-ARRAY['report_version','election_id','election_config_digest','snapshot_digest','algorithm_version','accepted_total','valid_total','invalid_total','counted_total','candidate_counts','invalid_reasons']<>'{}'::jsonb
 THEN RAISE EXCEPTION USING ERRCODE='P5303',MESSAGE='Aggregate report mismatch'; END IF;
 INSERT INTO voting.tally_reports(tally_id,election_id,snapshot_id,election_config_digest,snapshot_digest,accepted_total,valid_total,invalid_total,counted_total,
  candidate_counts,algorithm_version,report_bytes,report_digest) VALUES(id,e,j.snapshot_id,j.election_config_digest,s.snapshot_digest,(r->>'accepted_total')::bigint,total,
  (r->>'invalid_total')::bigint,total,r->'candidate_counts','evote-tally-v1',raw,sha256(raw));
 INSERT INTO voting_tally.report_evidence(tally_id,signature) VALUES(id,sig);
 UPDATE voting.tally_jobs SET status='SUCCEEDED',finished_at=clock_timestamp() WHERE tally_job_id=id AND lease_until>clock_timestamp();
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P5302',MESSAGE='Expired tally lease'; END IF;
 UPDATE voting.elections SET status='TALLIED',active_tally_job_id=NULL WHERE election_id=e;
 UPDATE voting_admin.controls SET phase='TALLIED' WHERE election_id=e;
 INSERT INTO voting.voting_audit_events(audit_event_id,election_id,actor_type,actor_principal_id,event_type,outcome,reason_code)
 VALUES(gen_random_uuid(),e,'TALLY_OPERATOR',actor,'TALLY_JOB_SUCCEEDED','SUCCESS',CASE WHEN (r->>'invalid_total')::bigint>0 THEN 'INVALID_BALLOTS_PRESENT' ELSE NULL END),
       (gen_random_uuid(),e,'TALLY_OPERATOR',actor,'ELECTION_TALLIED','SUCCESS',NULL);
END $f$;
CREATE FUNCTION voting_tally.fail(d bytea,e uuid,id uuid,f bigint,reason text) RETURNS void LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,voting_tally,voting,pg_temp AS $f$
DECLARE actor uuid;j voting.tally_jobs%ROWTYPE;
BEGIN
 actor:=voting_tally._actor(d);PERFORM voting_tally._lock(e);
 SELECT * INTO j FROM voting.tally_jobs WHERE tally_job_id=id AND election_id=e FOR UPDATE;
 IF NOT FOUND OR j.fencing_token IS DISTINCT FROM f OR j.status<>'RUNNING' OR
  reason IS NULL OR reason NOT IN ('KEY_UNAVAILABLE','INTEGRITY','UNAVAILABLE') THEN
  RAISE EXCEPTION USING ERRCODE='P5302',MESSAGE='Stale tally failure'; END IF;
 UPDATE voting.tally_jobs SET status='FAILED',finished_at=clock_timestamp(),failure_code=reason WHERE tally_job_id=id;
 UPDATE voting.final_snapshots SET status='FAILED',failed_at=clock_timestamp(),failure_code=reason WHERE snapshot_id=j.snapshot_id AND status='PREPARING';
 UPDATE voting.elections SET active_tally_job_id=NULL WHERE election_id=e AND active_tally_job_id=id;
 INSERT INTO voting.voting_audit_events(audit_event_id,election_id,actor_type,actor_principal_id,event_type,outcome,reason_code)
 VALUES(gen_random_uuid(),e,'TALLY_OPERATOR',actor,'TALLY_JOB_FAILED','ERROR',reason);
END $f$;
CREATE FUNCTION voting_tally.list_elections(d bytea) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,voting_tally,voting,voting_admin,pg_temp AS $f$
DECLARE result jsonb;
BEGIN
 PERFORM voting_tally._actor(d);
 SELECT COALESCE(jsonb_agg(to_jsonb(x)),'[]'::jsonb) INTO result FROM
 (SELECT e.election_id,e.title,e.status,c.ra_ready FROM voting.elections e JOIN voting_admin.controls c USING(election_id)
  WHERE e.status IN ('CLOSED','TALLIED') ORDER BY e.election_id LIMIT 200) x;
 RETURN result;
END $f$;
CREATE FUNCTION voting_tally.view_report(d bytea,e uuid) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,voting_tally,voting,pg_temp AS $f$
DECLARE s uuid;
BEGIN
 PERFORM voting_tally._actor(d);PERFORM voting_tally._lock(e);
 SELECT r.snapshot_id INTO s FROM voting.tally_reports r JOIN voting.elections v USING(election_id) WHERE r.election_id=e AND v.status='TALLIED';
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P5304',MESSAGE='Report unavailable'; END IF;
 RETURN voting_tally._input(e,s);
END $f$;
CREATE FUNCTION voting_tally.immutable() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,voting_tally,voting,pg_temp AS $f$
DECLARE state text;
BEGIN
 IF TG_TABLE_NAME='final_snapshots' THEN
  IF OLD.status<>'FINALIZED' THEN
   IF TG_OP='DELETE' THEN RETURN OLD; END IF; RETURN NEW;
  END IF;
 END IF;
 IF TG_TABLE_NAME='accepted_ballots' AND TG_OP='INSERT' THEN
  SELECT status INTO state FROM voting.elections WHERE election_id=NEW.election_id FOR SHARE;
  IF state='OPEN' THEN RETURN NEW; END IF;
 END IF;
 RAISE EXCEPTION USING ERRCODE='P5303',MESSAGE='Immutable tally evidence';
END $f$;
CREATE TRIGGER tally_immutable_ballot BEFORE INSERT OR UPDATE OR DELETE ON voting.accepted_ballots FOR EACH ROW EXECUTE FUNCTION voting_tally.immutable();
CREATE TRIGGER tally_immutable_snapshot BEFORE UPDATE OR DELETE ON voting.final_snapshots FOR EACH ROW EXECUTE FUNCTION voting_tally.immutable();
CREATE TRIGGER tally_immutable_report BEFORE UPDATE OR DELETE ON voting.tally_reports FOR EACH ROW EXECUTE FUNCTION voting_tally.immutable();
CREATE TRIGGER tally_immutable_data BEFORE UPDATE OR DELETE ON voting_tally.snapshot_data FOR EACH ROW EXECUTE FUNCTION voting_tally.immutable();
CREATE TRIGGER tally_immutable_report_evidence BEFORE UPDATE OR DELETE ON voting_tally.report_evidence FOR EACH ROW EXECUTE FUNCTION voting_tally.immutable();
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA voting_tally FROM PUBLIC;
GRANT USAGE ON SCHEMA voting_tally TO voting_tally_login;
GRANT EXECUTE ON FUNCTION voting_tally.login_session(uuid,bytea),voting_tally.session(bytea),voting_tally.logout(bytea),
 voting_tally.claim(bytea,uuid),voting_tally.work(bytea,uuid,uuid,bigint),voting_tally.seal(bytea,uuid,uuid,bigint,jsonb),
 voting_tally.complete(bytea,uuid,uuid,bigint,bytea,bytea),voting_tally.fail(bytea,uuid,uuid,bigint,text),
 voting_tally.list_elections(bytea),voting_tally.view_report(bytea,uuid) TO voting_tally_login;
DO $acl$ BEGIN
 IF EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
  WHERE n.nspname='voting_tally' AND (p.proowner<>'voting_owner'::regrole OR NOT p.prosecdef OR EXISTS
  (SELECT 1 FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a WHERE a.grantee<>p.proowner AND NOT
   (a.grantee='voting_tally_login'::regrole AND p.proname IN ('login_session','session','logout','claim','work','seal','complete','fail','list_elections','view_report') AND NOT a.is_grantable))))
 THEN RAISE EXCEPTION 'Unexpected Tally function ACL'; END IF;
 IF EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
  CROSS JOIN LATERAL aclexplode(COALESCE(c.relacl,acldefault('r',c.relowner))) a WHERE n.nspname='voting_tally' AND c.relkind IN ('r','p') AND a.grantee<>c.relowner)
 THEN RAISE EXCEPTION 'Unexpected Tally table ACL'; END IF;
END $acl$;
""")


def downgrade():
    raise RuntimeError("Tally snapshots, reports and audit retention require reviewed recovery")
