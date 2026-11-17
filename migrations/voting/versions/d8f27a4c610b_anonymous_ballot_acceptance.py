"""Restricted anonymous acceptance; reuse the Voting baseline. Forward-only.

Revision ID: d8f27a4c610b
Revises: b5bd58a07ceb
"""

from alembic import op

revision = "d8f27a4c610b"
down_revision = "b5bd58a07ceb"
branch_labels = None
depends_on = None


def upgrade():
    op.execute("""
DO $preflight$
DECLARE r record;
BEGIN
  IF EXISTS (
    SELECT 1 FROM (VALUES ('voting_owner'),('voting_admin_service'),('voting_ballot_service'),
      ('voting_snapshot_worker'),('voting_tally_worker'),('voting_publication_service'),
      ('voting_board_reader'),('voting_audit_reader')) AS required(name)
    LEFT JOIN pg_catalog.pg_roles p ON p.rolname=required.name WHERE p.oid IS NULL
  ) THEN RAISE EXCEPTION 'Required Voting roles absent'; END IF;
  FOR r IN SELECT * FROM pg_catalog.pg_roles WHERE rolname IN
    ('voting_owner','voting_ballot_service','voting_ballot_login') LOOP
    IF r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls
       OR (r.rolname IN ('voting_owner','voting_ballot_service') AND r.rolcanlogin) THEN
      RAISE EXCEPTION 'Unsafe Voting role attributes';
    END IF;
  END LOOP;
  -- The application role is not an administrator or another worker through inheritance.
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m
    JOIN pg_catalog.pg_roles child ON child.oid=m.member
    JOIN pg_catalog.pg_roles parent ON parent.oid=m.roleid
    WHERE (child.rolname='voting_ballot_service') OR
      (child.rolname='voting_ballot_login' AND parent.rolname<>'voting_ballot_service')) THEN
    RAISE EXCEPTION 'Unexpected Voting runtime memberships';
  END IF;
  FOR r IN SELECT rolname FROM pg_catalog.pg_roles
    WHERE rolname IN ('voting_ballot_service','voting_ballot_login') LOOP
    IF pg_catalog.has_schema_privilege(r.rolname,'voting','CREATE') OR
       pg_catalog.has_schema_privilege(r.rolname,'public','CREATE') OR
       pg_catalog.pg_has_role(r.rolname,'voting_owner','MEMBER') OR EXISTS (
        SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname='voting' AND c.relkind IN ('r','p','v','m','f') AND
          (pg_catalog.has_table_privilege(r.rolname,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
           OR pg_catalog.has_any_column_privilege(r.rolname,c.oid,'SELECT,INSERT,UPDATE,REFERENCES'))
       ) OR EXISTS (
        SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname='voting' AND c.relkind='S' AND
          pg_catalog.has_sequence_privilege(r.rolname,c.oid,'USAGE,SELECT,UPDATE')
       ) OR EXISTS (
        SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
        WHERE n.nspname='voting' AND pg_catalog.has_function_privilege(r.rolname,p.oid,'EXECUTE')
       ) THEN RAISE EXCEPTION 'Existing Voting runtime ACLs require review'; END IF;
  END LOOP;
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='voting' AND c.relkind IN ('r','p') AND
      c.relowner<>(SELECT oid FROM pg_catalog.pg_roles WHERE rolname='voting_owner')) THEN
    RAISE EXCEPTION 'Unexpected Voting table ownership';
  END IF;
END
$preflight$;
SET LOCAL ROLE voting_owner;
"""
    )
    op.execute("""
CREATE FUNCTION voting.guard_frozen_config() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,voting,pg_temp AS $f$
BEGIN
  IF TG_TABLE_NAME='election_configs' THEN
    RAISE EXCEPTION 'Frozen configuration is immutable';
  END IF;
  IF OLD.status<>'DRAFT' AND
    (NEW.election_config_digest IS DISTINCT FROM OLD.election_config_digest OR
     NEW.opens_at IS DISTINCT FROM OLD.opens_at OR NEW.closes_at IS DISTINCT FROM OLD.closes_at) THEN
    RAISE EXCEPTION 'Frozen election policy is immutable';
  END IF;
  RETURN NEW;
END $f$;
CREATE TRIGGER immutable_frozen_config BEFORE UPDATE ON voting.election_configs
FOR EACH ROW EXECUTE FUNCTION voting.guard_frozen_config();
CREATE TRIGGER immutable_election_policy BEFORE UPDATE ON voting.elections
FOR EACH ROW EXECUTE FUNCTION voting.guard_frozen_config();

CREATE FUNCTION voting.ballot_policy(p_election uuid)
RETURNS TABLE(manifest_bytes bytea, signature bytea, config_digest bytea,
              authority_fingerprint bytea, opens_at timestamptz, closes_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,voting,pg_temp AS $f$
BEGIN
  RETURN QUERY SELECT c.config_bytes,c.config_signature,c.config_digest,
    c.config_signing_key_fingerprint,e.opens_at,e.closes_at
    FROM voting.elections e JOIN voting.election_configs c USING(election_id)
    WHERE e.election_id=p_election AND e.status<>'DRAFT'
      AND e.election_config_digest=c.config_digest
      AND pg_catalog.sha256(c.config_bytes)=c.config_digest;
END $f$;

-- All receipt fields have ASCII-only canonical encodings; lexical field order is JCS order.
-- No JSONB textual formatting is used. PostgreSQL base64 line breaks are removed.
CREATE FUNCTION voting._ballot_receipt(p_election uuid,p_serial bytea,p_envelope bytea,
                                     p_prepared bytea,p_signature bytea) RETURNS bytea
LANGUAGE sql IMMUTABLE STRICT SECURITY DEFINER SET search_path=pg_catalog,voting,pg_temp AS $f$
  SELECT pg_catalog.sha256(pg_catalog.convert_to('EVOTE-RECEIPT-v1','UTF8') ||
    pg_catalog.decode('00','hex') || pg_catalog.convert_to(
    '{"election_id":"' || p_election::text || '","envelope_hash":"' ||
    pg_catalog.encode(pg_catalog.sha256(p_envelope),'hex') || '","prepared_msg":"' ||
    pg_catalog.rtrim(pg_catalog.translate(pg_catalog.replace(pg_catalog.encode(p_prepared,'base64'),E'\\n',''),'+/','-_'),'=') ||
    '","serial":"' ||
    pg_catalog.rtrim(pg_catalog.translate(pg_catalog.replace(pg_catalog.encode(p_serial,'base64'),E'\\n',''),'+/','-_'),'=') ||
    '","signature":"' ||
    pg_catalog.rtrim(pg_catalog.translate(pg_catalog.replace(pg_catalog.encode(p_signature,'base64'),E'\\n',''),'+/','-_'),'=') ||
    '"}', 'UTF8'));
$f$;

CREATE FUNCTION voting.accept_anonymous_ballot(p_election uuid,p_config bytea,p_serial bytea,
    p_envelope bytea,p_prepared bytea,p_signature bytea) RETURNS bytea
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,voting,pg_temp AS $f$
DECLARE e voting.elections%ROWTYPE; c voting.election_configs%ROWTYPE;
        decision timestamptz; receipt bytea;
BEGIN
  IF p_election IS NULL OR p_config IS NULL OR pg_catalog.octet_length(p_config)<>32
    OR p_serial IS NULL OR pg_catalog.octet_length(p_serial)<>32
    OR p_envelope IS NULL OR pg_catalog.octet_length(p_envelope) NOT BETWEEN 1 AND 16384
    OR p_prepared IS NULL OR pg_catalog.octet_length(p_prepared) NOT BETWEEN 33 AND 8192
    OR p_signature IS NULL OR pg_catalog.octet_length(p_signature)<>384 THEN
    RAISE EXCEPTION USING ERRCODE='P4204',MESSAGE='Invalid ballot data';
  END IF;
  -- Universal lock order: election, frozen configuration, accepted serial.
  SELECT * INTO e FROM voting.elections WHERE election_id=p_election FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P4201',MESSAGE='Election not open'; END IF;
  SELECT * INTO c FROM voting.election_configs WHERE election_id=p_election FOR SHARE;
  IF NOT FOUND OR e.election_config_digest IS DISTINCT FROM p_config
    OR c.config_digest IS DISTINCT FROM p_config
    OR pg_catalog.sha256(c.config_bytes) IS DISTINCT FROM p_config THEN
    RAISE EXCEPTION USING ERRCODE='P4204',MESSAGE='Election policy unavailable';
  END IF;
  IF EXISTS(SELECT 1 FROM voting.accepted_ballots WHERE election_id=p_election AND serial=p_serial) THEN
    RAISE EXCEPTION USING ERRCODE='P4202',MESSAGE='Credential spent';
  END IF;
  decision := pg_catalog.clock_timestamp();
  IF e.status<>'OPEN' OR decision<e.opens_at OR decision>=e.closes_at THEN
    RAISE EXCEPTION USING ERRCODE='P4201',MESSAGE='Election not open';
  END IF;
  receipt := voting._ballot_receipt(p_election,p_serial,p_envelope,p_prepared,p_signature);
  INSERT INTO voting.accepted_ballots(ballot_id,election_id,serial,envelope,prepared_msg,signature,
    envelope_hash,receipt_hash) VALUES(pg_catalog.gen_random_uuid(),p_election,p_serial,p_envelope,
      p_prepared,p_signature,pg_catalog.sha256(p_envelope),receipt);
  RETURN receipt;
END $f$;

CREATE FUNCTION voting.recover_ballot_receipt(p_election uuid,p_config bytea,p_serial bytea,
    p_envelope bytea,p_prepared bytea,p_signature bytea) RETURNS bytea
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,voting,pg_temp AS $f$
DECLARE receipt bytea;
BEGIN
  -- Recovery never writes, never reveals timestamps, and may run after closing.
  SELECT b.receipt_hash INTO receipt FROM voting.accepted_ballots b
    JOIN voting.elections e USING(election_id) JOIN voting.election_configs c USING(election_id)
    WHERE b.election_id=p_election AND b.serial=p_serial
      AND e.election_config_digest=p_config AND c.config_digest=p_config
      AND pg_catalog.sha256(c.config_bytes)=p_config
      AND b.envelope=p_envelope AND b.prepared_msg=p_prepared AND b.signature=p_signature
      AND b.receipt_hash=voting._ballot_receipt(p_election,p_serial,p_envelope,p_prepared,p_signature);
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P4203',MESSAGE='Receipt not found'; END IF;
  RETURN receipt;
END $f$;
"""
    )
    # Named revocations include every baseline worker. No generic table/function grants.
    for signature in (
        "guard_frozen_config()", "ballot_policy(uuid)",
        "_ballot_receipt(uuid,bytea,bytea,bytea,bytea)",
        "accept_anonymous_ballot(uuid,bytea,bytea,bytea,bytea,bytea)",
        "recover_ballot_receipt(uuid,bytea,bytea,bytea,bytea,bytea)",
    ):
        op.execute(f"ALTER FUNCTION voting.{signature} OWNER TO voting_owner")
        op.execute(f"REVOKE ALL ON FUNCTION voting.{signature} FROM PUBLIC, voting_admin_service, "
                   "voting_ballot_service, voting_snapshot_worker, voting_tally_worker, "
                   "voting_publication_service, voting_board_reader, voting_audit_reader")
    op.execute("GRANT USAGE ON SCHEMA voting TO voting_ballot_service")
    for signature in ("ballot_policy(uuid)",
                      "accept_anonymous_ballot(uuid,bytea,bytea,bytea,bytea,bytea)",
                      "recover_ballot_receipt(uuid,bytea,bytea,bytea,bytea,bytea)"):
        op.execute(f"GRANT EXECUTE ON FUNCTION voting.{signature} TO voting_ballot_service")
    op.execute("""
DO $acl$
DECLARE p record; runtime_oid oid;
BEGIN
  SELECT oid INTO runtime_oid FROM pg_catalog.pg_roles WHERE rolname='voting_ballot_service';
  FOR p IN SELECT f.oid,f.proname,f.proowner,f.proacl FROM pg_catalog.pg_proc f
    JOIN pg_catalog.pg_namespace n ON n.oid=f.pronamespace WHERE n.nspname='voting' LOOP
    IF EXISTS(SELECT 1 FROM pg_catalog.aclexplode(COALESCE(p.proacl,
      pg_catalog.acldefault('f',p.proowner))) a WHERE a.privilege_type='EXECUTE'
      AND a.grantee<>p.proowner AND NOT(a.grantee=runtime_oid AND p.proname IN
      ('ballot_policy','accept_anonymous_ballot','recover_ballot_receipt'))) THEN
      RAISE EXCEPTION 'Unexpected Voting function ACL';
    END IF;
  END LOOP;
END $acl$;
"""
    )


def downgrade():
    raise RuntimeError("Forward-only Voting security migration; reviewed recovery required")
