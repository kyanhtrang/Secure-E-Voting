"""Durable RA-only authorization; preserve completed issuance and all old ACLs.

Revision ID: 7b2d91a6c840
Revises: f3c2a1d4e6b8
"""

from alembic import op

revision = "7b2d91a6c840"
down_revision = "f3c2a1d4e6b8"
branch_labels = None
depends_on = None


def upgrade():
    op.execute("""
        DO $$
        BEGIN
            IF EXISTS (
                SELECT 1 FROM (VALUES ('ra_owner'),('ra_auth_login'),('ra_issuance_login'),
                    ('ra_service'),('ra_service_login'),('ra_recovery_worker'),('ra_audit_reader')) AS required(name)
                WHERE NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles r WHERE r.rolname=required.name)
            ) THEN RAISE EXCEPTION 'Required RA issuance roles are absent; provision separately'; END IF;
            IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='ra_owner'
                AND (rolsuper OR rolcanlogin OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls))
            THEN RAISE EXCEPTION 'Unsafe RA owner role attributes'; END IF;
            IF EXISTS (
                SELECT 1 FROM pg_catalog.pg_roles r WHERE r.rolname IN ('ra_auth_login','ra_issuance_login')
                AND (NOT r.rolcanlogin OR r.rolinherit OR r.rolsuper OR r.rolcreatedb OR r.rolcreaterole
                     OR r.rolreplication OR r.rolbypassrls)
            ) OR EXISTS (
                SELECT 1 FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles r
                ON r.oid IN (m.member,m.roleid) WHERE r.rolname IN ('ra_auth_login','ra_issuance_login')
            ) THEN RAISE EXCEPTION 'Unsafe RA issuance role attributes or memberships'; END IF;
            IF EXISTS (
                SELECT 1 FROM (VALUES ('ra_auth_login'),('ra_issuance_login')) a(name)
                WHERE pg_catalog.has_schema_privilege(a.name,'ra','USAGE')
                   OR pg_catalog.has_schema_privilege(a.name,'ra','CREATE')
            ) OR EXISTS (
                SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
                CROSS JOIN (VALUES ('ra_auth_login'),('ra_issuance_login')) a(name)
                WHERE n.nspname='ra' AND pg_catalog.has_function_privilege(a.name,p.oid,'EXECUTE')
            ) OR EXISTS (
                SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
                CROSS JOIN (VALUES ('ra_auth_login'),('ra_issuance_login')) a(name)
                CROSS JOIN (VALUES ('SELECT'),('INSERT'),('UPDATE'),('REFERENCES')) x(privilege)
                WHERE n.nspname='ra' AND c.relkind IN ('r','p','v','m','f')
                  AND pg_catalog.has_any_column_privilege(a.name,c.oid,x.privilege)
            ) OR EXISTS (
                SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
                CROSS JOIN (VALUES ('ra_auth_login'),('ra_issuance_login')) a(name)
                CROSS JOIN (VALUES ('SELECT'),('INSERT'),('UPDATE'),('DELETE'),('TRUNCATE'),('REFERENCES'),('TRIGGER')) x(privilege)
                WHERE n.nspname='ra' AND c.relkind IN ('r','p','v','m','f')
                  AND pg_catalog.has_table_privilege(a.name,c.oid,x.privilege)
            ) OR EXISTS (
                SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
                CROSS JOIN (VALUES ('ra_auth_login'),('ra_issuance_login')) a(name)
                CROSS JOIN (VALUES ('SELECT'),('UPDATE'),('USAGE')) x(privilege)
                WHERE n.nspname='ra' AND c.relkind='S'
                  AND pg_catalog.has_sequence_privilege(a.name,c.oid,x.privilege)
            ) THEN RAISE EXCEPTION 'Existing RA authorization boundary is unsafe'; END IF;
        END $$;
    """)
    op.execute("SET LOCAL ROLE ra_owner")
    op.execute("CREATE SCHEMA ra_credential AUTHORIZATION ra_owner")
    op.execute("REVOKE ALL ON SCHEMA ra_credential FROM PUBLIC, ra_auth_login, ra_issuance_login")
    op.execute("""
        CREATE TABLE ra.credential_policies (
            election_id uuid PRIMARY KEY,
            ra_key_id text NOT NULL,
            manifest_bytes bytea NOT NULL CHECK (octet_length(manifest_bytes) BETWEEN 1 AND 131072),
            manifest_signature bytea NOT NULL CHECK (octet_length(manifest_signature)=64),
            config_hash bytea NOT NULL CHECK (octet_length(config_hash)=32),
            key_fingerprint bytea NOT NULL UNIQUE CHECK (octet_length(key_fingerprint)=32),
            opens_at timestamptz NOT NULL,
            closes_at timestamptz NOT NULL CHECK (closes_at>opens_at),
            issuance_enabled boolean NOT NULL DEFAULT false,
            FOREIGN KEY (election_id,ra_key_id) REFERENCES ra.ra_signing_keys(election_id,ra_key_id) ON DELETE RESTRICT,
            CHECK (config_hash=pg_catalog.sha256(manifest_bytes))
        )
    """)
    op.execute("""
        CREATE TABLE ra.credential_reservations (
            reservation_id uuid PRIMARY KEY DEFAULT pg_catalog.gen_random_uuid(),
            voter_id uuid NOT NULL,
            election_id uuid NOT NULL REFERENCES ra.credential_policies(election_id) ON DELETE RESTRICT,
            request_id uuid NOT NULL,
            blinded_request_hash bytea NOT NULL CHECK (octet_length(blinded_request_hash)=32),
            ra_key_id text NOT NULL,
            config_hash bytea NOT NULL CHECK (octet_length(config_hash)=32),
            reserved_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
            recovery_expires_at timestamptz NOT NULL CHECK (recovery_expires_at>reserved_at),
            UNIQUE (voter_id,election_id),
            FOREIGN KEY (voter_id,election_id) REFERENCES ra.voter_eligibility(voter_id,election_id) ON DELETE RESTRICT,
            FOREIGN KEY (election_id,ra_key_id) REFERENCES ra.ra_signing_keys(election_id,ra_key_id) ON DELETE RESTRICT
        )
    """)
    op.execute("""
        REVOKE ALL ON TABLE ra.credential_policies,ra.credential_reservations
        FROM PUBLIC,ra_auth_login,ra_issuance_login,ra_service,ra_service_login,ra_recovery_worker,ra_audit_reader
    """)
    op.execute("""
        CREATE TYPE ra_credential.request_context AS (
            reservation_id uuid,voter_id uuid,election_id uuid,request_id uuid,
            blinded_hash bytea,key_id text,config_hash bytea,reserved_at timestamptz,
            recovery_expires_at timestamptz,issuance_id uuid,ciphertext bytea,nonce bytea,storage_key_id text
        )
    """)
    op.execute("REVOKE ALL ON TYPE ra_credential.request_context FROM PUBLIC,ra_auth_login,ra_issuance_login")
    op.execute("""
        CREATE FUNCTION ra_credential.guard_policy() RETURNS trigger
        LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,ra,pg_temp AS $f$
        DECLARE k ra.ra_signing_keys%ROWTYPE; m jsonb;
        BEGIN
            IF TG_OP='DELETE' THEN
                IF EXISTS (SELECT 1 FROM ra.blind_issuances b WHERE b.election_id=OLD.election_id) THEN
                    RAISE EXCEPTION 'Policy is retained with issuance tombstones';
                END IF;
                RETURN OLD;
            END IF;
            IF TG_OP='UPDATE' THEN
                IF ROW(NEW.election_id,NEW.ra_key_id,NEW.manifest_bytes,NEW.manifest_signature,
                       NEW.config_hash,NEW.key_fingerprint,NEW.opens_at,NEW.closes_at)
                   IS DISTINCT FROM ROW(OLD.election_id,OLD.ra_key_id,OLD.manifest_bytes,OLD.manifest_signature,
                       OLD.config_hash,OLD.key_fingerprint,OLD.opens_at,OLD.closes_at)
                   OR (NOT OLD.issuance_enabled AND NEW.issuance_enabled) THEN
                    RAISE EXCEPTION 'Credential policy is immutable';
                END IF;
            END IF;
            SELECT * INTO k FROM ra.ra_signing_keys s WHERE s.election_id=NEW.election_id AND s.ra_key_id=NEW.ra_key_id FOR SHARE;
            m:=pg_catalog.convert_from(NEW.manifest_bytes,'UTF8')::jsonb;
            IF NOT FOUND OR k.signature_profile IS DISTINCT FROM 'RSABSSA-SHA384-PSS-Randomized'
               OR k.public_key_fingerprint IS DISTINCT FROM NEW.key_fingerprint
               OR pg_catalog.sha256(k.public_key_spki_der) IS DISTINCT FROM NEW.key_fingerprint
               OR (m->>'election_id') IS DISTINCT FROM NEW.election_id::text
               OR (m->'ra_key'->>'key_id') IS DISTINCT FROM NEW.ra_key_id
               OR (m->>'opens_at')::timestamptz IS DISTINCT FROM NEW.opens_at
               OR (m->>'closes_at')::timestamptz IS DISTINCT FROM NEW.closes_at
               OR (m->>'profile') IS DISTINCT FROM 'RSABSSA-SHA384-PSS-Randomized' THEN
                RAISE EXCEPTION 'Inconsistent credential policy';
            END IF;
            RETURN NEW;
        END $f$
    """)
    op.execute("CREATE TRIGGER credential_policy_guard BEFORE INSERT OR UPDATE OR DELETE ON ra.credential_policies FOR EACH ROW EXECUTE FUNCTION ra_credential.guard_policy()")
    op.execute("""
        CREATE FUNCTION ra_credential.guard_reservation() RETURNS trigger
        LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,ra,pg_temp AS $f$
        BEGIN RAISE EXCEPTION 'Credential reservations are immutable'; END $f$
    """)
    op.execute("CREATE TRIGGER credential_reservation_guard BEFORE UPDATE ON ra.credential_reservations FOR EACH ROW EXECUTE FUNCTION ra_credential.guard_reservation()")
    op.execute("""
        CREATE FUNCTION ra_credential.guard_key_material() RETURNS trigger
        LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,ra,pg_temp AS $f$
        BEGIN
            IF ROW(OLD.election_id,OLD.ra_key_id,OLD.public_key_spki_der,OLD.public_key_fingerprint,OLD.signature_profile)
               IS DISTINCT FROM ROW(NEW.election_id,NEW.ra_key_id,NEW.public_key_spki_der,NEW.public_key_fingerprint,NEW.signature_profile)
               AND EXISTS (SELECT 1 FROM ra.credential_policies p WHERE p.election_id=OLD.election_id) THEN
                RAISE EXCEPTION 'Enrolled signing key material is immutable';
            END IF;
            RETURN NEW;
        END $f$
    """)
    op.execute("CREATE TRIGGER credential_key_guard BEFORE UPDATE ON ra.ra_signing_keys FOR EACH ROW EXECUTE FUNCTION ra_credential.guard_key_material()")
    op.execute("""
        CREATE FUNCTION ra_credential._voter(p_digest text) RETURNS uuid
        LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,ra,pg_temp AS $f$
        DECLARE id uuid; active boolean;
        BEGIN
            SELECT s.voter_id INTO id FROM ra.find_active_session(p_digest) s;
            IF id IS NULL THEN RAISE EXCEPTION 'Invalid session' USING ERRCODE='P4101'; END IF;
            SELECT v.is_active INTO active FROM ra.voters v WHERE v.voter_id=id FOR UPDATE;
            IF active IS DISTINCT FROM true THEN RAISE EXCEPTION 'Invalid session' USING ERRCODE='P4101'; END IF;
            PERFORM 1 FROM ra.ra_sessions s WHERE s.token_digest=p_digest AND s.voter_id=id
                AND s.revoked_at IS NULL AND s.expires_at>pg_catalog.clock_timestamp() FOR SHARE;
            IF NOT FOUND THEN RAISE EXCEPTION 'Invalid session' USING ERRCODE='P4101'; END IF;
            RETURN id;
        END $f$
    """)
    op.execute("""
        CREATE FUNCTION ra_credential.policy_for_session(p_digest text,p_election uuid)
        RETURNS TABLE(manifest_bytes bytea,manifest_signature bytea,config_hash bytea,key_id text,spki_der bytea,key_fingerprint bytea)
        LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,ra,pg_temp AS $f$
        BEGIN
            PERFORM ra_credential._voter(p_digest);
            RETURN QUERY SELECT p.manifest_bytes,p.manifest_signature,p.config_hash,p.ra_key_id,
                k.public_key_spki_der,p.key_fingerprint
                FROM ra.credential_policies p JOIN ra.ra_signing_keys k
                ON k.election_id=p.election_id AND k.ra_key_id=p.ra_key_id WHERE p.election_id=p_election;
            IF NOT FOUND THEN RAISE EXCEPTION 'Credential policy unavailable' USING ERRCODE='P4105'; END IF;
        END $f$
    """)
    op.execute("""
        CREATE FUNCTION ra_credential._request(p_digest text,p_election uuid,p_request uuid,p_hash bytea,p_config bytea,p_create boolean)
        RETURNS SETOF ra_credential.request_context
        LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,ra,pg_temp AS $f$
        DECLARE id uuid; eligible boolean; r ra.credential_reservations%ROWTYPE;
            b ra.blind_issuances%ROWTYPE; k ra.ra_signing_keys%ROWTYPE; p ra.credential_policies%ROWTYPE;
            has_reservation boolean; has_issuance boolean; decision timestamptz;
        BEGIN
            -- Shared lock order: voter -> session -> eligibility -> reservation
            -- -> completed issuance -> key -> immutable policy.
            id:=ra_credential._voter(p_digest);
            IF p_election IS NULL OR p_request IS NULL OR p_hash IS NULL OR octet_length(p_hash)<>32
               OR p_config IS NULL OR octet_length(p_config)<>32 THEN
                RAISE EXCEPTION 'Invalid credential arguments' USING ERRCODE='22023';
            END IF;
            SELECT e.is_eligible INTO eligible FROM ra.voter_eligibility e
                WHERE e.voter_id=id AND e.election_id=p_election FOR UPDATE;
            IF eligible IS DISTINCT FROM true THEN RAISE EXCEPTION 'Credential denied' USING ERRCODE='P4102'; END IF;
            SELECT * INTO r FROM ra.credential_reservations x WHERE x.voter_id=id AND x.election_id=p_election FOR UPDATE;
            has_reservation:=FOUND;
            SELECT * INTO b FROM ra.blind_issuances x WHERE x.voter_id=id AND x.election_id=p_election FOR UPDATE;
            has_issuance:=FOUND;
            IF has_issuance AND NOT has_reservation THEN
                -- Preserve legacy completions without assuming their recovery AAD/protocol.
                RAISE EXCEPTION 'Credential already issued' USING ERRCODE='P4103';
            END IF;
            IF NOT has_reservation AND NOT p_create THEN
                RAISE EXCEPTION 'Reservation required' USING ERRCODE='P4103';
            END IF;
            IF has_reservation AND (r.request_id<>p_request OR r.blinded_request_hash<>p_hash OR r.config_hash<>p_config) THEN
                RAISE EXCEPTION 'Different credential request' USING ERRCODE='P4103';
            END IF;
            SELECT * INTO k FROM ra.ra_signing_keys x WHERE x.election_id=p_election FOR SHARE;
            IF NOT FOUND THEN RAISE EXCEPTION 'Signing policy unavailable' USING ERRCODE='P4105'; END IF;
            SELECT * INTO p FROM ra.credential_policies x WHERE x.election_id=p_election FOR SHARE;
            IF NOT FOUND OR p.config_hash<>p_config OR p.ra_key_id<>k.ra_key_id
               OR p.key_fingerprint<>k.public_key_fingerprint
               OR k.signature_profile<>'RSABSSA-SHA384-PSS-Randomized' THEN
                RAISE EXCEPTION 'Signing policy mismatch' USING ERRCODE='P4105';
            END IF;
            decision:=pg_catalog.clock_timestamp();
            IF NOT has_reservation THEN
                IF NOT p.issuance_enabled OR k.key_state<>'ACTIVE' OR decision<p.opens_at OR decision>=p.closes_at THEN
                    RAISE EXCEPTION 'Credential denied' USING ERRCODE='P4102';
                END IF;
                INSERT INTO ra.credential_reservations(voter_id,election_id,request_id,blinded_request_hash,ra_key_id,config_hash,recovery_expires_at)
                    VALUES(id,p_election,p_request,p_hash,p.ra_key_id,p.config_hash,p.closes_at+INTERVAL '24 hours') RETURNING * INTO r;
            END IF;
            IF r.ra_key_id<>p.ra_key_id THEN RAISE EXCEPTION 'Signing policy mismatch' USING ERRCODE='P4105'; END IF;
            IF decision>=r.recovery_expires_at THEN RAISE EXCEPTION 'Recovery expired' USING ERRCODE='P4104'; END IF;
            IF has_issuance THEN
                IF b.request_id<>r.request_id OR b.blinded_request_hash<>r.blinded_request_hash OR b.ra_key_id<>r.ra_key_id THEN
                    RAISE EXCEPTION 'Inconsistent issuance' USING ERRCODE='P4105';
                END IF;
                IF b.recovery_state<>'RETAINED' THEN RAISE EXCEPTION 'Recovery expired' USING ERRCODE='P4104'; END IF;
            ELSIF NOT p.issuance_enabled OR k.key_state<>'ACTIVE' THEN
                RAISE EXCEPTION 'Credential denied' USING ERRCODE='P4102';
            END IF;
            RETURN QUERY SELECT r.reservation_id,r.voter_id,r.election_id,r.request_id,r.blinded_request_hash,
                r.ra_key_id,r.config_hash,r.reserved_at,r.recovery_expires_at,b.issuance_id,
                b.encrypted_blind_signature,b.storage_nonce,b.storage_key_id;
        END $f$
    """)
    for name, create in (("reserve_request", "true"), ("lock_request", "false")):
        op.execute(f"""
            CREATE FUNCTION ra_credential.{name}(p_digest text,p_election uuid,p_request uuid,p_hash bytea,p_config bytea)
            RETURNS SETOF ra_credential.request_context LANGUAGE sql VOLATILE SECURITY DEFINER
            SET search_path=pg_catalog,ra,pg_temp AS $f$
                SELECT * FROM ra_credential._request(p_digest,p_election,p_request,p_hash,p_config,{create});
            $f$
        """)
    op.execute("""
        CREATE FUNCTION ra_credential.complete_request(p_digest text,p_election uuid,p_request uuid,p_hash bytea,p_config bytea,
            p_cipher bytea,p_nonce bytea,p_storage_key text) RETURNS SETOF ra_credential.request_context
        LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,ra,pg_temp AS $f$
        DECLARE c ra_credential.request_context;
            -- Stable opaque audit principal assigned to the local Gate 2
            -- credential-issuance service (ra_issuance_login boundary).
            -- Audit metadata only: authorization still comes from the session
            -- and restricted EXECUTE grant, never this identifier or HTTP input.
            service_actor_id CONSTANT uuid := '00000000-0000-4000-8000-000000000002'::uuid;
        BEGIN
            SELECT * INTO c FROM ra_credential._request(p_digest,p_election,p_request,p_hash,p_config,false);
            IF c.issuance_id IS NULL THEN
                IF p_cipher IS NULL OR octet_length(p_cipher)<>400 OR p_nonce IS NULL OR octet_length(p_nonce)<>12
                   OR p_storage_key IS NULL OR p_storage_key !~ '^[a-z0-9][a-z0-9._-]{0,127}$' THEN
                    RAISE EXCEPTION 'Invalid recovery data' USING ERRCODE='22023';
                END IF;
                PERFORM ra.issue_blind_credential(c.voter_id,c.election_id,c.request_id,c.blinded_hash,c.key_id,
                    p_cipher,p_nonce,p_storage_key,c.recovery_expires_at,service_actor_id);
            END IF;
            RETURN QUERY SELECT * FROM ra_credential._request(p_digest,p_election,p_request,p_hash,p_config,false);
        END $f$
    """)
    op.execute("""
        COMMENT ON FUNCTION ra_credential.complete_request(text,uuid,uuid,bytea,bytea,bytea,bytea,text) IS
        'Local Gate 2 credential issuance service: SERVICE audit principal 00000000-0000-4000-8000-000000000002. '
        'Opaque service identity, not an authorization credential; fixed by this wrapper and not client-selectable.'
    """)
    op.execute("REVOKE ALL ON ALL FUNCTIONS IN SCHEMA ra_credential FROM PUBLIC,ra_auth_login,ra_issuance_login")
    op.execute("GRANT USAGE ON SCHEMA ra_credential TO ra_issuance_login")
    op.execute("GRANT USAGE ON TYPE ra_credential.request_context TO ra_issuance_login")
    for signature in (
        "policy_for_session(text,uuid)", "reserve_request(text,uuid,uuid,bytea,bytea)",
        "lock_request(text,uuid,uuid,bytea,bytea)", "complete_request(text,uuid,uuid,bytea,bytea,bytea,bytea,text)",
    ):
        op.execute(f"GRANT EXECUTE ON FUNCTION ra_credential.{signature} TO ra_issuance_login")
    op.execute("""
        DO $$
        BEGIN
            IF EXISTS (
                SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
                CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(p.proacl,pg_catalog.acldefault('f',p.proowner))) a
                WHERE n.nspname='ra_credential' AND a.grantee NOT IN
                    (p.proowner,(SELECT oid FROM pg_catalog.pg_roles WHERE rolname='ra_issuance_login'))
            ) OR EXISTS (
                SELECT 1 FROM pg_catalog.pg_type t JOIN pg_catalog.pg_namespace n ON n.oid=t.typnamespace
                CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(t.typacl,pg_catalog.acldefault('T',t.typowner))) a
                WHERE n.nspname='ra_credential' AND t.typname='request_context' AND a.grantee NOT IN
                    (t.typowner,(SELECT oid FROM pg_catalog.pg_roles WHERE rolname='ra_issuance_login'))
            ) OR EXISTS (
                SELECT 1 FROM pg_catalog.pg_namespace n
                CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(n.nspacl,pg_catalog.acldefault('n',n.nspowner))) a
                WHERE n.nspname='ra_credential' AND a.grantee NOT IN
                    (n.nspowner,(SELECT oid FROM pg_catalog.pg_roles WHERE rolname='ra_issuance_login'))
            ) OR EXISTS (
                SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
                CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(c.relacl,pg_catalog.acldefault('r',c.relowner))) a
                WHERE n.nspname='ra' AND c.relname IN ('credential_policies','credential_reservations') AND a.grantee<>c.relowner
            ) THEN RAISE EXCEPTION 'Unexpected default RA issuance privileges'; END IF;
        END $$;
    """)


def downgrade():
    raise RuntimeError("Forward-only RA credential reservation migration; tombstones must not be removed")
