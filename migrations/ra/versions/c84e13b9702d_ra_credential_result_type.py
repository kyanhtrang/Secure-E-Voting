"""Match legacy varchar recovery key IDs to the text request-context result.

Revision ID: c84e13b9702d
Revises: 7b2d91a6c840
"""
from alembic import op

revision="c84e13b9702d"
down_revision="7b2d91a6c840"
branch_labels=None
depends_on=None


def upgrade():
    op.execute("SET LOCAL ROLE ra_owner")
    op.execute("""
        DO $$
        DECLARE target oid := pg_catalog.to_regprocedure('ra_credential._request(text,uuid,uuid,bytea,bytea,boolean)');
        BEGIN
            IF target IS NULL OR NOT EXISTS (
                SELECT 1 FROM pg_catalog.pg_proc p WHERE p.oid=target
                AND p.proowner='ra_owner'::pg_catalog.regrole AND p.prosecdef AND p.provolatile='v'
                AND p.prorettype='ra_credential.request_context'::pg_catalog.regtype
            ) OR EXISTS (
                SELECT 1 FROM pg_catalog.pg_proc p
                CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(p.proacl,pg_catalog.acldefault('f',p.proowner))) a
                WHERE p.oid=target AND a.grantee<>p.proowner
            ) THEN RAISE EXCEPTION 'Unexpected credential helper ownership or privileges'; END IF;
        END $$;
    """)
    # Same authorization/locking body as the previous revision. The only
    # expression change is the final varchar -> text result-column cast.
    # CREATE OR REPLACE preserves the existing owner and private EXECUTE ACL.
    op.execute("""
        CREATE OR REPLACE FUNCTION ra_credential._request(p_digest text,p_election uuid,p_request uuid,p_hash bytea,p_config bytea,p_create boolean)
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
                b.encrypted_blind_signature,b.storage_nonce,b.storage_key_id::text;
        END $f$
    """)


def downgrade():
    raise RuntimeError("Forward-only credential result-type correction")
