"""ra issue blind credential protected

Revision ID: 1dcfbb1dd9a4
Revises: 615b4733bd61
Create Date: 2026-11-13 01:10:44.477358

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '1dcfbb1dd9a4'
down_revision: Union[str, Sequence[str], None] = '615b4733bd61'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(r"""
        CREATE FUNCTION ra.issue_blind_credential(
            p_voter_id uuid,
            p_election_id uuid,
            p_request_id uuid,
            p_blinded_request_hash bytea,
            p_ra_key_id text,
            p_encrypted_blind_signature bytea,
            p_storage_nonce bytea,
            p_storage_key_id text,
            p_recovery_expires_at timestamptz,
            p_actor_principal_id uuid
        )
        RETURNS uuid
        LANGUAGE plpgsql
        VOLATILE
        SECURITY DEFINER
        SET search_path = pg_catalog, ra, pg_temp
        AS $func$
        DECLARE
            v_active boolean;
            v_eligible boolean;
            v_key_state text;
            v_existing_id uuid;
            v_existing_request uuid;
            v_existing_hash bytea;
            v_existing_key text;
            v_new_id uuid;
            v_issued_at timestamptz;
        BEGIN
            IF p_voter_id IS NULL
               OR p_election_id IS NULL
               OR p_request_id IS NULL
               OR p_blinded_request_hash IS NULL
               OR p_ra_key_id IS NULL
               OR p_actor_principal_id IS NULL THEN
                RAISE EXCEPTION 'Required argument is null'
                    USING ERRCODE = '22004';
            END IF;

            IF pg_catalog.octet_length(
                   p_blinded_request_hash
               ) <> 32
               OR pg_catalog.btrim(p_ra_key_id) = '' THEN
                RAISE EXCEPTION 'Invalid request data'
                    USING ERRCODE = '22023';
            END IF;

            -- Lock order: voter -> eligibility -> issuance -> key.
            SELECT v.is_active
            INTO v_active
            FROM ra.voters v
            WHERE v.voter_id = p_voter_id
            FOR UPDATE;

            IF NOT FOUND OR v_active IS DISTINCT FROM true THEN
                RAISE EXCEPTION 'Voter inactive or not found'
                    USING ERRCODE = '23514';
            END IF;

            SELECT e.is_eligible
            INTO v_eligible
            FROM ra.voter_eligibility e
            WHERE e.voter_id = p_voter_id
              AND e.election_id = p_election_id
            FOR UPDATE;

            IF NOT FOUND OR v_eligible IS DISTINCT FROM true THEN
                RAISE EXCEPTION 'Voter is not eligible'
                    USING ERRCODE = '23514';
            END IF;

            -- Existing issuance must never be overwritten.
            SELECT
                b.issuance_id,
                b.request_id,
                b.blinded_request_hash,
                b.ra_key_id
            INTO
                v_existing_id,
                v_existing_request,
                v_existing_hash,
                v_existing_key
            FROM ra.blind_issuances b
            WHERE b.voter_id = p_voter_id
              AND b.election_id = p_election_id
            FOR UPDATE;

            IF FOUND THEN
                IF v_existing_request = p_request_id
                   AND v_existing_hash = p_blinded_request_hash
                   AND v_existing_key = p_ra_key_id THEN

                    INSERT INTO ra.ra_audit_events (
                        audit_event_id,
                        election_id,
                        voter_id,
                        issuance_id,
                        actor_type,
                        actor_principal_id,
                        event_type,
                        outcome
                    )
                    VALUES (
                        pg_catalog.gen_random_uuid(),
                        p_election_id,
                        p_voter_id,
                        v_existing_id,
                        'SERVICE',
                        p_actor_principal_id,
                        'BLIND_ISSUANCE_REPLAYED',
                        'SUCCESS'
                    );

                    RETURN v_existing_id;
                END IF;

                RAISE EXCEPTION
                    'Credential already issued for voter/election'
                    USING ERRCODE = '23505';
            END IF;

            -- Lock active signing key against concurrent changes.
            SELECT k.key_state
            INTO v_key_state
            FROM ra.ra_signing_keys k
            WHERE k.election_id = p_election_id
              AND k.ra_key_id = p_ra_key_id
            FOR SHARE;

            IF NOT FOUND OR v_key_state IS DISTINCT FROM 'ACTIVE' THEN
                RAISE EXCEPTION 'Active signing key not found'
                    USING ERRCODE = '23514';
            END IF;

            v_issued_at := pg_catalog.clock_timestamp();

            IF p_encrypted_blind_signature IS NULL
               OR pg_catalog.octet_length(
                   p_encrypted_blind_signature
               ) <= 16
               OR p_storage_nonce IS NULL
               OR pg_catalog.octet_length(p_storage_nonce) <> 12
               OR p_storage_key_id IS NULL
               OR pg_catalog.btrim(p_storage_key_id) = ''
               OR p_recovery_expires_at IS NULL
               OR p_recovery_expires_at <= v_issued_at THEN
                RAISE EXCEPTION
                    'Invalid encrypted recovery data or expiry'
                    USING ERRCODE = '22023';
            END IF;

            v_new_id := pg_catalog.gen_random_uuid();

            INSERT INTO ra.blind_issuances (
                issuance_id,
                voter_id,
                election_id,
                request_id,
                blinded_request_hash,
                ra_key_id,
                encrypted_blind_signature,
                storage_nonce,
                storage_key_id,
                issuance_status,
                recovery_state,
                issued_at,
                recovery_expires_at
            )
            VALUES (
                v_new_id,
                p_voter_id,
                p_election_id,
                p_request_id,
                p_blinded_request_hash,
                p_ra_key_id,
                p_encrypted_blind_signature,
                p_storage_nonce,
                p_storage_key_id,
                'ISSUED',
                'RETAINED',
                v_issued_at,
                p_recovery_expires_at
            );

            INSERT INTO ra.ra_audit_events (
                audit_event_id,
                election_id,
                voter_id,
                issuance_id,
                actor_type,
                actor_principal_id,
                event_type,
                outcome
            )
            VALUES (
                pg_catalog.gen_random_uuid(),
                p_election_id,
                p_voter_id,
                v_new_id,
                'SERVICE',
                p_actor_principal_id,
                'BLIND_ISSUANCE_ISSUED',
                'SUCCESS'
            );

            RETURN v_new_id;
        END;
        $func$;
    """)

    # No runtime EXECUTE until authorization is implemented.
    op.execute("""
        REVOKE ALL ON FUNCTION ra.issue_blind_credential(
            uuid, uuid, uuid, bytea, text, bytea,
            bytea, text, timestamptz, uuid
        )
        FROM PUBLIC, ra_service, ra_recovery_worker,
             ra_audit_reader
    """)


def downgrade() -> None:
    op.execute("""
        DROP FUNCTION ra.issue_blind_credential(
            uuid, uuid, uuid, bytea, text, bytea,
            bytea, text, timestamptz, uuid
        )
    """)