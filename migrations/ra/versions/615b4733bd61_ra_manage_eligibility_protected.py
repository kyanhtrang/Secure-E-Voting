"""ra manage eligibility protected

Revision ID: 615b4733bd61
Revises: c07d6c70dc16
Create Date: 2026-11-13 00:51:04.632998

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '615b4733bd61'
down_revision: Union[str, Sequence[str], None] = 'c07d6c70dc16'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(r"""
        CREATE FUNCTION ra.set_voter_eligibility(
            p_voter_id uuid,
            p_election_id uuid,
            p_is_eligible boolean,
            p_actor_principal_id uuid
        )
        RETURNS boolean
        LANGUAGE plpgsql
        VOLATILE
        SECURITY DEFINER
        SET search_path = pg_catalog, ra, pg_temp
        AS $func$
        DECLARE
            v_active boolean;
            v_old_eligible boolean;
            v_has_eligibility boolean;
        BEGIN
            IF p_voter_id IS NULL
               OR p_election_id IS NULL
               OR p_is_eligible IS NULL
               OR p_actor_principal_id IS NULL THEN
                RAISE EXCEPTION 'Required argument is null'
                    USING ERRCODE = '22004';
            END IF;

            -- Lock voter first to serialize eligibility changes.
            SELECT is_active
            INTO v_active
            FROM ra.voters
            WHERE voter_id = p_voter_id
            FOR UPDATE;

            IF NOT FOUND THEN
                RAISE EXCEPTION 'Voter not found'
                    USING ERRCODE = 'P0002';
            END IF;

            IF p_is_eligible AND NOT v_active THEN
                RAISE EXCEPTION
                    'Cannot grant eligibility to inactive voter'
                    USING ERRCODE = '23514';
            END IF;

            SELECT is_eligible
            INTO v_old_eligible
            FROM ra.voter_eligibility
            WHERE voter_id = p_voter_id
              AND election_id = p_election_id
            FOR UPDATE;

            v_has_eligibility := FOUND;

            -- No change required.
            IF v_has_eligibility
               AND v_old_eligible = p_is_eligible THEN
                RETURN false;
            END IF;

            -- Revoking a nonexistent eligibility is a no-op.
            IF NOT v_has_eligibility
               AND NOT p_is_eligible THEN
                RETURN false;
            END IF;

            -- Never change eligibility after credential issuance.
            IF EXISTS (
                SELECT 1
                FROM ra.blind_issuances
                WHERE voter_id = p_voter_id
                  AND election_id = p_election_id
            ) THEN
                RAISE EXCEPTION
                    'Eligibility change blocked after issuance'
                    USING ERRCODE = '23514';
            END IF;

            IF v_has_eligibility THEN
                UPDATE ra.voter_eligibility
                SET is_eligible = p_is_eligible,
                    updated_at = pg_catalog.clock_timestamp()
                WHERE voter_id = p_voter_id
                  AND election_id = p_election_id;
            ELSE
                INSERT INTO ra.voter_eligibility (
                    eligibility_id,
                    voter_id,
                    election_id,
                    is_eligible
                )
                VALUES (
                    pg_catalog.gen_random_uuid(),
                    p_voter_id,
                    p_election_id,
                    true
                );
            END IF;

            -- This audit record shares the mutation transaction.
            INSERT INTO ra.ra_audit_events (
                audit_event_id,
                election_id,
                voter_id,
                actor_type,
                actor_principal_id,
                event_type,
                outcome
            )
            VALUES (
                pg_catalog.gen_random_uuid(),
                p_election_id,
                p_voter_id,
                'SERVICE',
                p_actor_principal_id,
                CASE
                    WHEN p_is_eligible
                    THEN 'ELIGIBILITY_GRANTED'
                    ELSE 'ELIGIBILITY_REVOKED'
                END,
                'SUCCESS'
            );

            RETURN true;
        END;
        $func$;
    """)

    # Function is intentionally unavailable to runtime roles.
    op.execute("""
        REVOKE ALL ON FUNCTION
        ra.set_voter_eligibility(uuid, uuid, boolean, uuid)
        FROM PUBLIC
    """)

    op.execute("""
        REVOKE ALL ON FUNCTION
        ra.set_voter_eligibility(uuid, uuid, boolean, uuid)
        FROM ra_service
    """)


def downgrade() -> None:
    op.execute("""
        DROP FUNCTION
        ra.set_voter_eligibility(uuid, uuid, boolean, uuid)
    """)