"""ra disable voter protected

Revision ID: c07d6c70dc16
Revises: 00e554fb031a
Create Date: 2026-11-13 00:39:39.504496

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c07d6c70dc16'
down_revision: Union[str, Sequence[str], None] = '00e554fb031a'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(r"""
        CREATE FUNCTION ra.disable_voter(
            p_voter_id uuid,
            p_actor_principal_id uuid
        )
        RETURNS boolean
        LANGUAGE plpgsql
        VOLATILE
        SECURITY DEFINER
        SET search_path = pg_catalog, ra, pg_temp
        AS $func$
        BEGIN
            IF p_voter_id IS NULL
               OR p_actor_principal_id IS NULL THEN
                RAISE EXCEPTION 'Required identifier is null'
                    USING ERRCODE = '22004';
            END IF;

            UPDATE ra.voters
            SET is_active = false,
                updated_at = pg_catalog.clock_timestamp()
            WHERE voter_id = p_voter_id
              AND is_active = true;

            IF NOT FOUND THEN
                RETURN false;
            END IF;

            INSERT INTO ra.ra_audit_events (
                audit_event_id,
                voter_id,
                actor_type,
                actor_principal_id,
                event_type,
                outcome
            )
            VALUES (
                pg_catalog.gen_random_uuid(),
                p_voter_id,
                'SERVICE',
                p_actor_principal_id,
                'VOTER_DISABLED',
                'SUCCESS'
            );

            RETURN true;
        END;
        $func$;
    """)

    op.execute("""
        REVOKE ALL ON FUNCTION ra.disable_voter(uuid, uuid)
        FROM PUBLIC
    """)

    # Runtime EXECUTE remains disabled until authorization is implemented.


def downgrade() -> None:
    op.execute("""
        REVOKE ALL ON FUNCTION ra.disable_voter(uuid, uuid)
        FROM ra_service
    """)

    op.execute("""
        DROP FUNCTION ra.disable_voter(uuid, uuid)
    """)