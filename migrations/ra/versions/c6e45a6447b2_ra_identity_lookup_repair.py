"""ra identity lookup repair

Revision ID: c6e45a6447b2
Revises: 74f0541eff26
Create Date: 2026-11-14 17:34:10.773720

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c6e45a6447b2'
down_revision: Union[str, Sequence[str], None] = '74f0541eff26'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(r"""
        CREATE FUNCTION ra.find_active_voter_id(
            p_auth_provider text,
            p_auth_subject text
        )
        RETURNS uuid
        LANGUAGE plpgsql
        STABLE
        SECURITY DEFINER
        SET search_path = pg_catalog, ra, pg_temp
        AS $func$
        DECLARE
            v_voter_id uuid;
        BEGIN
            IF p_auth_provider IS NULL
               OR p_auth_subject IS NULL
               OR pg_catalog.btrim(p_auth_provider) = ''
               OR pg_catalog.btrim(p_auth_subject) = ''
               OR pg_catalog.length(p_auth_provider) > 128
               OR pg_catalog.length(p_auth_subject) > 255
            THEN
                RETURN NULL;
            END IF;

            SELECT v.voter_id
            INTO v_voter_id
            FROM ra.voters v
            WHERE v.auth_provider = p_auth_provider
              AND v.auth_subject = p_auth_subject
              AND v.is_active = true;

            RETURN v_voter_id;
        END;
        $func$;
    """)

    op.execute("""
        REVOKE ALL ON FUNCTION
            ra.find_active_voter_id(text, text)
        FROM PUBLIC, ra_service, ra_service_login,
             ra_recovery_worker, ra_audit_reader
    """)


def downgrade() -> None:
    raise RuntimeError(
        "Automatic rollback of RA identity lookup "
        "security migration is disabled"
    )