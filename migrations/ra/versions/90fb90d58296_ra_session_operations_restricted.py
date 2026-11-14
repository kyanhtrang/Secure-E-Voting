"""ra session operations restricted

Revision ID: 90fb90d58296
Revises: 3a2b3cec335f
Create Date: 2026-11-13 02:01:31.677072

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '90fb90d58296'
down_revision: Union[str, Sequence[str], None] = '3a2b3cec335f'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Create a session after trusted authentication.
    op.execute(r"""
        CREATE FUNCTION ra.create_session(
            p_token_digest text,
            p_voter_id uuid,
            p_created_at timestamptz,
            p_expires_at timestamptz
        )
        RETURNS void
        LANGUAGE plpgsql
        VOLATILE
        SECURITY DEFINER
        SET search_path = pg_catalog, ra, pg_temp
        AS $func$
        DECLARE
            v_active boolean;
            v_now timestamptz := pg_catalog.clock_timestamp();
        BEGIN
            IF p_token_digest IS NULL
               OR p_token_digest !~ '^[0-9a-f]{64}$'
               OR p_voter_id IS NULL
               OR p_created_at IS NULL
               OR p_expires_at IS NULL THEN
                RAISE EXCEPTION 'Invalid session arguments'
                    USING ERRCODE = '22023';
            END IF;

            -- Temporary development policy: maximum 15 minutes.
            -- Reject stale/future timestamps and expired tokens.
            IF p_created_at < v_now - INTERVAL '5 minutes'
               OR p_created_at > v_now + INTERVAL '1 minute'
               OR p_expires_at <= v_now
               OR p_expires_at <= p_created_at
               OR p_expires_at > p_created_at + INTERVAL '15 minutes'
               OR p_expires_at > v_now + INTERVAL '15 minutes'
            THEN
                RAISE EXCEPTION 'Invalid session lifetime'
                    USING ERRCODE = '22023';
            END IF;

            -- Serialize session creation against voter disabling.
            SELECT v.is_active
            INTO v_active
            FROM ra.voters v
            WHERE v.voter_id = p_voter_id
            FOR SHARE;

            IF NOT FOUND OR v_active IS DISTINCT FROM true THEN
                RAISE EXCEPTION 'Voter inactive or not found'
                    USING ERRCODE = '23514';
            END IF;

            INSERT INTO ra.ra_sessions (
                token_digest,
                voter_id,
                created_at,
                expires_at
            )
            VALUES (
                p_token_digest,
                p_voter_id,
                p_created_at,
                p_expires_at
            );
        END;
        $func$;
    """)

    # 2. Resolve only active, nonexpired, nonrevoked sessions.
    op.execute(r"""
        CREATE FUNCTION ra.find_active_session(
            p_token_digest text
        )
        RETURNS TABLE (
            voter_id uuid,
            created_at timestamptz,
            expires_at timestamptz,
            revoked_at timestamptz
        )
        LANGUAGE plpgsql
        STABLE
        SECURITY DEFINER
        SET search_path = pg_catalog, ra, pg_temp
        AS $func$
        BEGIN
            IF p_token_digest IS NULL
               OR p_token_digest !~ '^[0-9a-f]{64}$' THEN
                RETURN;
            END IF;

            RETURN QUERY
            SELECT
                s.voter_id,
                s.created_at,
                s.expires_at,
                s.revoked_at
            FROM ra.ra_sessions s
            JOIN ra.voters v
                ON v.voter_id = s.voter_id
            WHERE s.token_digest = p_token_digest
              AND s.revoked_at IS NULL
              AND s.expires_at > pg_catalog.clock_timestamp()
              AND v.is_active = true;
        END;
        $func$;
    """)

    # 3. Revoke using database server time.
    op.execute(r"""
        CREATE FUNCTION ra.revoke_session(
            p_token_digest text
        )
        RETURNS boolean
        LANGUAGE plpgsql
        VOLATILE
        SECURITY DEFINER
        SET search_path = pg_catalog, ra, pg_temp
        AS $func$
        BEGIN
            IF p_token_digest IS NULL
               OR p_token_digest !~ '^[0-9a-f]{64}$' THEN
                RETURN false;
            END IF;

            UPDATE ra.ra_sessions s
            SET revoked_at = GREATEST(
                pg_catalog.clock_timestamp(),
                s.created_at
            )
            WHERE s.token_digest = p_token_digest
              AND s.revoked_at IS NULL;

            RETURN FOUND;
        END;
        $func$;
    """)

    # All functions remain inaccessible to runtime roles.
    op.execute("""
        REVOKE ALL ON FUNCTION
            ra.create_session(text, uuid, timestamptz, timestamptz)
        FROM PUBLIC, ra_service, ra_service_login,
             ra_recovery_worker, ra_audit_reader
    """)

    op.execute("""
        REVOKE ALL ON FUNCTION
            ra.find_active_session(text)
        FROM PUBLIC, ra_service, ra_service_login,
             ra_recovery_worker, ra_audit_reader
    """)

    op.execute("""
        REVOKE ALL ON FUNCTION
            ra.revoke_session(text)
        FROM PUBLIC, ra_service, ra_service_login,
             ra_recovery_worker, ra_audit_reader
    """)


def downgrade() -> None:
    raise RuntimeError(
        "Automatic rollback of RA session security operations "
        "is disabled"
    )