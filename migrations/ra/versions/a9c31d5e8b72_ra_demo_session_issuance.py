"""RA demo session issuance with restricted database privileges.

Revision ID: a9c31d5e8b72
Revises: c6e45a6447b2
"""

from alembic import op

revision = "a9c31d5e8b72"
down_revision = "c6e45a6447b2"
branch_labels = None
depends_on = None


def upgrade():
    # Transaction-scoped role switch; never use postgres
    # or the migrator's broad permissions as function owner.
    op.execute("SET LOCAL ROLE ra_owner")

    op.execute("""
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM pg_roles
                WHERE rolname = 'ra_auth_login'
            ) THEN
                RAISE EXCEPTION
                    'Provision ra_auth_login before migration';
            END IF;
        END
        $$;
    """)

    op.execute("""
        CREATE SCHEMA IF NOT EXISTS ra_demo
        AUTHORIZATION ra_owner
    """)

    op.execute("""
        DO $$
        DECLARE
            v_owner text;
        BEGIN
            SELECT pg_get_userbyid(nspowner)
            INTO v_owner
            FROM pg_namespace
            WHERE nspname = 'ra_demo';

            IF v_owner IS DISTINCT FROM 'ra_owner' THEN
                RAISE EXCEPTION
                    'Unexpected ra_demo schema owner: %', v_owner;
            END IF;
        END
        $$;
    """)

    op.execute("""
        REVOKE ALL ON SCHEMA ra_demo FROM PUBLIC
    """)

    op.execute("""
        REVOKE ALL ON SCHEMA ra_demo
        FROM ra_service_login
    """)

    op.execute("""
        CREATE OR REPLACE FUNCTION ra_demo.issue_demo_session(
            p_token_digest text,
            p_voter_id uuid
        )
        RETURNS void
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, ra, pg_temp
        AS $function$
        DECLARE
            v_allowed_voter uuid;
            v_created_at timestamptz;
        BEGIN
            v_allowed_voter := ra.find_active_voter_id(
                'demo-local',
                'demo-voter-001'
            );

            IF v_allowed_voter IS NULL
               OR p_voter_id IS DISTINCT FROM v_allowed_voter
            THEN
                RAISE EXCEPTION 'Demo voter not authorized'
                    USING ERRCODE = '42501';
            END IF;

            v_created_at := clock_timestamp();

            PERFORM ra.create_session(
                p_token_digest,
                v_allowed_voter,
                v_created_at,
                v_created_at + INTERVAL '15 minutes'
            );
        END;
        $function$;
    """)

    op.execute("""
        REVOKE ALL
        ON FUNCTION ra_demo.issue_demo_session(text,uuid)
        FROM PUBLIC
    """)

    op.execute("""
        REVOKE ALL
        ON FUNCTION ra_demo.issue_demo_session(text,uuid)
        FROM ra_service_login
    """)

    op.execute("""
        GRANT USAGE ON SCHEMA ra_demo
        TO ra_auth_login
    """)

    op.execute("""
        GRANT EXECUTE
        ON FUNCTION ra_demo.issue_demo_session(text,uuid)
        TO ra_auth_login
    """)


def downgrade():
    # This installation had ra_demo created manually before
    # it was captured in Alembic. Do not silently remove it
    # or destroy existing demo sessions.
    raise RuntimeError(
        "Destructive downgrade is intentionally disabled; "
        "review ra_demo objects and session data manually."
    )
