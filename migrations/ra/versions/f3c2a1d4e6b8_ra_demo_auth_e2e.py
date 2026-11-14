"""Narrow local-demo identity, session verification, and atomic revocation.

Revision ID: f3c2a1d4e6b8
Revises: a9c31d5e8b72
"""

from alembic import op

revision = "f3c2a1d4e6b8"
down_revision = "a9c31d5e8b72"
branch_labels = None
depends_on = None


def upgrade():
    # These roles are dependencies of the earlier RA ACL/session migrations.
    # This revision never provisions roles or repairs broad existing grants.
    op.execute("""
        DO $$
        DECLARE v_missing text;
        BEGIN
            SELECT pg_catalog.string_agg(required.name, ', ' ORDER BY required.name)
            INTO v_missing
            FROM (VALUES ('ra_owner'), ('ra_auth_login'), ('ra_service'),
                         ('ra_service_login'), ('ra_recovery_worker'),
                         ('ra_audit_reader')) AS required(name)
            WHERE NOT EXISTS (
                SELECT 1 FROM pg_catalog.pg_roles AS r WHERE r.rolname = required.name
            );
            IF v_missing IS NOT NULL THEN
                RAISE EXCEPTION 'Required RA roles missing: %', v_missing;
            END IF;
            IF EXISTS (
                SELECT 1 FROM pg_catalog.pg_roles
                WHERE rolname = 'ra_auth_login'
                  AND (NOT rolcanlogin OR rolinherit OR rolsuper OR rolcreatedb
                       OR rolcreaterole OR rolreplication OR rolbypassrls)
            ) OR EXISTS (
                SELECT 1 FROM pg_catalog.pg_auth_members AS m
                JOIN pg_catalog.pg_roles AS r ON r.oid IN (m.member, m.roleid)
                WHERE r.rolname = 'ra_auth_login'
            ) THEN
                RAISE EXCEPTION 'Unsafe ra_auth_login role attributes or memberships';
            END IF;
        END
        $$;
    """)
    op.execute("SET LOCAL ROLE ra_owner")
    op.execute("""
        DO $$
        BEGIN
            IF (SELECT pg_catalog.pg_get_userbyid(nspowner)
                FROM pg_catalog.pg_namespace WHERE nspname = 'ra_demo')
                IS DISTINCT FROM 'ra_owner' THEN
                RAISE EXCEPTION 'Unexpected demo schema ownership';
            END IF;
            IF pg_catalog.has_schema_privilege('ra_auth_login', 'ra', 'USAGE')
               OR pg_catalog.has_schema_privilege('ra_auth_login', 'ra', 'CREATE')
               OR pg_catalog.has_schema_privilege('ra_auth_login', 'ra_demo', 'CREATE')
               OR NOT pg_catalog.has_schema_privilege('ra_auth_login', 'ra_demo', 'USAGE')
               OR EXISTS (
                   SELECT 1 FROM pg_catalog.pg_proc AS p
                   JOIN pg_catalog.pg_namespace AS n ON n.oid = p.pronamespace
                   WHERE n.nspname = 'ra'
                     AND pg_catalog.has_function_privilege('ra_auth_login', p.oid, 'EXECUTE')
               ) OR EXISTS (
                   SELECT 1 FROM pg_catalog.pg_class AS c
                   JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
                   CROSS JOIN (VALUES ('SELECT'), ('INSERT'), ('UPDATE'), ('DELETE'),
                                      ('TRUNCATE'), ('REFERENCES'), ('TRIGGER')) AS a(privilege)
                   WHERE n.nspname = 'ra' AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
                     AND pg_catalog.has_table_privilege('ra_auth_login', c.oid, a.privilege)
               ) OR EXISTS (
                   SELECT 1 FROM pg_catalog.pg_class AS c
                   JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
                   CROSS JOIN (VALUES ('SELECT'), ('UPDATE'), ('USAGE')) AS a(privilege)
                   WHERE n.nspname = 'ra' AND c.relkind = 'S'
                     AND pg_catalog.has_sequence_privilege('ra_auth_login', c.oid, a.privilege)
               ) THEN
                RAISE EXCEPTION 'Existing RA authorization boundary is unsafe';
            END IF;
        END
        $$;
    """)
    op.execute(r"""
        CREATE FUNCTION ra_demo.find_active_demo_voter_id(
            p_auth_provider text, p_auth_subject text
        ) RETURNS uuid
        LANGUAGE plpgsql STABLE SECURITY DEFINER
        SET search_path = pg_catalog, ra, pg_temp
        AS $func$
        BEGIN
            IF p_auth_provider IS DISTINCT FROM 'demo-local'
               OR p_auth_subject IS DISTINCT FROM 'demo-voter-001' THEN
                RETURN NULL;
            END IF;
            RETURN ra.find_active_voter_id('demo-local', 'demo-voter-001');
        END;
        $func$;
    """)
    op.execute(r"""
        CREATE FUNCTION ra_demo.find_active_demo_session(p_token_digest text)
        RETURNS TABLE (
            voter_id uuid, created_at timestamptz,
            expires_at timestamptz, revoked_at timestamptz
        )
        LANGUAGE plpgsql VOLATILE SECURITY DEFINER
        SET search_path = pg_catalog, ra, pg_temp
        AS $func$
        BEGIN
            IF p_token_digest IS NULL
               OR p_token_digest !~ '^[0-9a-f]{64}$' THEN
                RETURN;
            END IF;
            RETURN QUERY
            SELECT s.voter_id, s.created_at, s.expires_at, s.revoked_at
            FROM ra.find_active_session(p_token_digest) AS s
            WHERE s.voter_id = ra.find_active_voter_id(
                'demo-local', 'demo-voter-001'
            );
        END;
        $func$;
    """)
    op.execute(r"""
        CREATE FUNCTION ra_demo.revoke_demo_session(p_token_digest text)
        RETURNS boolean
        LANGUAGE plpgsql VOLATILE SECURITY DEFINER
        SET search_path = pg_catalog, ra, pg_temp
        AS $func$
        BEGIN
            IF p_token_digest IS NULL
               OR p_token_digest !~ '^[0-9a-f]{64}$' THEN
                RETURN false;
            END IF;
            -- Ownership and revocation are one statement, including under
            -- concurrent logout. Inactive/expired demo sessions may be revoked.
            UPDATE ra.ra_sessions AS s
            SET revoked_at = GREATEST(pg_catalog.clock_timestamp(), s.created_at)
            FROM ra.voters AS v
            WHERE s.token_digest = p_token_digest
              AND s.revoked_at IS NULL
              AND s.voter_id = v.voter_id
              AND v.auth_provider = 'demo-local'
              AND v.auth_subject = 'demo-voter-001';
            RETURN FOUND;
        END;
        $func$;
    """)
    # The creating role is the owner; never grant access to the general ra API.
    for signature in (
        "ra_demo.find_active_demo_voter_id(text,text)",
        "ra_demo.find_active_demo_session(text)",
        "ra_demo.revoke_demo_session(text)",
    ):
        op.execute(f"""
            REVOKE ALL ON FUNCTION {signature}
            FROM PUBLIC, ra_auth_login, ra_service, ra_service_login,
                 ra_recovery_worker, ra_audit_reader
        """)
        op.execute(f"GRANT EXECUTE ON FUNCTION {signature} TO ra_auth_login")
    # Detect unexpected owner default grants rather than silently preserving
    # or widening them. A failure rolls the whole transactional migration back.
    op.execute("""
        DO $$
        BEGIN
            IF EXISTS (
                SELECT 1 FROM pg_catalog.pg_proc AS p
                CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(
                    p.proacl, pg_catalog.acldefault('f', p.proowner)
                )) AS a
                WHERE p.oid IN (
                    'ra_demo.find_active_demo_voter_id(text,text)'::pg_catalog.regprocedure,
                    'ra_demo.find_active_demo_session(text)'::pg_catalog.regprocedure,
                    'ra_demo.revoke_demo_session(text)'::pg_catalog.regprocedure
                ) AND a.grantee NOT IN (
                    p.proowner, (SELECT oid FROM pg_catalog.pg_roles WHERE rolname='ra_auth_login')
                )
            ) THEN
                RAISE EXCEPTION 'Unexpected default grants on demo functions';
            END IF;
        END
        $$;
    """)


def downgrade():
    raise RuntimeError("Automatic rollback of demo authentication is disabled")
