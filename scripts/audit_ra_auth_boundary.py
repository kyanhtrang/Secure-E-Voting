import getpass

import psycopg


DB_ROLE = "ra_service_login"

PROTECTED_FUNCTIONS = (
    "ra.find_active_voter_id(text,text)",
    "ra.create_session(text,uuid,timestamptz,timestamptz)",
    "ra.find_active_session(text)",
    "ra.revoke_session(text)",
)

PROTECTED_TABLES = (
    "ra.voters",
    "ra.ra_sessions",
)


def main():
    password = getpass.getpass(
        "PostgreSQL password for ra_migrator_login: "
    )

    with psycopg.connect(
        host="127.0.0.1",
        port=5432,
        dbname="ra_db",
        user="ra_migrator_login",
        password=password,
        connect_timeout=5,
    ) as conn:

        db, login = conn.execute(
            "SELECT current_database(), session_user"
        ).fetchone()

        if (db, login) != (
            "ra_db",
            "ra_migrator_login",
        ):
            raise RuntimeError("Unexpected database identity")

        print("PASS: Database identity verified")

        role_exists = conn.execute(
            """
            SELECT EXISTS (
                SELECT 1 FROM pg_roles
                WHERE rolname = %s
            )
            """,
            (DB_ROLE,),
        ).fetchone()[0]

        if not role_exists:
            raise RuntimeError("Runtime role missing")

        print("PASS: Existing runtime role found")

        # Use the owner role only to inspect metadata.
        # All privilege checks still target ra_service_login.
        conn.execute("SET ROLE ra_owner")

        current_role = conn.execute(
            "SELECT current_user"
        ).fetchone()[0]

        if current_role != "ra_owner":
            raise RuntimeError("Audit role switch failed")

        print("PASS: Audit metadata role verified")

        for signature in PROTECTED_FUNCTIONS:
            row = conn.execute(
                """
                SELECT
                    p.prosecdef,
                    owner.rolname,
                    p.proconfig,
                    has_function_privilege(
                        %s::text, p.oid, 'EXECUTE'
                    ),
                    EXISTS (
                        SELECT 1
                        FROM aclexplode(
                            COALESCE(
                                p.proacl,
                                acldefault('f', p.proowner)
                            )
                        ) AS acl
                        WHERE acl.grantee = 0
                          AND acl.privilege_type = 'EXECUTE'
                    )
                FROM pg_proc AS p
                JOIN pg_roles AS owner
                  ON owner.oid = p.proowner
                WHERE p.oid = to_regprocedure(%s)
                """,
                (DB_ROLE, signature),
            ).fetchone()

            if row is None:
                raise RuntimeError(
                    f"Protected function missing: {signature}"
                )

            security_definer, owner, config, runtime_exec, public_exec = row

            normalized_config = "".join(
                " ".join(config or []).split()
            )

            fixed_path = (
                "search_path=pg_catalog,ra,pg_temp"
                in normalized_config
            )

            if not (
                security_definer
                and owner == "ra_owner"
                and fixed_path
                and not runtime_exec
                and not public_exec
            ):
                raise RuntimeError(
                    f"Function boundary FAILED: {signature}; "
                    f"owner={owner}, "
                    f"security_definer={security_definer}, "
                    f"fixed_path={fixed_path}, "
                    f"runtime_exec={runtime_exec}, "
                    f"public_exec={public_exec}"
                )

            print(f"PASS: Protected function {signature}")

        for table in PROTECTED_TABLES:
            for privilege in ("INSERT", "UPDATE", "DELETE"):
                granted = conn.execute(
                    """
                    SELECT has_table_privilege(
                        %s::text, %s::text, %s::text
                    )
                    """,
                    (DB_ROLE, table, privilege),
                ).fetchone()[0]

                if granted:
                    raise RuntimeError(
                        f"Unsafe DML privilege: "
                        f"{table} {privilege}"
                    )

            print(f"PASS: Direct DML denied on {table}")

    print("RA runtime authorization preflight: PASS")


if __name__ == "__main__":
    main()