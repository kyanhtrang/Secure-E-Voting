import getpass

import psycopg
from psycopg.errors import InsufficientPrivilege


EXPECTED_FUNCTIONS = {
    "find_active_voter_id",
    "create_session",
    "find_active_session",
    "revoke_session",
}

EXPECTED_TABLES = {"voters", "ra_sessions"}


def check(condition, message):
    if not condition:
        raise AssertionError(message)


def main():
    password = getpass.getpass(
        "PostgreSQL password for ra_auth_login: "
    )

    with psycopg.connect(
        host="127.0.0.1",
        port=5432,
        dbname="ra_db",
        user="ra_auth_login",
        password=password,
        connect_timeout=5,
        autocommit=True,
    ) as conn:

        identity = conn.execute(
            """
            SELECT current_database(),
                   session_user,
                   current_user
            """
        ).fetchone()

        check(
            identity == (
                "ra_db",
                "ra_auth_login",
                "ra_auth_login",
            ),
            "Unexpected database identity",
        )
        print("PASS 1/5: Dedicated auth role login")

        schema_usage = conn.execute(
            """
            SELECT has_schema_privilege(
                current_user, 'ra', 'USAGE'
            )
            """
        ).fetchone()[0]

        check(not schema_usage, "Unexpected RA schema USAGE")
        print("PASS 2/5: RA schema access denied")

        functions = conn.execute(
            """
            SELECT
                p.proname,
                has_function_privilege(
                    current_user, p.oid, 'EXECUTE'
                )
            FROM pg_proc AS p
            JOIN pg_namespace AS n
              ON n.oid = p.pronamespace
            WHERE n.nspname = 'ra'
              AND p.proname = ANY(%s)
            """,
            (list(EXPECTED_FUNCTIONS),),
        ).fetchall()

        check(
            {name for name, _ in functions} == EXPECTED_FUNCTIONS,
            "Missing protected functions",
        )
        check(
            all(not allowed for _, allowed in functions),
            "Unexpected function EXECUTE privilege",
        )
        print("PASS 3/5: Protected function EXECUTE denied")

        tables = conn.execute(
            """
            SELECT
                c.relname,
                has_table_privilege(
                    current_user, c.oid, 'SELECT'
                ),
                has_table_privilege(
                    current_user, c.oid, 'INSERT'
                ),
                has_table_privilege(
                    current_user, c.oid, 'UPDATE'
                ),
                has_table_privilege(
                    current_user, c.oid, 'DELETE'
                )
            FROM pg_class AS c
            JOIN pg_namespace AS n
              ON n.oid = c.relnamespace
            WHERE n.nspname = 'ra'
              AND c.relname = ANY(%s)
            """,
            (list(EXPECTED_TABLES),),
        ).fetchall()

        check(
            {row[0] for row in tables} == EXPECTED_TABLES,
            "Missing protected tables",
        )
        check(
            all(not granted for row in tables for granted in row[1:]),
            "Unexpected RA table privilege",
        )
        print("PASS 4/5: Direct table access denied")

        try:
            conn.execute(
                """
                SELECT ra.find_active_voter_id(
                    %s::text, %s::text
                )
                """,
                ("demo-local", "demo-voter-001"),
            )
        except InsufficientPrivilege:
            print("PASS 5/5: Unauthorized lookup blocked")
        else:
            raise AssertionError(
                "SECURITY FAILURE: Unauthorized lookup succeeded"
            )

    print("RA authentication role security: PASS 5/5")


if __name__ == "__main__":
    main()