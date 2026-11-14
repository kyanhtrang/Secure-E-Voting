import getpass
import json
import os
from pathlib import Path
from uuid import uuid4

import psycopg


def main():
    base = os.environ.get("LOCALAPPDATA")
    if not base:
        raise RuntimeError("LOCALAPPDATA unavailable")

    config_path = (
        Path(base)
        / "Secure-E-Voting"
        / "ra-demo-auth.local.json"
    )

    config = json.loads(
        config_path.read_text(encoding="utf-8")
    )

    if not (
        config.get("RA_ENVIRONMENT") == "local"
        and config.get("RA_DEMO_AUTH_ENABLED") == "true"
        and config.get("RA_DEMO_USERNAME") == "demo-voter"
        and config.get("RA_DEMO_PROVIDER") == "demo-local"
        and config.get("RA_DEMO_SUBJECT") == "demo-voter-001"
    ):
        raise RuntimeError("Unexpected demo configuration")

    provider = config["RA_DEMO_PROVIDER"]
    subject = config["RA_DEMO_SUBJECT"]

    print("PASS 1/4: Local demo configuration verified")

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
        conn.execute("SET ROLE ra_owner")

        identity = conn.execute(
            """
            SELECT current_database(),
                   session_user,
                   current_user
            """
        ).fetchone()

        if identity != (
            "ra_db",
            "ra_migrator_login",
            "ra_owner",
        ):
            raise RuntimeError("Unexpected database identity")

        print("PASS 2/4: Database identity verified")

        existing = conn.execute(
            """
            SELECT voter_id, is_active
            FROM ra.voters
            WHERE auth_provider = %s
              AND auth_subject = %s
            FOR UPDATE
            """,
            (provider, subject),
        ).fetchone()

        if existing is None:
            voter_id = uuid4()

            conn.execute(
                """
                INSERT INTO ra.voters (
                    voter_id,
                    auth_provider,
                    auth_subject,
                    is_active
                )
                VALUES (%s, %s, %s, true)
                """,
                (voter_id, provider, subject),
            )

            result = "CREATED"
        else:
            voter_id, is_active = existing

            if is_active is not True:
                raise RuntimeError(
                    "Existing demo voter is inactive; "
                    "refusing to reactivate automatically"
                )

            result = "ALREADY_REGISTERED"

        print("PASS 3/4: Demo voter", result)

        mapped = conn.execute(
            """
            SELECT ra.find_active_voter_id(%s, %s)
            """,
            (provider, subject),
        ).fetchone()

        if mapped is None or mapped[0] != voter_id:
            raise RuntimeError("Identity mapping mismatch")

    print("PASS 4/4: Identity lookup verified")
    print("RA demo voter registration: PASS 4/4")


if __name__ == "__main__":
    main()