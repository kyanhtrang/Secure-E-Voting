"""Manual DB-test support. Importing this module never connects or reads secrets."""

import getpass
import hashlib
import re
import secrets
import warnings
from uuid import UUID

import psycopg
from pydantic import SecretStr


def check(condition, label):
    if not condition:
        raise AssertionError(label)


def digest(token):
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def prompt_password(prompt):
    # Refuse getpass's fallback to an echoing input stream.
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        value = SecretStr(getpass.getpass(prompt))
    check(bool(value.get_secret_value()), "Empty database password refused")
    return value


def validate_disposable_designation(database, marker):
    check(bool(re.fullmatch(r"ra_demo_test_[a-z0-9_]+", database)),
          "Disposable database must have a distinct ra_demo_test_ name")
    try:
        canonical = str(UUID(marker))
    except (ValueError, TypeError, AttributeError):
        raise AssertionError("Disposable marker must be a UUID") from None
    check(marker == canonical, "Disposable marker must be a canonical UUID")


def verify_disposable_database(conn, database, marker):
    validate_disposable_designation(database, marker)
    row = conn.execute(
        """SELECT pg_catalog.current_database(),
                  pg_catalog.shobj_description(d.oid, 'pg_database')
           FROM pg_catalog.pg_database AS d
           WHERE d.datname = pg_catalog.current_database()"""
    ).fetchone()
    check(row == (database, "secure-evoting-disposable:" + marker),
          "Database is not independently marked disposable; refusing writes")


def database_factory(password, *, database="ra_db", port=5432, fixture=False,
                     disposable_marker=None):
    """Keep fixture-only owner connections separate from real auth logins."""
    if disposable_marker is not None:
        validate_disposable_designation(database, disposable_marker)
    else:
        check(database == "ra_db", "Existing-demo smoke target must be ra_db")
    check(isinstance(port, int) and 1 <= port <= 65535, "Invalid database port")
    login = "ra_migrator_login" if fixture else "ra_auth_login"
    expected_role = "ra_owner" if fixture else "ra_auth_login"

    def connect():
        conn = psycopg.connect(
            host="127.0.0.1", port=port, dbname=database, user=login,
            password=password.get_secret_value(), connect_timeout=5,
            options="-c statement_timeout=5000 -c lock_timeout=2000",
        )
        try:
            if fixture:
                conn.execute("SET LOCAL ROLE ra_owner")
            check(conn.execute(
                "SELECT current_database(), session_user, current_user"
            ).fetchone() == (database, login, expected_role),
                "Unexpected database connection identity")
            if disposable_marker is not None:
                # Recheck on every connection, including cleanup and runtime.
                verify_disposable_database(conn, database, disposable_marker)
            return conn
        except BaseException:
            conn.close()
            raise

    return connect


def require_migration(conn):
    check(conn.execute("SELECT version_num FROM ra.alembic_version").fetchone()
          == ("f3c2a1d4e6b8",), "Expected reviewed demo migration is not installed")


def seed_disposable_voters(conn, voter_id, other_id, *, database, marker):
    verify_disposable_database(conn, database, marker)
    require_migration(conn)
    check(conn.execute(
        "SELECT 1 FROM ra.voters WHERE auth_provider=%s AND auth_subject=%s",
        ("demo-local", "demo-voter-001"),
    ).fetchone() is None, "Refusing to replace an existing demo identity")
    conn.execute(
        """INSERT INTO ra.voters(voter_id, auth_provider, auth_subject, is_active)
           VALUES (%s, %s, %s, true), (%s, %s, %s, true)""",
        (voter_id, "demo-local", "demo-voter-001",
         other_id, "demo-e2e-fixture", str(other_id)),
    )


def synthetic_environment(auth_password):
    password = secrets.token_urlsafe(32)
    salt = secrets.token_bytes(16)
    return password, {
        "RA_ENVIRONMENT": "local", "RA_DEMO_AUTH_ENABLED": "true",
        "RA_DEMO_USERNAME": "demo-e2e", "RA_DEMO_PROVIDER": "demo-local",
        "RA_DEMO_SUBJECT": "demo-voter-001", "RA_DEMO_SALT_HEX": salt.hex(),
        "RA_DEMO_DIGEST_HEX": hashlib.scrypt(
            password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32
        ).hex(),
        "RA_DEMO_DB_PASSWORD": auth_password.get_secret_value(),
    }
