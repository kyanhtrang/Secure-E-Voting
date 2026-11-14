"""Explicit local-demo composition; never loaded by backend.main.app."""

from collections.abc import Callable, Mapping

import psycopg
from psycopg import Connection
from pydantic import SecretStr

from backend.ra.auth_service import AuthenticationUnavailable, RAAuthenticationService
from backend.ra.demo_auth_config import load_demo_credential_verifier
from backend.ra.demo_session_service import DemoSessionService
from backend.ra.login_rate_limit import LimitedDemoAuthentication
from backend.ra.postgres_demo_auth import (
    PostgreSQLDemoSessionStore,
    PostgreSQLDemoVoterAccountReader,
)
from backend.ra.postgres_demo_session_issuer import PostgreSQLDemoSessionIssuer


def demo_connection_factory(password: SecretStr) -> Callable[[], Connection]:
    if not password.get_secret_value():
        raise ValueError("Missing demo database password")

    def connect() -> Connection:
        conn = None
        try:
            conn = psycopg.connect(
                host="127.0.0.1",
                port=5432,
                dbname="ra_db",
                user="ra_auth_login",
                password=password.get_secret_value(),
                connect_timeout=5,
                # Override ambient PGOPTIONS; no role switching or search path.
                options="-c statement_timeout=5000 -c lock_timeout=2000",
                application_name="secure-evoting-local-demo",
            )
            identity = conn.execute(
                "SELECT current_database(), session_user, current_user"
            ).fetchone()
            if identity != ("ra_db", "ra_auth_login", "ra_auth_login"):
                raise AuthenticationUnavailable("Authentication unavailable")
            conn.commit()
            return conn
        except Exception:
            if conn is not None:
                conn.close()
            raise AuthenticationUnavailable("Authentication unavailable") from None

    return connect


def compose_demo_services(
    environment: Mapping[str, str],
    *,
    connection_factory: Callable[[], Connection] | None = None,
) -> tuple[LimitedDemoAuthentication, DemoSessionService]:
    verifier = load_demo_credential_verifier(environment)
    if (
        environment.get("RA_DEMO_PROVIDER") != "demo-local"
        or environment.get("RA_DEMO_SUBJECT") != "demo-voter-001"
        or not environment.get("RA_DEMO_DB_PASSWORD")
    ):
        raise ValueError("Invalid local demo configuration")
    # These are fixed, not operator-selectable runtime identities/destinations.
    for key, expected in (
        ("RA_DEMO_DB_USER", "ra_auth_login"),
        ("RA_DEMO_DB_HOST", "127.0.0.1"),
        ("RA_DEMO_DB_NAME", "ra_db"),
        ("RA_DEMO_DB_PORT", "5432"),
    ):
        if environment.get(key, expected) != expected:
            raise ValueError("Invalid local demo database configuration")
    factory = connection_factory or demo_connection_factory(
        SecretStr(environment["RA_DEMO_DB_PASSWORD"])
    )
    authentication = RAAuthenticationService(
        verifier,
        PostgreSQLDemoVoterAccountReader(factory),
        PostgreSQLDemoSessionIssuer(factory),
    )
    sessions = DemoSessionService(PostgreSQLDemoSessionStore(factory))
    return LimitedDemoAuthentication(authentication), sessions
