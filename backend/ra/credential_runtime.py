"""Local-only credential composition. Default backend.main.app is unchanged."""

import psycopg
from starlette.datastructures import MutableHeaders

from backend.ra.credential_router import get_credential_service, router
from backend.ra.credential_service import CredentialUnavailable
from backend.ra.demo_launcher import create_demo_app
from backend.ra.login_router import NO_CACHE_HEADERS


class CredentialNoStore:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        async def wrapped(message):
            if message["type"] == "http.response.start":
                MutableHeaders(scope=message).update(NO_CACHE_HEADERS)
            await send(message)
        protected = scope["type"] == "http" and scope["path"].startswith("/api/v1/ra/credentials")
        await self.app(scope, receive, wrapped if protected else send)


def credential_connection_factory(password):
    if not password.get_secret_value():
        raise ValueError("Missing issuance database password")

    def connect():
        conn = None
        try:
            conn = psycopg.connect(host="127.0.0.1", port=5432, dbname="ra_db",
                user="ra_issuance_login", password=password.get_secret_value(), connect_timeout=5,
                options="-c statement_timeout=5000 -c lock_timeout=2000",
                application_name="secure-evoting-ra-credentials")
            if conn.execute("SELECT current_database(), session_user, current_user").fetchone() != (
                "ra_db", "ra_issuance_login", "ra_issuance_login"
            ):
                raise CredentialUnavailable()
            conn.commit()
            return conn
        except Exception:
            if conn is not None:
                conn.close()
            raise CredentialUnavailable() from None
    return connect


def create_credential_app(auth_config, service, *, auth_connection_factory=None, catalogue=None):
    app = create_demo_app(auth_config, connection_factory=auth_connection_factory)
    app.include_router(router)
    app.dependency_overrides[get_credential_service] = lambda: service
    app.add_middleware(CredentialNoStore)
    if catalogue is not None:
        from backend.ra.election_catalogue import get_election_catalogue, router as catalogue_router
        app.include_router(catalogue_router)
        app.dependency_overrides[get_election_catalogue] = lambda: catalogue
    return app
