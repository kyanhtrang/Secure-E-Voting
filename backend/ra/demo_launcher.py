"""Explicit local launcher; requires --enable-local-demo --load-local-verifier."""

import argparse
import getpass
import json
import os
import re
import warnings
from collections.abc import Mapping
from pathlib import Path

import uvicorn
from fastapi import FastAPI
from starlette.datastructures import Headers
from starlette.responses import JSONResponse

from backend.ra.auth_middleware import AuthNoStoreMiddleware
from backend.ra.demo_auth_runtime import compose_demo_services
from backend.ra.demo_auth_config import REQUIRED_KEYS, load_demo_credential_verifier
from backend.ra.login_router import NO_CACHE_HEADERS, get_ra_auth_service
from backend.ra.login_router import router as login_router
from backend.ra.session_router import get_ra_session_service
from backend.ra.session_router import router as session_router


class LocalDemoMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            headers = Headers(scope=scope)
            hosts = headers.getlist("host")
            origins = headers.getlist("origin")
            client = scope.get("client")
            host_ok = len(hosts) == 1 and re.fullmatch(
                r"(?:127\.0\.0\.1|localhost)(?::[0-9]{1,5})?", hosts[0]
            )
            origin_ok = not origins or (
                len(origins) == 1 and host_ok
                and origins[0] == f"http://{hosts[0]}"
            )
            if not client or client[0] != "127.0.0.1" or not host_ok or not origin_ok:
                response = JSONResponse(
                    {"detail": "Local demo access required"},
                    status_code=403,
                    headers=NO_CACHE_HEADERS,
                )
                await response(scope, receive, send)
                return
        await self.app(scope, receive, send)


def create_demo_app(environment: Mapping[str, str], *, connection_factory=None):
    # No automatic dotenv/service/credential-file discovery.
    authentication, sessions = compose_demo_services(
        environment, connection_factory=connection_factory
    )
    app = FastAPI(title="Secure E-Voting Local RA Demo", debug=False)
    app.include_router(login_router)
    app.include_router(session_router)
    app.dependency_overrides[get_ra_auth_service] = lambda: authentication
    app.dependency_overrides[get_ra_session_service] = lambda: sessions
    app.add_middleware(LocalDemoMiddleware)
    app.add_middleware(AuthNoStoreMiddleware)
    return app


def _unique_json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate configuration field")
        result[key] = value
    return result


def load_local_verifier(environment: Mapping[str, str]) -> dict[str, str]:
    """Read only the explicitly requested local verifier, never DB credentials."""
    base = environment.get("LOCALAPPDATA")
    if not base or not Path(base).is_absolute():
        raise ValueError("Local verifier configuration unavailable")
    path = Path(base) / "Secure-E-Voting" / "ra-demo-auth.local.json"
    try:
        with path.open(encoding="utf-8") as stream:
            # Bound input and reject oversized/non-object configuration.
            contents = stream.read(16385)
        if len(contents) > 16384:
            raise ValueError
        payload = json.loads(contents, object_pairs_hook=_unique_json_object)
        allowed = (*REQUIRED_KEYS, "RA_ENVIRONMENT", "RA_DEMO_AUTH_ENABLED")
        if not isinstance(payload, dict):
            raise ValueError
        values = {key: payload[key] for key in allowed}
        if any(not isinstance(value, str) for value in values.values()):
            raise ValueError
        load_demo_credential_verifier(values)
        if (values["RA_DEMO_PROVIDER"], values["RA_DEMO_SUBJECT"]) != (
            "demo-local", "demo-voter-001"
        ):
            raise ValueError
        return values
    except Exception:
        raise ValueError("Local verifier configuration unavailable or invalid") from None


def main():
    parser = argparse.ArgumentParser(description="Local RA authentication demo")
    parser.add_argument("--enable-local-demo", action="store_true", required=True)
    parser.add_argument(
        "--load-local-verifier", action="store_true", required=True,
        help="Read the verifier from the fixed LOCALAPPDATA location",
    )
    parser.parse_args()
    try:
        values = load_local_verifier(os.environ)
        # Never accept a DB password from the verifier JSON or command line.
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            values["RA_DEMO_DB_PASSWORD"] = getpass.getpass(
                "PostgreSQL password for ra_auth_login: "
            )
        try:
            app = create_demo_app(values)
        finally:
            values.pop("RA_DEMO_DB_PASSWORD", None)
    except Exception:
        parser.exit(2, "Local demo configuration unavailable or invalid\n")
    uvicorn.run(
        app,
        host="127.0.0.1",
        port=8000,
        proxy_headers=False,
        forwarded_allow_ips="",
        access_log=False,
        workers=1,
        log_level="warning",
        server_header=False,
    )


if __name__ == "__main__":
    main()
