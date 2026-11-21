"""Explicit local Tally HTTP boundary. No ciphertext/plaintext ballot endpoint."""
from uuid import UUID
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
from starlette.concurrency import run_in_threadpool

from backend.crypto.credential_protocol import strict_json
from backend.ra.auth_service import AuthenticationDenied
from backend.ra.demo_launcher import LocalDemoMiddleware
from backend.ra.login_rate_limit import LoginRateLimited
from backend.tally.verification import TallyError


def create_tally_app(service=None):
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(LocalDemoMiddleware)

    @app.middleware("http")
    async def security(request, call_next):
        try: response = await call_next(request)
        except Exception: response = JSONResponse({"detail": "Restricted tally unavailable", "code": "UNAVAILABLE"}, status_code=503)
        response.headers.update({"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer"})
        return response

    def dispatch(path, method, header, data):
        if service is None: raise TallyError()
        if path == "auth/login" and method == "POST":
            if type(data) is not dict or set(data) != {"username", "password"} or any(type(data[k]) is not str or not 1 <= len(data[k]) <= (1024 if k == "password" else 255) for k in data):
                raise TallyError(422, "INVALID_REQUEST")
            return {"access_token": service.auth.limited.login(data["username"], data["password"]), "token_type": "bearer"}
        if not header.startswith("Bearer ") or header.count(" ") != 1: raise TallyError(401, "AUTHENTICATION")
        token = header[7:]; service.auth.identity(token)
        if path == "auth/me" and method == "GET": return service.auth.identity(token)
        if path == "auth/logout" and method == "POST":
            if data != {}: raise TallyError(422, "INVALID_REQUEST")
            service.auth.logout(token); return Response(status_code=204)
        if path == "elections" and method == "GET": return {"elections": service.elections(token)}
        parts = path.split("/")
        if len(parts) == 3 and parts[0] == "elections":
            election = UUID(parts[1])
            if str(election) != parts[1]: raise ValueError()
            if parts[2] == "run" and method == "POST":
                if data != {}: raise TallyError(422, "INVALID_REQUEST")
                return service.run(token, election)
            if parts[2] == "report" and method == "GET": return service.report(token, election)
        raise TallyError(404, "UNAVAILABLE")

    @app.api_route("/api/v1/tally/{path:path}", methods=["GET", "POST"])
    async def handle(request: Request, path: str):
        try:
            if request.url.query: raise ValueError()
            data = None
            if request.method == "POST":
                if request.headers.get("content-type", "").split(";")[0] != "application/json": raise ValueError()
                body = bytearray()
                async for chunk in request.stream():
                    body.extend(chunk)
                    if len(body) > 8192: raise ValueError()
                data = strict_json(bytes(body))
            return await run_in_threadpool(dispatch, path, request.method, request.headers.get("authorization", ""), data)
        except LoginRateLimited as error:
            return JSONResponse({"detail": "Login temporarily limited", "code": "RATE_LIMIT"}, status_code=429, headers={"Retry-After": str(error.retry_after)})
        except AuthenticationDenied: error = TallyError(401, "AUTHENTICATION")
        except TallyError as caught: error = caught
        except (ValueError, TypeError): error = TallyError(422, "INVALID_REQUEST")
        except Exception: error = TallyError()
        return JSONResponse({"detail": "Restricted tally request rejected", "code": error.code}, status_code=error.status)
    return app
