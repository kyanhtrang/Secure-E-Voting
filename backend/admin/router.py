"""Local admin HTTP boundary, deliberately absent from backend.main.app."""
import re
import unicodedata
from datetime import datetime
from uuid import UUID, uuid4

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

from backend.admin.store import AdminError
from backend.crypto.credential_protocol import strict_json
from backend.ra.auth_service import AuthenticationDenied
from backend.ra.login_rate_limit import LoginRateLimited
from backend.ra.demo_launcher import LocalDemoMiddleware


def identifier(value):
    try:
        result = UUID(value)
        if str(result) != value:
            raise ValueError()
        return result
    except (ValueError, TypeError, AttributeError):
        raise AdminError(422) from None


def validate(data, fields):
    if type(data) is not dict or set(data) != set(fields):
        raise AdminError(422)
    for field in fields:
        value = data[field]
        if field == "revision":
            if type(value) is not int or not 1 <= value <= 2147483647:
                raise AdminError(422)
        elif type(value) is not str or not value or len(value) > (1024 if field == "password" else 255):
            raise AdminError(422)
    if "title" in data and (not data["title"].strip() or any(ord(c) < 32 for c in data["title"])):
        raise AdminError(422)
    if "candidate_name" in data:
        name = data["candidate_name"]
        if len(name) > 128 or name != name.strip() or name != unicodedata.normalize("NFC", name) or not name or any(unicodedata.category(c).startswith("C") for c in name):
            raise AdminError(422)
    if "opens_at" in data:
        try:
            for field in ("opens_at", "closes_at"):
                if not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", data[field]):
                    raise ValueError()
            if datetime.fromisoformat(data["opens_at"]) >= datetime.fromisoformat(data["closes_at"]):
                raise ValueError()
        except ValueError:
            raise AdminError(422) from None
    return data


def create_admin_app(service=None):
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @app.middleware("http")
    async def boundary(request, call_next):
        try:
            response = await call_next(request)
        except Exception:
            response = JSONResponse({"detail": "Administrative service unavailable"}, status_code=503)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    app.add_middleware(LocalDemoMiddleware)

    @app.api_route("/api/v1/admin/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
    async def admin(request: Request, path: str):
        try:
            if service is None:
                raise AdminError(503)
            if request.url.query:
                raise AdminError(422)
            method = request.method
            data = {}
            if method != "GET":
                if request.headers.get("content-type", "").split(";")[0] != "application/json":
                    raise AdminError(422)
                raw = bytearray()
                async for chunk in request.stream():
                    raw.extend(chunk)
                    if len(raw) > 8192:
                        raise AdminError(422)
                data = strict_json(bytes(raw))
            if path == "auth/login" and method == "POST":
                validate(data, ("username", "password"))
                token = service.auth.limited.login(data["username"], data["password"])
                return {"access_token": token, "token_type": "bearer"}
            header = request.headers.get("authorization", "")
            if not header.startswith("Bearer ") or header.count(" ") != 1:
                raise AdminError(401)
            token = header[7:]
            # Authenticate before parsing resource IDs, including unknown routes.
            service.auth.identity(token)
            if path == "auth/me" and method == "GET":
                return service.auth.identity(token)
            if path == "auth/logout" and method == "POST":
                validate(data, ()); service.auth.logout(token)
                return Response(status_code=204)
            if path == "keysets" and method == "GET":
                return {"keysets": service.keys(token)}
            if path == "elections":
                if method == "GET":
                    return {"elections": service.list(token)}
                if method == "POST":
                    return JSONResponse(service.create(token, validate(data, ("title", "opens_at", "closes_at"))), status_code=201)
            parts = path.split("/")
            if len(parts) >= 2 and parts[0] == "elections":
                election = identifier(parts[1])
                if len(parts) == 2:
                    if method == "GET": return service.detail(token, election)
                    if method == "PUT": return service.change(token, election, "edit", validate(data, ("revision", "title", "opens_at", "closes_at")))
                if len(parts) == 3:
                    action = parts[2]
                    if action == "audit" and method == "GET": return {"events": service.audit(token, election)}
                    if action == "finalize" and method == "POST":
                        validate(data, ("revision", "keyset_id"))
                        return service.finalize(token, election, data["revision"], data["keyset_id"])
                    if action in ("open", "close") and method == "POST":
                        validate(data, ()); return service.transition(token, election, action == "close")
                    if action == "candidates" and method == "POST":
                        validate(data, ("revision", "candidate_name")); data["candidate_id"] = str(uuid4())
                        return service.change(token, election, "candidate", data)
                if len(parts) == 4 and parts[2] == "candidates" and method in ("PUT", "DELETE"):
                    candidate = identifier(parts[3])
                    validate(data, ("revision", "candidate_name") if method == "PUT" else ("revision",))
                    data["candidate_id"] = str(candidate)
                    return service.change(token, election, "candidate" if method == "PUT" else "remove", data)
            raise AdminError(404)
        except LoginRateLimited as error:
            return JSONResponse({"detail": "Login temporarily limited"}, status_code=429, headers={"Retry-After": str(error.retry_after)})
        except AuthenticationDenied:
            return JSONResponse({"detail": "Authentication required"}, status_code=401)
        except AdminError as error:
            messages = {401: "Authentication required", 403: "Operation forbidden", 404: "Resource unavailable", 409: "Conflicting election operation; refresh and reconcile", 422: "Invalid administrative request"}
            return JSONResponse({"detail": messages.get(error.status, "Administrative service unavailable")}, status_code=error.status)
        except (ValueError, TypeError):
            return JSONResponse({"detail": "Invalid administrative request"}, status_code=422)
        except Exception:
            return JSONResponse({"detail": "Administrative service unavailable"}, status_code=503)
    return app
