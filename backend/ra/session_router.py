from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel

from backend.ra.login_router import NO_CACHE_HEADERS, SecureRALoginRoute
from backend.ra.session_service import InvalidRASession, RASessionService


router = APIRouter(
    prefix="/api/v1/ra/auth",
    tags=["RA Authentication"],
    route_class=SecureRALoginRoute,
)


def get_ra_session_service() -> RASessionService:
    raise HTTPException(503, "Authentication unavailable", headers=NO_CACHE_HEADERS)


def invalid_session() -> HTTPException:
    return HTTPException(
        401,
        "Invalid authentication credentials",
        headers={**NO_CACHE_HEADERS, "WWW-Authenticate": "Bearer"},
    )


def bearer_token(request: Request) -> str:
    values = request.headers.getlist("authorization")
    if len(values) != 1:
        raise invalid_session()
    parts = values[0].split(" ")
    if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1]:
        raise invalid_session()
    # Validate before service invocation, including duplicate encodings.
    try:
        RASessionService._digest(parts[1])
    except InvalidRASession:
        raise invalid_session() from None
    return parts[1]


class MeResponse(BaseModel):
    voter_id: UUID


@router.get("/me", response_model=MeResponse)
def me(
    request: Request,
    service: RASessionService = Depends(get_ra_session_service),
) -> MeResponse:
    token = bearer_token(request)
    try:
        return MeResponse(voter_id=service.resolve_voter_id(token))
    except InvalidRASession:
        raise invalid_session() from None
    except Exception:
        raise HTTPException(
            503, "Authentication unavailable", headers=NO_CACHE_HEADERS
        ) from None


@router.post("/logout", status_code=204)
def logout(
    request: Request,
    service: RASessionService = Depends(get_ra_session_service),
) -> Response:
    token = bearer_token(request)
    try:
        service.revoke_ra_session(token)
    except InvalidRASession:
        raise invalid_session() from None
    except Exception:
        raise HTTPException(
            503, "Authentication unavailable", headers=NO_CACHE_HEADERS
        ) from None
    return Response(status_code=204, headers=NO_CACHE_HEADERS)
