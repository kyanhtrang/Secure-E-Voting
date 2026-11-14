from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from pydantic import BaseModel, ConfigDict, Field, SecretStr

from backend.ra.auth_service import (
    RAAuthenticationService,
    AuthenticationDenied,
    AuthenticationUnavailable,
)
from backend.ra.login_rate_limit import LoginRateLimited


NO_CACHE_HEADERS = {
    "Cache-Control": "no-store",
    "Pragma": "no-cache",
}


class SecureRALoginRoute(APIRoute):
    def get_route_handler(self):
        original_handler = super().get_route_handler()

        async def secure_handler(request: Request) -> Response:
            try:
                response = await original_handler(request)
            except RequestValidationError:
                # Never echo passwords or other request input.
                return JSONResponse(
                    status_code=422,
                    content={"detail": "Invalid login request"},
                    headers=NO_CACHE_HEADERS,
                )
            except HTTPException as exc:
                return JSONResponse(
                    status_code=exc.status_code,
                    content={"detail": exc.detail},
                    headers={**(exc.headers or {}), **NO_CACHE_HEADERS},
                )
            except Exception:
                return JSONResponse(
                    status_code=503,
                    content={"detail": "Authentication unavailable"},
                    headers=NO_CACHE_HEADERS,
                )

            response.headers.update(NO_CACHE_HEADERS)
            return response

        return secure_handler


router = APIRouter(
    prefix="/api/v1/ra/auth",
    tags=["RA Authentication"],
    route_class=SecureRALoginRoute,
)


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=1, max_length=256)
    password: SecretStr = Field(min_length=1, max_length=1024)


class LoginResponse(BaseModel):
    access_token: str
    token_type: Literal["Bearer"] = "Bearer"


def get_ra_auth_service() -> RAAuthenticationService:
    # Deliberately disabled until trusted dependencies
    # and runtime authorization are configured.
    raise HTTPException(
        status_code=503,
        detail="Authentication unavailable",
        headers=NO_CACHE_HEADERS,
    )


@router.post(
    "/login",
    response_model=LoginResponse,
)
def login(
    payload: LoginRequest,
    response: Response,
    service: RAAuthenticationService = Depends(
        get_ra_auth_service
    ),
) -> LoginResponse:
    response.headers.update(NO_CACHE_HEADERS)

    try:
        token = service.login(
            payload.username,
            payload.password.get_secret_value(),
        )
    except AuthenticationDenied:
        raise HTTPException(
            status_code=401,
            detail="Invalid credentials",
            headers=NO_CACHE_HEADERS,
        ) from None
    except AuthenticationUnavailable:
        raise HTTPException(
            status_code=503,
            detail="Authentication unavailable",
            headers=NO_CACHE_HEADERS,
        ) from None
    except LoginRateLimited as exc:
        raise HTTPException(
            status_code=429,
            detail="Too many login attempts",
            headers={**NO_CACHE_HEADERS, "Retry-After": str(exc.retry_after)},
        ) from None
    except Exception:
        # Fail closed without exposing internal errors.
        raise HTTPException(
            status_code=503,
            detail="Authentication unavailable",
            headers=NO_CACHE_HEADERS,
        ) from None

    if not isinstance(token, str) or not token:
        raise HTTPException(
            status_code=503,
            detail="Authentication unavailable",
            headers=NO_CACHE_HEADERS,
        )

    return LoginResponse(access_token=token)
