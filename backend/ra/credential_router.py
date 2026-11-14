from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator
from uuid import UUID

from backend.crypto.credential_protocol import b64decode, b64encode, strict_json, uuid_string, PROFILE
from backend.ra.credential_service import (
    CredentialConflict, CredentialDenied, CredentialExpired, InvalidBlindedMessage,
)
from backend.ra.login_router import NO_CACHE_HEADERS
from backend.ra.session_router import bearer_token, invalid_session
from backend.ra.session_service import InvalidRASession


class CredentialRoute(APIRoute):
    def get_route_handler(self):
        original = super().get_route_handler()

        async def handler(request):
            try:
                body = bytearray()
                async for chunk in request.stream():
                    if len(body) + len(chunk) > 4096:
                        raise HTTPException(413, "Invalid credential request")
                    body.extend(chunk)
                try:
                    strict_json(bytes(body))
                except ValueError:
                    raise HTTPException(422, "Invalid credential request") from None
                request._body = bytes(body)  # Cache the bounded body for FastAPI validation.
                response = await original(request)
            except RequestValidationError:
                response = JSONResponse({"detail": "Invalid credential request"}, status_code=422)
            except HTTPException as error:
                response = JSONResponse({"detail": error.detail}, status_code=error.status_code,
                                        headers=error.headers)
            except Exception:
                response = JSONResponse({"detail": "Credential issuance unavailable"}, status_code=503)
            response.headers.update(NO_CACHE_HEADERS)
            return response

        return handler


router = APIRouter(prefix="/api/v1/ra/credentials", tags=["RA credentials"], route_class=CredentialRoute)


def get_credential_service():
    raise HTTPException(503, "Credential issuance unavailable", headers=NO_CACHE_HEADERS)


class CredentialRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    election_id: UUID
    request_id: UUID
    blinded_msg: SecretStr = Field(min_length=512, max_length=512)

    @field_validator("election_id", "request_id", mode="before")
    @classmethod
    def canonical_uuid(cls, value):
        uuid_string(value)
        return value


@router.post("/issue")
def issue(payload: CredentialRequest, request: Request, response: Response,
          service=Depends(get_credential_service)):
    token = bearer_token(request)
    try:
        blinded = b64decode(payload.blinded_msg.get_secret_value(), 384)
    except ValueError:
        raise HTTPException(422, "Invalid credential request") from None
    try:
        result = service.issue(token, payload.election_id, payload.request_id, blinded)
    except InvalidRASession:
        raise invalid_session() from None
    except CredentialDenied:
        raise HTTPException(403, "Credential issuance not permitted") from None
    except CredentialConflict:
        raise HTTPException(409, "Credential already reserved or issued") from None
    except CredentialExpired:
        raise HTTPException(410, "Credential recovery unavailable") from None
    except InvalidBlindedMessage:
        raise HTTPException(422, "Invalid credential request") from None
    except Exception:
        raise HTTPException(503, "Credential issuance unavailable") from None
    response.status_code = 200 if result.replayed else 201
    return {"status": "replayed" if result.replayed else "issued", "ra_key_id": result.key_id,
            "profile": PROFILE, "blind_sig": b64encode(result.blind_signature)}
