"""Bounded, anonymous-only HTTP boundary. Errors never echo submitted data."""

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute

from backend.crypto.credential_protocol import ProtocolError, strict_json
from backend.voting.ballot_service import AlreadySpent, ElectionClosed, ReceiptNotFound


NO_STORE = {"Cache-Control": "no-store", "Pragma": "no-cache", "Referrer-Policy": "no-referrer"}


class AnonymousRoute(APIRoute):
    def get_route_handler(self):
        original = super().get_route_handler()

        async def handler(request):
            try:
                # No bearer tokens, RA cookies, identity headers or query metadata.
                forbidden = {"authorization", "proxy-authorization", "cookie", "x-voter-id",
                             "x-ra-token", "x-username", "x-request-id"}
                if request.url.query or any(name in request.headers for name in forbidden):
                    raise HTTPException(400, "Anonymous request required")
                content_type = request.headers.getlist("content-type")
                if len(content_type) != 1 or content_type[0].lower() != "application/json":
                    raise HTTPException(415, "JSON request required")
                body = bytearray()
                async for chunk in request.stream():
                    if len(body) + len(chunk) > 32768:
                        raise HTTPException(413, "Invalid ballot request")
                    body.extend(chunk)
                request.state.ballot = strict_json(bytes(body))
                response = await original(request)
            except (ProtocolError, RecursionError):
                response = JSONResponse({"detail": "Invalid anonymous credential or ballot"}, status_code=422)
            except AlreadySpent:
                response = JSONResponse({"detail": "Credential already spent"}, status_code=409)
            except ElectionClosed:
                response = JSONResponse({"detail": "Election not open"}, status_code=409)
            except ReceiptNotFound:
                response = JSONResponse({"detail": "Receipt not found"}, status_code=404)
            except HTTPException as error:
                response = JSONResponse({"detail": error.detail}, status_code=error.status_code)
            except Exception:
                response = JSONResponse({"detail": "Voting unavailable"}, status_code=503)
            response.headers.update(NO_STORE)
            return response
        return handler


router = APIRouter(prefix="/api/v1/vote/ballots", tags=["Anonymous voting"], route_class=AnonymousRoute)


def get_ballot_service():
    raise HTTPException(503, "Voting unavailable")


@router.post("", status_code=201)
def submit_ballot(request: Request, service=Depends(get_ballot_service)):
    return {"status": "accepted", "receipt_hash": service.submit(request.state.ballot)}


@router.post("/receipt")
def recover_receipt(request: Request, service=Depends(get_ballot_service)):
    return {"status": "accepted", "receipt_hash": service.recover(request.state.ballot)}
