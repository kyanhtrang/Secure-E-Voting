"""Opt-in public policy catalogue, using existing restricted session/policy reads.

Eligibility is deliberately unknown here: only issuance can decide it with the
currently deployed DB API. Listing never reserves or consumes an authorization.
"""

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request

from backend.crypto.credential_protocol import b64encode, canonical_manifest, strict_json, verify_manifest
from backend.ra.demo_session_service import DemoSessionService
from backend.ra.login_router import NO_CACHE_HEADERS, SecureRALoginRoute
from backend.ra.session_router import bearer_token, get_ra_session_service, invalid_session
from backend.ra.session_service import InvalidRASession


class ElectionCatalogue:
    def __init__(self, store, pin, election_ids):
        if type(pin) is not bytes or len(pin) != 32 or len(election_ids) > 100:
            raise ValueError("Invalid public election catalogue configuration")
        self.store, self.pin = store, pin
        self.ids = tuple(UUID(str(value)) for value in election_ids)
        if len(set(self.ids)) != len(self.ids):
            raise ValueError("Duplicate catalogue election")

    def list(self, token):
        digest = DemoSessionService._digest(token)
        rows = []
        for election in self.ids:
            policy = self.store.policy(digest, election)
            bundle = {"manifest": strict_json(policy.manifest_bytes), "signature": b64encode(policy.manifest_signature)}
            manifest, config_hash = verify_manifest(bundle, self.pin, str(election))
            if (canonical_manifest(manifest) != policy.manifest_bytes
                or bytes.fromhex(config_hash) != policy.config_hash
                or manifest["ra_key"]["key_id"] != policy.key_id
                or manifest["ra_key"]["spki"] != b64encode(policy.spki_der)
                or bytes.fromhex(manifest["ra_key"]["fingerprint"]) != policy.key_fingerprint):
                raise ValueError("Public policy unavailable")
            rows.append({"election_id": str(election), "bundle": bundle,
                         "eligibility": "checked_on_issue", "credential_availability": "checked_on_issue"})
        return {"elections": rows}


router = APIRouter(prefix="/api/v1/ra", tags=["Local election catalogue"], route_class=SecureRALoginRoute)


def get_election_catalogue():
    raise HTTPException(503, "Election catalogue unavailable", headers=NO_CACHE_HEADERS)


@router.get("/elections")
def elections(request: Request, catalogue=Depends(get_election_catalogue), sessions=Depends(get_ra_session_service)):
    token = bearer_token(request)
    try:
        sessions.resolve_voter_id(token)  # Also validates sessions for an empty catalogue.
        return catalogue.list(token)
    except InvalidRASession:
        raise invalid_session() from None
    except Exception:
        raise HTTPException(503, "Election catalogue unavailable", headers=NO_CACHE_HEADERS) from None
