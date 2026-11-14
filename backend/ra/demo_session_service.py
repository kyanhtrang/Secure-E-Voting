"""Compatibility with the existing local-demo issuer's token digest."""

import hashlib
from uuid import UUID

from backend.ra.session_service import RASessionService


class DemoSessionService(RASessionService):
    @staticmethod
    def _digest(token: str) -> str:
        # Reuse canonical encoding/length validation before any store access.
        # The general service continues to hash decoded bytes by default.
        RASessionService._digest(token)
        return hashlib.sha256(token.encode("ascii")).hexdigest()

    def issue_ra_session(self, voter_id: UUID) -> str:
        # Issuance must use the restricted wrapper and database-assigned TTL.
        raise RuntimeError("Use the restricted demo session issuer")
