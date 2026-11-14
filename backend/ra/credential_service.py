"""RA-only issuance orchestration; no serial, ballot, or finalized credential."""

import hashlib
import hmac
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from backend.crypto.credential_protocol import (
    PROFILE, b64encode, canonical_manifest, public_rsa, strict_json, verify_manifest,
)
from backend.ra.demo_session_service import DemoSessionService


class CredentialDenied(Exception):
    pass


class CredentialConflict(Exception):
    pass


class CredentialExpired(Exception):
    pass


class CredentialUnavailable(Exception):
    pass


class InvalidBlindedMessage(Exception):
    pass


@dataclass(frozen=True, repr=False)
class CredentialPolicy:
    manifest_bytes: bytes
    manifest_signature: bytes
    config_hash: bytes
    key_id: str
    spki_der: bytes
    key_fingerprint: bytes


@dataclass(frozen=True, repr=False)
class CredentialContext:
    reservation_id: UUID
    voter_id: UUID
    election_id: UUID
    request_id: UUID
    blinded_hash: bytes
    key_id: str
    config_hash: bytes
    reserved_at: datetime
    recovery_expires_at: datetime
    issuance_id: UUID | None
    ciphertext: bytes | None
    nonce: bytes | None
    storage_key_id: str | None


@dataclass(frozen=True, repr=False)
class IssuedCredential:
    blind_signature: bytes
    key_id: str
    replayed: bool


class CredentialIssuanceService:
    def __init__(self, store, signer, recovery, pinned_authority: bytes):
        if not isinstance(pinned_authority, bytes) or len(pinned_authority) != 32:
            raise ValueError("Invalid manifest authority pin")
        self.store = store
        self.signer = signer
        self.recovery = recovery
        self._authority = pinned_authority

    def issue(self, token: str, election_id: UUID, request_id: UUID,
              blinded_msg: bytes) -> IssuedCredential:
        # Validation preserves the existing demo's explicit ASCII digest mode.
        digest = DemoSessionService._digest(token)
        if not isinstance(election_id, UUID) or not isinstance(request_id, UUID):
            raise InvalidBlindedMessage()
        if not isinstance(blinded_msg, bytes) or len(blinded_msg) != 384:
            raise InvalidBlindedMessage()
        policy = self.store.policy(digest, election_id)
        try:
            manifest = strict_json(policy.manifest_bytes)
            manifest, config_hash = verify_manifest(
                {"manifest": manifest, "signature": b64encode(policy.manifest_signature)},
                self._authority, str(election_id),
            )
            if (canonical_manifest(manifest) != policy.manifest_bytes
                or bytes.fromhex(config_hash) != policy.config_hash
                or manifest["ra_key"]["key_id"] != policy.key_id
                or manifest["ra_key"]["spki"] != b64encode(policy.spki_der)
                or bytes.fromhex(manifest["ra_key"]["fingerprint"]) != policy.key_fingerprint):
                raise CredentialUnavailable()
            public = public_rsa(manifest["ra_key"]["spki"])
        except Exception:
            raise CredentialUnavailable() from None
        representative = int.from_bytes(blinded_msg, "big")
        if not 0 < representative < public.public_numbers().n:
            raise InvalidBlindedMessage()
        request_hash = hashlib.sha256(blinded_msg).digest()
        params = (digest, election_id, request_id, request_hash, policy.config_hash)
        # Transaction 1 exits/commits BEFORE any signer operation.
        reserved = self.store.reserve(*params)
        self._check_context(reserved, election_id, request_id, request_hash, policy)
        signature = None
        replayed = False
        # Transaction 2 locks the same authorization through signing + persistence.
        # Exiting successfully is mandatory before a response can be returned.
        with self.store.locked(*params) as transaction:
            context = transaction.context
            self._check_context(context, election_id, request_id, request_hash, policy)
            if context.issuance_id is not None:
                signature = self.recovery.decrypt(context)
                replayed = True
            else:
                if not self.signer.matches(policy.key_id, policy.key_fingerprint):
                    raise CredentialUnavailable()
                # Never sign request_hash. Only the ORIGINAL blinded_msg is used.
                signature = self.signer.sign(blinded_msg)
                if not isinstance(signature, bytes) or len(signature) != 384:
                    raise CredentialUnavailable()
                ciphertext, nonce, storage_key_id = self.recovery.encrypt(signature, context)
                saved = transaction.complete(ciphertext, nonce, storage_key_id)
                self._check_context(saved, election_id, request_id, request_hash, policy)
                if saved.reservation_id != context.reservation_id or saved.issuance_id is None:
                    raise CredentialUnavailable()
                # Return the persisted protected response, not an uncommitted buffer.
                signature = self.recovery.decrypt(saved)
        return IssuedCredential(signature, policy.key_id, replayed)

    @staticmethod
    def _check_context(context, election, request, digest, policy):
        if (not isinstance(context, CredentialContext)
            or context.election_id != election or context.request_id != request
            or not hmac.compare_digest(context.blinded_hash, digest)
            or context.config_hash != policy.config_hash or context.key_id != policy.key_id):
            raise CredentialUnavailable()
