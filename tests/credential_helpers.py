"""Transactional business-logic double, not evidence of PostgreSQL concurrency."""

import hashlib
import secrets
import threading
from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import Mock
from uuid import uuid4

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

from backend.crypto.credential_protocol import canonical_manifest
from backend.ra.credential_recovery import CredentialRecovery
from backend.ra.credential_service import (
    CredentialConflict, CredentialContext, CredentialDenied, CredentialExpired,
    CredentialIssuanceService, CredentialPolicy, CredentialUnavailable,
)
from backend.ra.demo_session_service import DemoSessionService
from backend.ra.session_service import InvalidRASession
from crypto_interop.gate import ELECTION, make_manifest, signed_bundle


def credential_material():
    def public():
        key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        return {"spki": __import__('base64').urlsafe_b64encode(key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).rstrip(b'=').decode()}
    from backend.crypto.credential_protocol import b64decode
    manifest = make_manifest(public(), public())
    authority = ed25519.Ed25519PrivateKey.generate()
    bundle = signed_bundle(manifest, authority)
    raw = canonical_manifest(manifest)
    policy = CredentialPolicy(raw, b64decode(bundle["signature"]), hashlib.sha256(raw).digest(),
        manifest["ra_key"]["key_id"], b64decode(manifest["ra_key"]["spki"]),
        bytes.fromhex(manifest["ra_key"]["fingerprint"]))
    pinned = authority.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return policy, pinned


class MemoryCredentialStore:
    def __init__(self, policy, token):
        self.public_policy = policy
        self.election = __import__('uuid').UUID(ELECTION)
        self.voter = uuid4()
        self.session_digest = DemoSessionService._digest(token)
        self.active = self.eligible = self.session_valid = self.enabled = True
        self.now = datetime(2026,11,14,12,tzinfo=timezone.utc)
        self.expiry = datetime(2026,11,16,tzinfo=timezone.utc)
        self.records = {}
        self.completed = {}
        self.events = []
        self.lock = threading.RLock()
        self.fail_reservation_response = False
        self.fail_before_commit = False
        self.fail_after_commit = False

    def _session(self, digest):
        if digest != self.session_digest or not self.session_valid or not self.active:
            raise InvalidRASession()

    def policy(self, digest, election):
        self._session(digest)
        if election != self.election:
            raise CredentialUnavailable()
        return self.public_policy

    def _context(self, params, create):
        digest, election, request, blinded_hash, config_hash = params
        self._session(digest)
        if not self.eligible:
            raise CredentialDenied()
        key = (self.voter, election)
        previous = self.records.get(key)
        if previous is None:
            if key in self.completed or not create:
                raise CredentialConflict()
            if not self.enabled:
                raise CredentialDenied()
            previous = CredentialContext(uuid4(), self.voter, election, request, blinded_hash,
                self.public_policy.key_id, config_hash, self.now, self.expiry, None, None, None, None)
            self.records[key] = previous
        if previous.request_id != request or previous.blinded_hash != blinded_hash or previous.config_hash != config_hash:
            raise CredentialConflict()
        if self.now >= previous.recovery_expires_at:
            raise CredentialExpired()
        return self.completed.get(key, previous)

    def reserve(self, *params):
        with self.lock:
            value = self._context(params, True)
            self.events.append("reservation committed")
            if self.fail_reservation_response:
                raise CredentialUnavailable()
            return value

    @contextmanager
    def locked(self, *params):
        with self.lock:
            context = self._context(params, False)
            staged = []

            def complete(ciphertext, nonce, storage_key_id):
                self.events.append("completion staged")
                value = replace(context, issuance_id=uuid4(), ciphertext=ciphertext,
                                nonce=nonce, storage_key_id=storage_key_id)
                staged.append(value)
                return value

            yield SimpleNamespace(context=context, complete=complete)
            if self.fail_before_commit:
                raise CredentialUnavailable()
            if staged:
                self.completed[(self.voter, params[1])] = staged[-1]
            self.events.append("completion committed")
            if self.fail_after_commit:
                raise CredentialUnavailable()


def credential_environment(material):
    policy, pinned = material
    token = secrets.token_urlsafe(32)
    store = MemoryCredentialStore(policy, token)
    signature = secrets.token_bytes(384)
    signer = Mock()
    signer.matches.return_value = True

    def sign(value):
        assert store.events[-1] == "reservation committed"
        store.events.append("signed original bytes")
        return signature
    signer.sign.side_effect = sign
    recovery = CredentialRecovery({"test-recovery": secrets.token_bytes(32)}, "test-recovery")
    service = CredentialIssuanceService(store, signer, recovery, pinned)
    return SimpleNamespace(service=service, store=store, signer=signer, recovery=recovery,
                           token=token, signature=signature, blinded=b"\x01"*384, request=uuid4())
