"""Anonymous acceptance. Only public verification material crosses this boundary."""

import hashlib
import hmac
from dataclasses import dataclass
from datetime import datetime

import rfc8785
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from backend.crypto.credential_protocol import (
    b64decode, b64encode, canonical_manifest, canonical_message, exact_fields, require,
    strict_json, uuid_string, verify_credential, verify_manifest,
)


class VotingUnavailable(Exception):
    pass


class ElectionClosed(Exception):
    pass


class AlreadySpent(Exception):
    pass


class ReceiptNotFound(Exception):
    pass


@dataclass(frozen=True, repr=False)
class ElectionPolicy:
    manifest_bytes: bytes
    signature: bytes
    config_digest: bytes
    authority_fingerprint: bytes
    opens_at: datetime
    closes_at: datetime


@dataclass(frozen=True, repr=False)
class VerifiedBallot:
    election_id: str
    config_digest: bytes
    serial: bytes
    envelope: bytes
    prepared_msg: bytes
    signature: bytes
    receipt_hash: bytes


ENVELOPE_FIELDS = {"schema_version", "key_id", "cipher_algorithm", "key_wrap_algorithm",
                   "nonce", "ciphertext", "encrypted_key"}


def canonical_envelope(envelope, manifest):
    exact_fields(envelope, ENVELOPE_FIELDS)
    require(type(envelope["schema_version"]) is int and envelope["schema_version"] == 1)
    require(envelope["key_id"] == manifest["tally_key"]["key_id"])
    require(envelope["cipher_algorithm"] == "AES-256-GCM"
            and envelope["key_wrap_algorithm"] == "RSA-OAEP-SHA256")
    b64decode(envelope["nonce"], 12)
    b64decode(envelope["encrypted_key"], 384)
    # A local-demo bound, stricter than the baseline's 65536-byte storage limit.
    # The GCM tag is 16 bytes; at least one ciphertext byte is required.
    require(17 <= len(b64decode(envelope["ciphertext"])) <= 8192)
    raw = rfc8785.dumps(envelope)
    require(len(raw) <= 16384)
    return raw


def receipt_digest(election_id, proof, envelope_hash):
    """Document 08's existing EVOTE-RECEIPT-v1 construction, unchanged."""
    receipt = {"election_id": election_id, "serial": proof["message"]["serial"],
               "envelope_hash": envelope_hash, "prepared_msg": proof["prepared_msg"],
               "signature": proof["signature"]}
    return hashlib.sha256(b"EVOTE-RECEIPT-v1\x00" + rfc8785.dumps(receipt)).digest()


class BallotService:
    def __init__(self, store, authority_pin: bytes):
        require(type(authority_pin) is bytes and len(authority_pin) == 32)
        self._store, self._pin = store, authority_pin

    def verify(self, payload):
        exact_fields(payload, {"election_id", "credential", "envelope"})
        election = payload["election_id"]
        uuid_string(election)
        # Validate the credential shape before any database access.
        proof = payload["credential"]
        exact_fields(proof, {"message", "prepared_msg", "signature"})
        encoded = canonical_message(proof["message"])
        prepared, signature = b64decode(proof["prepared_msg"]), b64decode(proof["signature"], 384)
        require(len(prepared) == 32 + len(encoded) and hmac.compare_digest(prepared[32:], encoded))
        policy = self._store.policy(election)
        try:
            bundle = {"manifest": strict_json(policy.manifest_bytes),
                      "signature": b64encode(policy.signature)}
            manifest, config_hash = verify_manifest(bundle, self._pin, election)
            require(canonical_manifest(manifest) == policy.manifest_bytes)
            require(hmac.compare_digest(bytes.fromhex(config_hash), policy.config_digest))
            authority_der = ed25519.Ed25519PublicKey.from_public_bytes(self._pin).public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
            require(hmac.compare_digest(hashlib.sha256(authority_der).digest(), policy.authority_fingerprint))
            for field in ("opens_at", "closes_at"):
                require(datetime.fromisoformat(manifest[field].replace("Z", "+00:00")) == getattr(policy, field))
        except (ValueError, TypeError, AttributeError):
            raise VotingUnavailable() from None
        envelope = canonical_envelope(payload["envelope"], manifest)
        envelope_hash = hashlib.sha256(envelope).hexdigest()
        message = verify_credential(proof, bundle, self._pin, election, envelope_hash)
        return VerifiedBallot(election, policy.config_digest, b64decode(message["serial"], 32),
                              envelope, prepared, signature, receipt_digest(election, proof, envelope_hash))

    def submit(self, payload):
        ballot = self.verify(payload)
        receipt = self._store.accept(ballot)
        if not hmac.compare_digest(receipt, ballot.receipt_hash):
            raise VotingUnavailable()
        return receipt.hex()

    def recover(self, payload):
        ballot = self.verify(payload)
        receipt = self._store.receipt(ballot)
        if not hmac.compare_digest(receipt, ballot.receipt_hash):
            raise VotingUnavailable()
        return receipt.hex()
