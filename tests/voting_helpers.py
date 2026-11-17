"""Ephemeral TEST keys and final-signature fixtures; never an RA blind signer.

PSS signing here generates verifier test inputs only. RFC BlindSign remains CIRCL
and is covered by the unchanged cross-language gate. No fixture keys touch disk.
"""

import hashlib
import secrets
import threading
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import uuid4

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa

from backend.crypto.credential_protocol import (
    DOMAIN, MANIFEST_CONTEXT, MANIFEST_DOMAIN, PROFILE, b64encode,
    canonical_manifest, canonical_message,
)
from backend.voting.ballot_service import (
    AlreadySpent, ElectionClosed, ElectionPolicy, ReceiptNotFound, VotingUnavailable,
)


def material(*, opens_offset=-3600, closes_offset=3600):
    ra = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    tally = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    authority = ed25519.Ed25519PrivateKey.generate()
    pin = authority.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    def key(private, key_id):
        raw = private.public_key().public_bytes(serialization.Encoding.DER,
                                              serialization.PublicFormat.SubjectPublicKeyInfo)
        return {"key_id": key_id, "spki": b64encode(raw), "fingerprint": hashlib.sha256(raw).hexdigest()}

    now = datetime.now(timezone.utc).replace(microsecond=0)
    manifest = {"domain": MANIFEST_DOMAIN, "version": 1, "election_id": str(uuid4()),
        "opens_at": (now+timedelta(seconds=opens_offset)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "closes_at": (now+timedelta(seconds=closes_offset)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "candidates": [{"candidate_id": str(uuid4()), "candidate_name": "Ephemeral fixture"}],
        "ra_key": key(ra, "test-ra"), "tally_key": key(tally, "test-tally"), "profile": PROFILE}
    raw = canonical_manifest(manifest)
    policy = ElectionPolicy(raw, authority.sign(MANIFEST_CONTEXT+raw), hashlib.sha256(raw).digest(),
        hashlib.sha256(authority.public_key().public_bytes(serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo)).digest(),
        now+timedelta(seconds=opens_offset), now+timedelta(seconds=closes_offset))
    return SimpleNamespace(ra=ra, tally=tally, pin=pin, manifest=manifest, policy=policy)


def payload_for(value, *, salt_length=48, prefix_length=32):
    serial = secrets.token_bytes(32)
    # This is a real AEAD/OAEP envelope; its choice validity remains Tally's job.
    import rfc8785
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    aes = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)
    election = value.manifest["election_id"]
    aad = rfc8785.dumps({"schema_version": 1, "election_id": election, "serial": b64encode(serial)})
    plaintext = rfc8785.dumps({"schema_version": 1, "election_id": election,
                             "candidate_id": value.manifest["candidates"][0]["candidate_id"]})
    envelope = {"schema_version": 1, "key_id": value.manifest["tally_key"]["key_id"],
                "cipher_algorithm": "AES-256-GCM", "key_wrap_algorithm": "RSA-OAEP-SHA256",
                "nonce": b64encode(nonce), "ciphertext": b64encode(AESGCM(aes).encrypt(nonce, plaintext, aad)),
                "encrypted_key": b64encode(value.tally.public_key().encrypt(aes,
                    padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)))}
    message = {"domain": DOMAIN, "version": 2, "election_id": election, "serial": b64encode(serial),
               "envelope_hash": hashlib.sha256(rfc8785.dumps(envelope)).hexdigest(),
               "config_hash": value.policy.config_digest.hex(), "key_id": value.manifest["ra_key"]["key_id"]}
    prepared = secrets.token_bytes(prefix_length)+canonical_message(message)
    signature = value.ra.sign(prepared, padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=salt_length), hashes.SHA384())
    return {"election_id": election, "envelope": envelope,
            "credential": {"message": message, "prepared_msg": b64encode(prepared), "signature": b64encode(signature)}}


class MemoryBallotStore:
    """Locking transactional double, not PostgreSQL concurrency evidence."""
    def __init__(self, value):
        self.policy_value = value.policy
        self.election = value.manifest["election_id"]
        self.rows = {}
        self.lock = threading.RLock()
        self.open = True
        self.fail_commit = self.lose_response = False
        self.calls = []

    def policy(self, election):
        self.calls.append("policy")
        if election != self.election:
            raise VotingUnavailable()
        return self.policy_value

    def accept(self, ballot):
        with self.lock:
            self.calls.append("accept")
            if ballot.serial in self.rows:
                raise AlreadySpent()
            if not self.open:
                raise ElectionClosed()
            if self.fail_commit:
                raise VotingUnavailable()
            self.rows[ballot.serial] = ballot
            if self.lose_response:
                raise VotingUnavailable()
            return ballot.receipt_hash

    def receipt(self, ballot):
        self.calls.append("receipt")
        previous = self.rows.get(ballot.serial)
        if previous != ballot:
            raise ReceiptNotFound()
        return previous.receipt_hash
