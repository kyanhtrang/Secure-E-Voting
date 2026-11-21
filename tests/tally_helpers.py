"""Ephemeral verifier fixtures, not an RFC BlindSign implementation.

Finalized PSS signatures exercise the unchanged verifier. Real RA/CIRCL issuance
remains covered by the separate interoperability and Admin-to-Voter gates.
"""
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import uuid4

import rfc8785
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from backend.crypto.credential_protocol import DOMAIN, PROFILE, MANIFEST_CONTEXT, b64decode, b64encode, canonical_manifest, canonical_message
from backend.tally.verification import FrozenPolicy
from backend.voting.ballot_service import BallotService, ElectionPolicy


def material():
    ra = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    tally = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    authority = ed25519.Ed25519PrivateKey.generate()
    pin = authority.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    def public(key, name):
        raw = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        return {"key_id": name, "spki": b64encode(raw), "fingerprint": hashlib.sha256(raw).hexdigest()}
    now = datetime.now(timezone.utc).replace(microsecond=0)
    manifest = {"domain": "secure-evoting-election-manifest-v1", "version": 1, "profile": PROFILE,
        "election_id": str(uuid4()), "opens_at": (now-timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "closes_at": (now+timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "candidates": sorted([{"candidate_id": str(uuid4()), "candidate_name": "Synthetic Tally " + name} for name in ("A", "B")], key=lambda c: c["candidate_id"]),
        "ra_key": public(ra, "tally-test-ra-" + uuid4().hex), "tally_key": public(tally, "tally-test-key-" + uuid4().hex)}
    raw = canonical_manifest(manifest); signature = authority.sign(MANIFEST_CONTEXT + raw)
    fingerprint = hashlib.sha256(authority.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).digest()
    policy = ElectionPolicy(raw, signature, hashlib.sha256(raw).digest(), fingerprint,
        datetime.fromisoformat(manifest["opens_at"]), datetime.fromisoformat(manifest["closes_at"]))
    config = {"manifest_hex": raw.hex(), "signature_hex": signature.hex(), "authority_fingerprint": fingerprint.hex(),
        "config_hash": policy.config_digest.hex(), "opens_at": manifest["opens_at"], "closes_at": manifest["closes_at"]}
    return SimpleNamespace(ra=ra, tally=tally, manifest=manifest, pin=pin, policy=policy, config=config)


def ballot(value, candidate=None, invalid=None):
    election = value.manifest["election_id"]
    serial, aes, nonce = secrets.token_bytes(32), secrets.token_bytes(32), secrets.token_bytes(12)
    aad = rfc8785.dumps({"schema_version": 1, "election_id": election, "serial": b64encode(serial)})
    plain = {"schema_version": 1, "election_id": election, "candidate_id": candidate or value.manifest["candidates"][0]["candidate_id"]}
    if invalid == "candidate": plain["candidate_id"] = str(uuid4())
    if invalid == "schema": plain["extra"] = "rejected"
    cipher = AESGCM(aes).encrypt(nonce, rfc8785.dumps(plain), aad)
    if invalid == "aead": cipher = bytes([cipher[0] ^ 1]) + cipher[1:]
    wrapped = value.tally.public_key().encrypt(aes, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    if invalid == "wrap": wrapped = bytes(384)
    envelope = {"schema_version": 1, "key_id": value.manifest["tally_key"]["key_id"], "cipher_algorithm": "AES-256-GCM",
        "key_wrap_algorithm": "RSA-OAEP-SHA256", "nonce": b64encode(nonce), "ciphertext": b64encode(cipher), "encrypted_key": b64encode(wrapped)}
    message = {"domain": DOMAIN, "version": 2, "election_id": election, "serial": b64encode(serial),
        "config_hash": value.config["config_hash"], "envelope_hash": hashlib.sha256(rfc8785.dumps(envelope)).hexdigest(), "key_id": value.manifest["ra_key"]["key_id"]}
    prepared = secrets.token_bytes(32) + canonical_message(message)
    sig = value.ra.sign(prepared, padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=48), hashes.SHA384())
    return {"election_id": election, "envelope": envelope, "credential": {"message": message, "prepared_msg": b64encode(prepared), "signature": b64encode(sig)}}


def stored(value, payload):
    verified = BallotService(FrozenPolicy(value.policy), value.pin).verify(payload)
    return {"serial_hex": verified.serial.hex(), "envelope_hex": verified.envelope.hex(),
        "envelope_hash": hashlib.sha256(verified.envelope).hexdigest(), "prepared_hex": verified.prepared_msg.hex(),
        "signature_hex": verified.signature.hex(), "receipt_hash": verified.receipt_hash.hex()}
