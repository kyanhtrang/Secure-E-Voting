"""Frozen credential v2. Public verification only; no signing or database IO."""

import base64
import hashlib
import hmac
import json
import re
import unicodedata
from datetime import datetime
from uuid import UUID

import rfc8785
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa


PROFILE = "RSABSSA-SHA384-PSS-Randomized"
DOMAIN = "secure-evoting-blind-credential-v2"
MANIFEST_DOMAIN = "secure-evoting-election-manifest-v1"
MANIFEST_CONTEXT = b"EVOTE-MANIFEST-v1\x00"
MESSAGE_FIELDS = {"domain", "version", "election_id", "serial", "envelope_hash", "config_hash", "key_id"}
MANIFEST_FIELDS = {"domain", "version", "election_id", "opens_at", "closes_at", "candidates", "ra_key", "tally_key", "profile"}


class ProtocolError(ValueError):
    """Sanitized error; never include input or underlying exception text."""


def require(condition):
    if not condition:
        raise ProtocolError("Invalid cryptographic protocol input")


def exact_fields(value, fields):
    require(type(value) is dict and set(value) == fields)


def b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def b64decode(value, length=None):
    require(type(value) is str and 0 < len(value) <= 12000
            and re.fullmatch(r"[A-Za-z0-9_-]+", value) is not None)
    try:
        raw = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except (ValueError, TypeError):
        raise ProtocolError("Invalid cryptographic protocol input") from None
    require(b64encode(raw) == value and (length is None or len(raw) == length))
    return raw


def uuid_string(value):
    require(type(value) is str)
    try:
        require(str(UUID(value)) == value)
    except (ValueError, AttributeError):
        raise ProtocolError("Invalid cryptographic protocol input") from None


def key_id(value):
    require(type(value) is str and re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,127}", value) is not None)


def hex_hash(value):
    require(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None)


def canonical_message(message):
    exact_fields(message, MESSAGE_FIELDS)
    require(message["domain"] == DOMAIN and type(message["version"]) is int and message["version"] == 2)
    uuid_string(message["election_id"])
    b64decode(message["serial"], 32)
    hex_hash(message["envelope_hash"])
    hex_hash(message["config_hash"])
    key_id(message["key_id"])
    return rfc8785.dumps(message)


def public_rsa(spki):
    der = b64decode(spki)
    try:
        public = serialization.load_der_public_key(der)
        require(isinstance(public, rsa.RSAPublicKey) and public.key_size == 3072
                and public.public_numbers().e == 65537)
        require(public.public_bytes(serialization.Encoding.DER,
                                    serialization.PublicFormat.SubjectPublicKeyInfo) == der)
        return public
    except (ValueError, TypeError, UnsupportedAlgorithm):
        raise ProtocolError("Invalid cryptographic protocol input") from None


def canonical_manifest(manifest):
    exact_fields(manifest, MANIFEST_FIELDS)
    require(manifest["domain"] == MANIFEST_DOMAIN and type(manifest["version"]) is int
            and manifest["version"] == 1 and manifest["profile"] == PROFILE)
    uuid_string(manifest["election_id"])
    times = []
    for field in ("opens_at", "closes_at"):
        value = manifest[field]
        require(type(value) is str and re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value) is not None)
        try:
            times.append(datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ"))
        except ValueError:
            raise ProtocolError("Invalid cryptographic protocol input") from None
    require(times[0] < times[1])
    candidates = manifest["candidates"]
    require(type(candidates) is list and 1 <= len(candidates) <= 1000)
    ids = []
    for candidate in candidates:
        exact_fields(candidate, {"candidate_id", "candidate_name"})
        uuid_string(candidate["candidate_id"])
        ids.append(candidate["candidate_id"])
        name = candidate["candidate_name"]
        require(type(name) is str and 0 < len(name) <= 128 and name == name.strip()
                and unicodedata.normalize("NFC", name) == name
                and not any(ord(c) < 32 or 127 <= ord(c) <= 159 or 0xD800 <= ord(c) <= 0xDFFF for c in name))
    require(ids == sorted(set(ids)))
    fingerprints = []
    for field in ("ra_key", "tally_key"):
        key = manifest[field]
        exact_fields(key, {"key_id", "spki", "fingerprint"})
        key_id(key["key_id"])
        public_rsa(key["spki"])
        expected = hashlib.sha256(b64decode(key["spki"])).hexdigest()
        require(key["fingerprint"] == expected)
        fingerprints.append(expected)
    require(fingerprints[0] != fingerprints[1])
    return rfc8785.dumps(manifest)


def verify_manifest(bundle, pinned_authority: bytes, expected_election_id: str):
    exact_fields(bundle, {"manifest", "signature"})
    uuid_string(expected_election_id)
    encoded = canonical_manifest(bundle["manifest"])
    require(type(pinned_authority) is bytes and len(pinned_authority) == 32)
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(pinned_authority).verify(
            b64decode(bundle["signature"], 64), MANIFEST_CONTEXT + encoded
        )
    except (InvalidSignature, ValueError):
        raise ProtocolError("Invalid cryptographic protocol input") from None
    require(bundle["manifest"]["election_id"] == expected_election_id)
    return bundle["manifest"], hashlib.sha256(encoded).hexdigest()


def verify_credential(proof, bundle, pinned_authority, expected_election_id, expected_envelope_hash):
    exact_fields(proof, {"message", "prepared_msg", "signature"})
    manifest, config_hash = verify_manifest(bundle, pinned_authority, expected_election_id)
    encoded = canonical_message(proof["message"])
    expected = {
        **proof["message"], "election_id": expected_election_id,
        "envelope_hash": expected_envelope_hash, "config_hash": config_hash,
        "key_id": manifest["ra_key"]["key_id"],
    }
    require(hmac.compare_digest(encoded, canonical_message(expected)))
    prepared = b64decode(proof["prepared_msg"])
    require(len(prepared) == 32 + len(encoded) and hmac.compare_digest(prepared[32:], encoded))
    try:
        public_rsa(manifest["ra_key"]["spki"]).verify(
            b64decode(proof["signature"], 384), prepared,
            padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=48), hashes.SHA384(),
        )
    except (InvalidSignature, ValueError):
        raise ProtocolError("Invalid cryptographic protocol input") from None
    return proof["message"]


def strict_json(raw: bytes):
    require(type(raw) is bytes and len(raw) <= 131072)

    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result)
            result[key] = value
        return result

    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=unique,
                          parse_constant=lambda _: require(False))
    except (ValueError, UnicodeError, RecursionError):
        raise ProtocolError("Invalid cryptographic protocol input") from None
