"""Pure protocol checks; generated test keys remain in memory."""

import copy
import hashlib
import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

from backend.crypto.credential_protocol import (
    DOMAIN, MANIFEST_CONTEXT, ProtocolError, b64decode, b64encode,
    canonical_manifest, canonical_message, strict_json, verify_credential, verify_manifest,
)
from crypto_interop.gate import ELECTION, ENVELOPE_HASH, ROOT, make_manifest, signed_bundle


@pytest.fixture(scope="module")
def authority():
    private = ed25519.Ed25519PrivateKey.generate()
    pinned = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return private, pinned


@pytest.fixture(scope="module")
def manifest():
    def public():
        key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        return {"spki": b64encode(key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))}
    return make_manifest(public(), public())


@pytest.fixture
def message(manifest):
    return {"domain": DOMAIN, "version": 2, "election_id": ELECTION, "serial": b64encode(bytes(range(32))),
            "envelope_hash": ENVELOPE_HASH, "config_hash": hashlib.sha256(canonical_manifest(manifest)).hexdigest(),
            "key_id": manifest["ra_key"]["key_id"]}


def test_frozen_serialization_vectors():
    for case in json.loads((ROOT / "crypto_interop/vectors/credential-v2.json").read_text()):
        assert canonical_message(case["message"]) == case["canonical_utf8"].encode("utf-8")


@pytest.mark.parametrize("key,value", [
    ("version", 1), ("version", True), ("domain", "secure-evoting-ballot-v1"),
    ("election_id", ELECTION.upper()), ("election_id", ELECTION.replace("-", "")),
    ("serial", "A"*42+"B"), ("serial", "A"*43+"="),
    ("envelope_hash", "A"*64), ("config_hash", "b"*63),
    ("key_id", "../secret"), ("voter_id", "IDENTITY_SECRET"),
])
def test_message_rejects_invalid_or_unexpected_fields(message, key, value):
    # ELECTION contains digits only; use a valid alphabetic UUID to test case.
    if key == "election_id" and value == ELECTION.upper():
        value = "ABCDEFAB-1111-4111-8111-111111111111"
    message[key] = value
    with pytest.raises(ProtocolError) as caught:
        canonical_message(message)
    assert "IDENTITY_SECRET" not in str(caught.value)


@pytest.mark.parametrize("raw", [b'{"version":2,"version":2}', b'{"secret":"PASSWORD_CANARY"', b'NaN', b'\xff'])
def test_json_errors_never_echo_input(raw):
    with pytest.raises(ProtocolError) as caught:
        strict_json(raw)
    assert "PASSWORD_CANARY" not in str(caught.value)


@pytest.mark.parametrize("raw", ["", "abc=", "A"*42+"B", "A"*43+"=", " A"*22, None])
def test_rejects_noncanonical_binary(raw):
    with pytest.raises(ProtocolError):
        b64decode(raw, 32)


def test_manifest_is_bound_to_independent_authority_and_election(manifest, authority):
    private, pinned = authority
    bundle = signed_bundle(manifest, private)
    _, config_hash = verify_manifest(bundle, pinned, ELECTION)
    assert config_hash == hashlib.sha256(canonical_manifest(manifest)).hexdigest()
    with pytest.raises(ProtocolError):
        verify_manifest(bundle, pinned, "33333333-3333-4333-8333-333333333333")
    other = ed25519.Ed25519PrivateKey.generate()
    with pytest.raises(ProtocolError):
        verify_manifest(signed_bundle(manifest, other), pinned, ELECTION)
    altered = copy.deepcopy(bundle)
    altered["manifest"]["candidates"][0]["candidate_name"] = "Modified"
    with pytest.raises(ProtocolError):
        verify_manifest(altered, pinned, ELECTION)
    bundle["pinned_root"] = b64encode(pinned)
    with pytest.raises(ProtocolError):
        verify_manifest(bundle, pinned, ELECTION)


@pytest.mark.parametrize("change", ["same-key", "wrong-fingerprint", "extra-field", "unsorted-candidates", "bad-time"])
def test_manifest_is_strict(manifest, change):
    value = copy.deepcopy(manifest)
    if change == "same-key":
        value["tally_key"] = value["ra_key"]
    elif change == "wrong-fingerprint":
        value["ra_key"]["fingerprint"] = "0"*64
    elif change == "extra-field":
        value["username"] = "SECRET"
    elif change == "unsorted-candidates":
        value["candidates"] *= 2
    else:
        value["opens_at"] = "2026-02-30T00:00:00Z"
    with pytest.raises(ProtocolError):
        canonical_manifest(value)


@pytest.mark.parametrize("prefix_length", [0, 31, 33])
def test_prepared_message_requires_exact_prefix(message, manifest, authority, prefix_length):
    private, pinned = authority
    proof = {"message": message, "prepared_msg": b64encode(bytes(prefix_length)+canonical_message(message)),
             "signature": b64encode(bytes(384))}
    with pytest.raises(ProtocolError):
        verify_credential(proof, signed_bundle(manifest, private), pinned, ELECTION, ENVELOPE_HASH)


def test_random_bytes_are_not_a_credential(message, manifest, authority):
    private, pinned = authority
    proof = {"message": message, "prepared_msg": b64encode(bytes(32)+canonical_message(message)),
             "signature": b64encode(bytes(384))}
    with pytest.raises(ProtocolError):
        verify_credential(proof, signed_bundle(manifest, private), pinned, ELECTION, ENVELOPE_HASH)


def test_manifest_signature_has_separate_domain(manifest, authority):
    private, pinned = authority
    correct = signed_bundle(manifest, private)
    correct["signature"] = b64encode(private.sign(canonical_manifest(manifest)))
    with pytest.raises(ProtocolError):
        verify_manifest(correct, pinned, ELECTION)
    assert MANIFEST_CONTEXT != DOMAIN.encode()
