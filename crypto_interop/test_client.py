"""Real TypeScript client checks. These do not assert Go interoperability."""

import copy
import hashlib
import os
import shutil

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from backend.crypto.credential_protocol import b64decode, b64encode, canonical_manifest, canonical_message
from crypto_interop.gate import ELECTION, ENVELOPE_HASH, ROOT, Peer, hex_bytes, load_vector, signed_bundle
from crypto_interop.test_protocol import authority, manifest


@pytest.fixture(scope="module")
def client():
    node = os.environ.get("EVOTE_TEST_NODE") or shutil.which("node")
    if not node:
        pytest.fail("Node >=24 required for the executable TypeScript tests; no silent skip")
    peer = Peer([node, str(ROOT / "crypto_interop/dist/client.js")], "TypeScript client")
    try:
        yield peer
    finally:
        peer.close()


def test_official_rfc_client_and_python_using_published_blind_signature(client):
    vector = load_vector(os.environ.get("EVOTE_TEST_RFC_VECTOR"))
    modulus = int.from_bytes(hex_bytes(vector["n"]), "big")
    exponent = int.from_bytes(hex_bytes(vector["e"]), "big")
    inverse = int.from_bytes(hex_bytes(vector["inv"]), "big")
    public = rsa.RSAPublicNumbers(exponent, modulus).public_key()
    spki = b64encode(public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))
    start = client.call({"op": "rfc_prepare", "spki": spki, "msg": b64encode(hex_bytes(vector["msg"])),
                         "prefix": b64encode(hex_bytes(vector["msg_prefix"])),
                         "salt": b64encode(hex_bytes(vector["salt"])),
                         "random_blind": b64encode(pow(inverse, -1, modulus).to_bytes(512, "big")),
                         "expected_inverse": b64encode(hex_bytes(vector["inv"]))})
    assert b64decode(start["prepared_msg"]) == hex_bytes(vector["input_msg"])
    assert b64decode(start["blinded_msg"]) == hex_bytes(vector["blinded_msg"])
    final = client.call({"op": "finalize", "handle": start["handle"],
                         "blind_sig": b64encode(hex_bytes(vector["blind_sig"]))})
    assert b64decode(final["signature"]) == hex_bytes(vector["sig"])
    public.verify(b64decode(final["signature"]), b64decode(final["prepared_msg"]),
                  padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=48), hashes.SHA384())


def test_client_manifest_validation_and_fresh_blinding(client, manifest, authority):
    private, pinned = authority
    bundle = signed_bundle(manifest, private)
    request = {"op": "prepare", "bundle": bundle, "pinned_root": b64encode(pinned),
               "expected_election": ELECTION, "envelope_hash": ENVELOPE_HASH}
    first = client.call(request)
    second = client.call(request)
    for result in (first, second):
        assert len(b64decode(result["blinded_msg"])) == 384
        assert b64decode(result["canonical_msg"]) == canonical_message(result["message"])
        assert b64decode(result["prepared_msg"])[32:] == canonical_message(result["message"])
        assert result["message"]["config_hash"] == hashlib.sha256(canonical_manifest(manifest)).hexdigest()
    assert first["message"]["serial"] != second["message"]["serial"]
    assert first["blinded_msg"] != second["blinded_msg"]
    bad = copy.deepcopy(request)
    bad["bundle"]["manifest"]["candidates"][0]["candidate_name"] = "Modified"
    client.call(bad, error=True)
    from cryptography.hazmat.primitives.asymmetric import ed25519
    bad = {**request, "bundle": signed_bundle(manifest, ed25519.Ed25519PrivateKey.generate())}
    client.call(bad, error=True)


def test_client_checks_serialization_and_noncanonical_input(client):
    import json
    for case in json.loads((ROOT / "crypto_interop/vectors/credential-v2.json").read_text()):
        actual = client.call({"op": "canonicalize", "message": case["message"]})
        assert b64decode(actual["canonical_msg"]) == case["canonical_utf8"].encode()
        malformed = {**case["message"], "serial": "A"*42+"B"}
        client.call({"op": "canonicalize", "message": malformed}, error=True)


@pytest.mark.parametrize("field", ["election_id", "key_id", "envelope_hash", "config_hash"])
def test_cross_language_rejects_trailing_line_terminators(client, field):
    import json
    from backend.crypto.credential_protocol import ProtocolError
    case = json.loads((ROOT / "crypto_interop/vectors/credential-v2.json").read_text())[0]
    altered = {**case["message"], field: case["message"][field]+"\n"}
    client.call({"op": "canonicalize", "message": altered}, error=True)
    with pytest.raises(ProtocolError):
        canonical_message(altered)
