"""Executable TEST-ONLY TS -> CIRCL -> Python gate; no HTTP or database IO.

Run with an isolated Python environment and prebuilt client/signer; see README.
Published RFC private test components exist only in an external temp directory.
Generated private keys stay in memory and are never returned by the signer.
"""

import argparse
import copy
import gzip
import hashlib
import json
import queue
import subprocess
import sys
import tempfile
import threading
import urllib.request
from pathlib import Path

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from backend.crypto.credential_protocol import (
    DOMAIN, MANIFEST_CONTEXT, MANIFEST_DOMAIN, PROFILE, ProtocolError,
    b64decode, b64encode, canonical_manifest, canonical_message, strict_json,
    verify_credential, verify_manifest,
)

RFC_URL = "https://raw.githubusercontent.com/cloudflare/circl/v1.6.5/blindsign/blindrsa/testdata/test_vectors_rfc9474.json.gz"
RFC_SHA256 = "374ba388a53cd9017aecff92afd2174188c7d5c7e8f0947d8af466043f134ff7"
ELECTION = "11111111-1111-4111-8111-111111111111"
ENVELOPE_HASH = hashlib.sha256(b"synthetic encrypted envelope for the crypto gate").hexdigest()


class GateError(RuntimeError):
    """Only static, input-free diagnostic labels may be used here."""


def require(condition, label):
    if not condition:
        raise GateError(label)


def hex_bytes(value):
    value = value.removeprefix("0x")
    return bytes.fromhex(("0" if len(value) % 2 else "") + value)


class Peer:
    def __init__(self, command, name):
        self.name = name
        try:
            self.process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                            stderr=subprocess.DEVNULL)
        except OSError:
            raise GateError(name + " cannot execute; check toolchain and application-control policy") from None
        self.lines = queue.Queue()
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self):
        for line in self.process.stdout:
            self.lines.put(line)
        self.lines.put(None)

    def call(self, request, *, error=False):
        self.process.stdin.write(rfc8785.dumps(request) + b"\n")
        self.process.stdin.flush()
        try:
            line = self.lines.get(timeout=60)
        except queue.Empty:
            raise GateError(self.name + " timed out") from None
        require(line is not None, self.name + " stopped")
        response = strict_json(line)
        require(isinstance(response, dict), self.name + " invalid response")
        require(("error" in response) == error, self.name + " rejected an expected operation")
        if error:
            require(response["error"] in ("Invalid crypto test input", "Invalid crypto test request"),
                    self.name + " error was not sanitized")
        return response

    def close(self):
        self.process.stdin.close()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()
        self.process.stdout.close()


def load_vector(path=None):
    if path:
        compressed = Path(path).read_bytes()
    else:
        with urllib.request.urlopen(RFC_URL, timeout=30) as response:
            compressed = response.read(1_000_000)
    require(hashlib.sha256(compressed).hexdigest() == RFC_SHA256, "RFC fixture integrity failure")
    vectors = json.loads(gzip.decompress(compressed))
    return next(v for v in vectors if v["name"] == PROFILE)


def rejection(label, operation):
    try:
        operation()
    except (ProtocolError, InvalidSignature):
        print("PASS:", label)
        return
    raise GateError(label + " was accepted")


def signed_bundle(manifest, authority):
    return {"manifest": manifest,
            "signature": b64encode(authority.sign(MANIFEST_CONTEXT + canonical_manifest(manifest)))}


def make_manifest(ra, tally):
    def entry(key_id, public):
        return {"key_id": key_id, "spki": public["spki"],
                "fingerprint": hashlib.sha256(b64decode(public["spki"])).hexdigest()}
    return {
        "domain": MANIFEST_DOMAIN, "version": 1, "election_id": ELECTION,
        "opens_at": "2026-11-14T00:00:00Z", "closes_at": "2026-11-15T00:00:00Z",
        "candidates": [{"candidate_id": "22222222-2222-4222-8222-222222222222",
                        "candidate_name": "Ứng viên Café 🗳"}],
        "ra_key": entry("ra-demo-v2", ra), "tally_key": entry("tally-demo-v1", tally),
        "profile": PROFILE,
    }


def run(node, signer, vector_path=None):
    vector = load_vector(vector_path)
    with tempfile.TemporaryDirectory(prefix="evote-crypto-interop-") as scratch:
        # Only the public RFC's fixed, already-public test key is written.
        # No generated private key or local/production key is ever read/written.
        key_file = Path(scratch) / "published-rfc-test-key.json"
        key_file.write_text(json.dumps({k: vector[k] for k in ("n", "e", "d", "p", "q")}), encoding="utf-8")
        go = client = None
        try:
            go = Peer([str(signer), "--rfc-test-key", str(key_file)], "CIRCL signer")
            client = Peer([str(node), str(ROOT / "crypto_interop/dist/client.js")], "TypeScript client")
            execute(go, client, vector)
        finally:
            if client is not None:
                client.close()
            if go is not None:
                go.close()


def execute(go, client, vector):
    def public(key):
        return go.call({"op": "public", "key": key})

    def sign(key, blinded):
        result = go.call({"op": "sign", "key": key, "blinded_msg": blinded})
        raw = b64decode(blinded)
        require(result["input_length"] == len(raw), "Signer received wrong input length")
        require(result["input_hash"] == hashlib.sha256(raw).hexdigest(), "Original blinded bytes changed")
        return result["blind_sig"]

    # Official fixed-vector randomness only, never used for the generated test.
    rfc = public("rfc")
    require((rfc["bits"], rfc["exponent"]) == (4096, 65537), "RFC key size changed")
    inverse = int.from_bytes(hex_bytes(vector["inv"]), "big")
    modulus = int.from_bytes(hex_bytes(vector["n"]), "big")
    # Recover the RFC's public test-randomness value, not a signing algorithm.
    random_blind = pow(inverse, -1, modulus).to_bytes(512, "big")
    prepared = client.call({
        "op": "rfc_prepare", "spki": rfc["spki"], "msg": b64encode(hex_bytes(vector["msg"])),
        "prefix": b64encode(hex_bytes(vector["msg_prefix"])), "salt": b64encode(hex_bytes(vector["salt"])),
        "random_blind": b64encode(random_blind), "expected_inverse": b64encode(hex_bytes(vector["inv"])),
    })
    require(b64decode(prepared["prepared_msg"]) == hex_bytes(vector["input_msg"]), "RFC Prepare mismatch")
    require(b64decode(prepared["blinded_msg"]) == hex_bytes(vector["blinded_msg"]), "RFC Blind mismatch")
    blind_signature = sign("rfc", prepared["blinded_msg"])
    require(b64decode(blind_signature) == hex_bytes(vector["blind_sig"]), "RFC BlindSign mismatch")
    finalized = client.call({"op": "finalize", "handle": prepared["handle"], "blind_sig": blind_signature})
    require(b64decode(finalized["signature"]) == hex_bytes(vector["sig"]), "RFC Finalize mismatch")
    rfc_public = serialization.load_der_public_key(b64decode(rfc["spki"]))
    rfc_public.verify(b64decode(finalized["signature"]), b64decode(finalized["prepared_msg"]),
                      padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=48), hashes.SHA384())
    print("PASS: official RFC 9474 A.1 (4096-bit): TS Prepare/Blind -> CIRCL original bytes -> TS Finalize -> Python")

    for case in json.loads((ROOT / "crypto_interop/vectors/credential-v2.json").read_text(encoding="utf-8")):
        expected = case["canonical_utf8"].encode("utf-8")
        require(canonical_message(case["message"]) == expected, "Python serialization vector mismatch")
        actual = client.call({"op": "canonicalize", "message": case["message"]})
        require(b64decode(actual["canonical_msg"]) == expected, "TypeScript serialization vector mismatch")
    print("PASS: frozen v2 UTF-8/JCS serialization vectors agree across TypeScript and Python")

    ra, wrong = public("generated"), public("wrong")
    require((ra["bits"], ra["exponent"], wrong["bits"]) == (3072, 65537, 3072), "Generated test profile mismatch")
    authority = ed25519.Ed25519PrivateKey.generate()
    pinned = authority.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    manifest = make_manifest(ra, wrong)
    bundle = signed_bundle(manifest, authority)
    verify_manifest(bundle, pinned, ELECTION)
    manifest_result = client.call({"op": "verify_manifest", "bundle": bundle,
                                  "pinned_root": b64encode(pinned), "expected_election": ELECTION})
    require(manifest_result["config_hash"] == hashlib.sha256(canonical_manifest(manifest)).hexdigest(),
            "Unicode manifest canonicalization mismatch")
    print("PASS: independent Ed25519 manifest authority and Unicode manifest canonicalization")

    prepare_request = {"op": "prepare", "bundle": bundle, "pinned_root": b64encode(pinned),
                       "expected_election": ELECTION, "envelope_hash": ENVELOPE_HASH}

    def issue(request):
        start = client.call(request)
        expected = canonical_message(start["message"])
        require(b64decode(start["canonical_msg"]) == expected, "Client reconstructed message mismatch")
        require(b64decode(start["prepared_msg"])[32:] == expected, "Prepared message suffix mismatch")
        result = client.call({"op": "finalize", "handle": start["handle"],
                              "blind_sig": sign("generated", start["blinded_msg"])})
        return result

    proof = issue(prepare_request)

    def verify(value=proof, config=bundle):
        return verify_credential(value, config, pinned, ELECTION, ENVELOPE_HASH)

    verify()
    print("PASS: generated RSA-3072/e=65537 TEST key end-to-end; original blinded input is 384 bytes")
    again = issue(prepare_request)
    verify(again)
    require(proof["message"]["serial"] != again["message"]["serial"], "Client serial randomness reused")
    require(b64decode(proof["prepared_msg"])[:32] != b64decode(again["prepared_msg"])[:32], "Prepare prefix reused")
    print("PASS: generated client serials and Prepare prefixes are fresh")

    for field, value in {
        "election_id": "33333333-3333-4333-8333-333333333333",
        "serial": b64encode(bytes(32)), "envelope_hash": "c"*64,
        "config_hash": "d"*64, "key_id": "different-ra-key",
    }.items():
        altered = copy.deepcopy(proof)
        altered["message"][field] = value
        altered["prepared_msg"] = b64encode(b64decode(proof["prepared_msg"])[:32] + canonical_message(altered["message"]))
        rejection("modified " + field + " rejected", lambda: verify(altered))
    altered = copy.deepcopy(proof)
    signature = bytearray(b64decode(altered["signature"])); signature[-1] ^= 1
    altered["signature"] = b64encode(signature)
    rejection("modified signature rejected", lambda: verify(altered))
    wrong_public = serialization.load_der_public_key(b64decode(wrong["spki"]))
    rejection("wrong RSA verification key rejected", lambda: wrong_public.verify(
        b64decode(proof["signature"]), b64decode(proof["prepared_msg"]),
        padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=48), hashes.SHA384()))

    wrong_salt = issue({**prepare_request, "op": "prepare_wrong_salt"})
    # Prove the negative fixture is valid PSS with salt 0, rather than random corruption.
    rsa_public = serialization.load_der_public_key(b64decode(ra["spki"]))
    rsa_public.verify(b64decode(wrong_salt["signature"]), b64decode(wrong_salt["prepared_msg"]),
                      padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=0), hashes.SHA384())
    rejection("valid signature with wrong PSS salt length rejected by fixed 48-byte profile", lambda: verify(wrong_salt))
    for length in (31, 33):
        altered = copy.deepcopy(proof)
        prefix = b64decode(proof["prepared_msg"])[:32]
        malformed = prefix[:length] if length == 31 else prefix + b"\x00"
        altered["prepared_msg"] = b64encode(malformed + canonical_message(proof["message"]))
        rejection(f"{length}-byte prepared prefix rejected", lambda: verify(altered))
    altered = copy.deepcopy(proof); altered["signature"] += "="
    rejection("padded noncanonical signature rejected", lambda: verify(altered))
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    altered = copy.deepcopy(proof)
    serial = altered["message"]["serial"]
    altered["message"]["serial"] = serial[:-1] + alphabet[alphabet.index(serial[-1]) ^ 1]
    rejection("noncanonical serial pad bits rejected", lambda: verify(altered))
    client.call({"op": "canonicalize", "message": altered["message"]}, error=True)
    go.call({"op": "sign", "key": "generated", "blinded_msg": b64encode(bytes(32))}, error=True)
    print("PASS: SHA256-sized signing input rejected; no hash-to-BlindSign path")

    modified = copy.deepcopy(bundle); modified["manifest"]["candidates"][0]["candidate_name"] = "Changed"
    rejection("modified manifest rejected by Python", lambda: verify_manifest(modified, pinned, ELECTION))
    client.call({"op": "verify_manifest", "bundle": modified, "pinned_root": b64encode(pinned),
                 "expected_election": ELECTION}, error=True)
    other_authority = ed25519.Ed25519PrivateKey.generate()
    wrong_bundle = signed_bundle(manifest, other_authority)
    rejection("wrong manifest signing authority rejected by Python", lambda: verify_manifest(wrong_bundle, pinned, ELECTION))
    client.call({"op": "verify_manifest", "bundle": wrong_bundle, "pinned_root": b64encode(pinned),
                 "expected_election": ELECTION}, error=True)
    print("PASS: modified manifest and wrong signing authority also rejected by TypeScript")
    changed = copy.deepcopy(manifest); changed["candidates"][0]["candidate_name"] = "New authorized configuration"
    replacement = signed_bundle(changed, authority)
    rejection("credential cannot move to a differently signed configuration", lambda: verify(proof, replacement))
    identity = copy.deepcopy(proof); identity["message"]["voter_id"] = "IDENTITY_SECRET_CANARY"
    rejection("unexpected identity-bearing field rejected", lambda: verify(identity))
    print("PASS: RA signer transport carries only key selector and original blinded bytes")
    print("CRYPTO INTEROPERABILITY GATE: PASS (test-only; database/API implementation remains unverified)")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node", required=True, type=Path)
    parser.add_argument("--signer", required=True, type=Path)
    parser.add_argument("--rfc-vector-gzip", type=Path, help="Optional offline fixture, checked against pinned SHA256")
    args = parser.parse_args()
    run(args.node, args.signer, args.rfc_vector_gzip)


if __name__ == "__main__":
    try:
        main()
    except GateError as error:
        raise SystemExit("CRYPTO INTEROPERABILITY GATE: FAIL: " + str(error)) from None
    except Exception:
        raise SystemExit("CRYPTO INTEROPERABILITY GATE: FAIL (sensitive internal details suppressed)") from None
