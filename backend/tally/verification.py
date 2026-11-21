"""Private snapshot verification and aggregate-only tallying. Frozen wire formats reused."""
import hashlib
import hmac
import json
import os
from pathlib import Path
import tempfile
from datetime import datetime

import rfc8785
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from backend.crypto.credential_protocol import b64decode, b64encode, exact_fields, strict_json, verify_manifest
from backend.voting.ballot_service import BallotService, ElectionPolicy

ALGORITHM = "evote-tally-v1"
MAX_BALLOTS = 1000
MAX_ARTIFACT = 16 * 1024 * 1024
REASONS = ("KEY_WRAP", "AEAD", "PLAINTEXT")
SNAPSHOT_CONTEXT = b"EVOTE-SNAPSHOT-v1\0"


class TallyError(Exception):
    def __init__(self, status=503, code="UNAVAILABLE"):
        self.status, self.code = status, code
        super().__init__("Restricted tally unavailable")


def integrity(condition):
    if not condition: raise TallyError(503, "INTEGRITY")


def artifact(raw):
    try:
        integrity(type(raw) is bytes and len(raw) <= MAX_ARTIFACT)
        def pairs(values):
            result = {}
            for key, value in values:
                integrity(key not in result); result[key] = value
            return result
        value = json.loads(raw.decode("utf8"), object_pairs_hook=pairs,
            parse_constant=lambda _: integrity(False))
        integrity(rfc8785.dumps(value) == raw)
        return value
    except TallyError: raise
    except Exception: raise TallyError(503, "INTEGRITY") from None


def policy(config, pin, election):
    try:
        raw, signature = bytes.fromhex(config["manifest_hex"]), bytes.fromhex(config["signature_hex"])
        manifest, digest = verify_manifest({"manifest": strict_json(raw), "signature": b64encode(signature)}, pin, election)
        integrity(rfc8785.dumps(manifest) == raw and digest == config["config_hash"])
        authority_der = ed25519.Ed25519PublicKey.from_public_bytes(pin).public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        integrity(hashlib.sha256(authority_der).hexdigest() == config["authority_fingerprint"])
        integrity(all(datetime.fromisoformat(config[field]) == datetime.fromisoformat(manifest[field]) for field in ("opens_at", "closes_at")))
        result = ElectionPolicy(raw, signature, bytes.fromhex(digest), bytes.fromhex(config["authority_fingerprint"]),
            datetime.fromisoformat(config["opens_at"]), datetime.fromisoformat(config["closes_at"]))
        return manifest, result
    except TallyError: raise
    except Exception: raise TallyError(503, "INTEGRITY") from None


class FrozenPolicy:
    def __init__(self, value): self.value = value
    def policy(self, _election): return self.value


def verify_record(record, election, verifier):
    try:
        exact_fields(record, {"election_id", "serial", "envelope", "prepared_msg", "signature", "receipt_hash"})
        integrity(record["election_id"] == election)
        prepared = b64decode(record["prepared_msg"])
        integrity(len(prepared) > 32)
        message = strict_json(prepared[32:])
        proof = {"message": message, "prepared_msg": record["prepared_msg"], "signature": record["signature"]}
        verified = verifier.verify({"election_id": election, "envelope": record["envelope"], "credential": proof})
        integrity(hmac.compare_digest(verified.serial, b64decode(record["serial"], 32)))
        integrity(verified.receipt_hash.hex() == record["receipt_hash"])
        return message
    except TallyError: raise
    except Exception: raise TallyError(503, "INTEGRITY") from None


def build_snapshot(rows, election, config, pin):
    manifest, frozen = policy(config, pin, election)
    verifier = BallotService(FrozenPolicy(frozen), pin)
    records = []
    try:
        integrity(len(rows) <= MAX_BALLOTS)
        for row in rows:
            envelope = bytes.fromhex(row["envelope_hex"])
            parsed = strict_json(envelope)
            integrity(rfc8785.dumps(parsed) == envelope and hashlib.sha256(envelope).hexdigest() == row["envelope_hash"])
            record = {"election_id": election, "serial": b64encode(bytes.fromhex(row["serial_hex"])),
                "envelope": parsed, "prepared_msg": b64encode(bytes.fromhex(row["prepared_hex"])),
                "signature": b64encode(bytes.fromhex(row["signature_hex"])), "receipt_hash": row["receipt_hash"]}
            verify_record(record, election, verifier)
            records.append(record)
        records.sort(key=lambda value: value["receipt_hash"])
        integrity(len({r["serial"] for r in records}) == len(records) == len({r["receipt_hash"] for r in records}))
        return rfc8785.dumps({"schema_version": 1, "election_id": election,
            "election_config_digest": config["config_hash"], "ballots": records})
    except TallyError: raise
    except Exception: raise TallyError(503, "INTEGRITY") from None


class EvidenceVault:
    """Private, no-overwrite evidence separate from DB. No public artifact API."""
    def __init__(self, directory, authority, pin, key_id):
        self.directory = Path(directory)
        if not self.directory.is_dir() or self.directory.is_symlink(): raise ValueError("Private evidence directory required")
        if os.name != "nt" and self.directory.stat().st_mode & 0o077: raise ValueError("Private evidence permissions required")
        if not isinstance(authority, ed25519.Ed25519PrivateKey) or authority.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw) != pin: raise ValueError("Snapshot authority mismatch")
        from backend.crypto.credential_protocol import key_id as valid_key_id
        valid_key_id(key_id)
        self.authority, self.pin, self.key_id = authority, pin, key_id

    def seal(self, raw):
        value = artifact(raw); digest = hashlib.sha256(raw).hexdigest()
        manifest = {"manifest_version": 1, "election_id": value["election_id"],
            "election_config_digest": value["election_config_digest"], "snapshot_schema_version": 1,
            "snapshot_digest": digest, "ballot_count": len(value["ballots"]),
            "digest_algorithm": "SHA-256", "signature_algorithm": "Ed25519", "signing_key_id": self.key_id}
        encoded = rfc8785.dumps(manifest)
        signature = self.authority.sign(SNAPSHOT_CONTEXT + encoded)
        package = rfc8785.dumps({"snapshot": value, "manifest": manifest, "signature": b64encode(signature)})
        self._preserve(digest + ".json", package)
        return {"bytes_hex": raw.hex(), "manifest_hex": encoded.hex(), "signature_hex": signature.hex(),
            "digest": digest, "key_id": self.key_id}

    def _preserve(self, name, package):
        target = self.directory / name
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(dir=self.directory, prefix=".staging-", delete=False) as stream:
                temporary = Path(stream.name)
                os.chmod(temporary, 0o600)
                stream.write(package); stream.flush(); os.fsync(stream.fileno())
            try: os.link(temporary, target)  # Atomic create, never replace prior evidence.
            except FileExistsError: integrity(not target.is_symlink() and target.read_bytes() == package)
            if os.name != "nt":
                descriptor = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
                try: os.fsync(descriptor)
                finally: os.close(descriptor)
        finally:
            if temporary is not None: temporary.unlink(missing_ok=True)

    def sign_report(self, report):
        raw = rfc8785.dumps(report)
        signature = self.authority.sign(b"EVOTE-TALLY-REPORT-v1\0" + raw)
        self._preserve("report-" + report["snapshot_digest"] + ".json",
            rfc8785.dumps({"report": report, "signature": b64encode(signature)}))
        return raw, signature

    def verify_report(self, evidence, snapshot, config_hash):
        try:
            raw, sig = bytes.fromhex(evidence["bytes_hex"]), bytes.fromhex(evidence["signature_hex"])
            report = artifact(raw)
            integrity(hashlib.sha256(raw).hexdigest() == evidence["digest"])
            ed25519.Ed25519PublicKey.from_public_bytes(self.pin).verify(sig, b"EVOTE-TALLY-REPORT-v1\0" + raw)
            integrity(report["election_id"] == snapshot["election_id"] and report["election_config_digest"] == config_hash
                and report["snapshot_digest"] == hashlib.sha256(rfc8785.dumps(snapshot)).hexdigest()
                and report["accepted_total"] == len(snapshot["ballots"]))
            path = self.directory / ("report-" + report["snapshot_digest"] + ".json")
            integrity(not path.is_symlink() and path.read_bytes() == rfc8785.dumps({"report": report, "signature": b64encode(sig)}))
            return {"report": report, "report_digest": evidence["digest"], "signature": b64encode(sig), "signing_key_id": self.key_id}
        except TallyError: raise
        except Exception: raise TallyError(503, "INTEGRITY") from None

    def verify(self, sealed, election, config_hash):
        try:
            raw, encoded = bytes.fromhex(sealed["bytes_hex"]), bytes.fromhex(sealed["manifest_hex"])
            value, manifest = artifact(raw), artifact(encoded)
            integrity(len(value["ballots"]) <= MAX_BALLOTS)
            exact_fields(value, {"schema_version", "election_id", "election_config_digest", "ballots"})
            integrity(type(value["schema_version"]) is int and value["schema_version"] == 1)
            integrity(value["election_id"] == election and value["election_config_digest"] == config_hash)
            expected = {"manifest_version": 1, "election_id": election, "election_config_digest": config_hash,
                "snapshot_schema_version": 1, "snapshot_digest": hashlib.sha256(raw).hexdigest(),
                "ballot_count": len(value["ballots"]), "digest_algorithm": "SHA-256",
                "signature_algorithm": "Ed25519", "signing_key_id": self.key_id}
            integrity(encoded == rfc8785.dumps(expected) and sealed["digest"] == expected["snapshot_digest"] and sealed["key_id"] == self.key_id)
            signature = bytes.fromhex(sealed["signature_hex"])
            ed25519.Ed25519PublicKey.from_public_bytes(self.pin).verify(signature, SNAPSHOT_CONTEXT + encoded)
            target = self.directory / (expected["snapshot_digest"] + ".json")
            integrity(not target.is_symlink() and target.read_bytes() == rfc8785.dumps(
                {"snapshot": value, "manifest": manifest, "signature": b64encode(signature)}))
            return value
        except TallyError: raise
        except Exception: raise TallyError(503, "INTEGRITY") from None


def count(snapshot, config, pin, load_key):
    election = snapshot["election_id"]
    manifest, frozen = policy(config, pin, election)
    verifier = BallotService(FrozenPolicy(frozen), pin)
    rows = snapshot["ballots"]
    integrity(len(rows) <= MAX_BALLOTS)
    integrity([r["receipt_hash"] for r in rows] == sorted({r["receipt_hash"] for r in rows}))
    integrity(len({r["serial"] for r in rows}) == len(rows))
    # Verify every public record before opening any private RSA key.
    messages = [verify_record(row, election, verifier) for row in rows]
    try:
        private = load_key(manifest["tally_key"])
        integrity(isinstance(private, rsa.RSAPrivateKey) and private.key_size == 3072 and private.public_key().public_numbers().e == 65537)
        der = private.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        if b64encode(der) != manifest["tally_key"]["spki"] or hashlib.sha256(der).hexdigest() != manifest["tally_key"]["fingerprint"]:
            raise ValueError()
    except Exception: raise TallyError(503, "KEY_UNAVAILABLE") from None
    totals = {candidate["candidate_id"]: 0 for candidate in manifest["candidates"]}
    reasons = dict.fromkeys(REASONS, 0)
    for row, message in zip(rows, messages):
        envelope = row["envelope"]
        try:
            aes = private.decrypt(b64decode(envelope["encrypted_key"], 384),
                padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
            if len(aes) != 32: raise ValueError()
        except ValueError:
            reasons["KEY_WRAP"] += 1; continue
        aad = rfc8785.dumps({"schema_version": 1, "election_id": election, "serial": message["serial"]})
        try: plaintext = AESGCM(aes).decrypt(b64decode(envelope["nonce"], 12), b64decode(envelope["ciphertext"]), aad)
        except InvalidTag:
            reasons["AEAD"] += 1; continue
        finally: del aes
        try:
            ballot = strict_json(plaintext)
            exact_fields(ballot, {"schema_version", "election_id", "candidate_id"})
            if type(ballot["schema_version"]) is not int or ballot["schema_version"] != 1 or ballot["election_id"] != election or ballot["candidate_id"] not in totals or rfc8785.dumps(ballot) != plaintext:
                raise ValueError()
            totals[ballot["candidate_id"]] += 1
        except (ValueError, TypeError): reasons["PLAINTEXT"] += 1
        finally: del plaintext
    valid, invalid = sum(totals.values()), sum(reasons.values())
    integrity(valid + invalid == len(rows))
    return {"report_version": 1, "election_id": election, "election_config_digest": config["config_hash"],
        "snapshot_digest": hashlib.sha256(rfc8785.dumps(snapshot)).hexdigest(), "algorithm_version": ALGORITHM,
        "accepted_total": len(rows), "valid_total": valid, "invalid_total": invalid, "counted_total": valid,
        "candidate_counts": [{"candidate_id": key, "vote_count": totals[key]} for key in sorted(totals)], "invalid_reasons": reasons}
