"""Keyless, offline public evidence verification. No network, database or decryption."""
from dataclasses import dataclass
import hashlib
import re

import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from backend.crypto.credential_protocol import b64decode, b64encode, exact_fields, key_id, uuid_string, verify_manifest
from backend.tally.verification import artifact, FrozenPolicy, policy, verify_record
from backend.voting.ballot_service import BallotService

MAX_BYTES = 16 * 1024 * 1024
REPORT_FIELDS = {"report_version","election_id","election_config_digest","snapshot_digest","algorithm_version",
    "accepted_total","valid_total","invalid_total","counted_total","candidate_counts","invalid_reasons"}


class BoardError(Exception):
    def __init__(self, status=503, code="UNAVAILABLE"):
        self.status,self.code=status,code
        super().__init__("Published evidence unavailable")


def require(value):
    if not value: raise BoardError(503,"INVALID")


def digest(value): return hashlib.sha256(rfc8785.dumps(value)).hexdigest()


def receipt_hash(value):
    if type(value) is not str or re.fullmatch(r"[0-9a-f]{64}",value) is None: raise BoardError(422,"INVALID_REQUEST")
    return value


@dataclass(frozen=True)
class Trust:
    authority: bytes
    evidence: bytes
    evidence_key_id: str
    publication: bytes
    publication_key_id: str

    def validate(self):
        if any(type(p) is not bytes or len(p)!=32 for p in (self.authority,self.evidence,self.publication)):
            raise BoardError(503,"UNVERIFIED")
        if len({self.authority,self.evidence,self.publication}) != 3: raise BoardError(503,"UNVERIFIED")
        try: key_id(self.evidence_key_id);key_id(self.publication_key_id)
        except Exception: raise BoardError(503,"UNVERIFIED") from None


def signature(pin, context, value, encoded):
    Ed25519PublicKey.from_public_bytes(pin).verify(b64decode(encoded,64),context+rfc8785.dumps(value))


def publication_manifest(bundle, trust):
    report=bundle["tally"]["report"]
    return {"manifest_version":1,"election_id":bundle["election_id"],"election_config_digest":report["election_config_digest"],
        "snapshot_digest":report["snapshot_digest"],"tally_report_digest":bundle["tally"]["report_digest"],
        **{k:report[k] for k in ("accepted_total","valid_total","invalid_total","counted_total")},
        "publication_key_id":trust.publication_key_id,"signature_algorithm":"Ed25519"}


def verify(bundle, election, trust, *, published=True):
    if trust is None: raise BoardError(503,"UNVERIFIED")
    trust.validate()
    try:
        uuid_string(election)
        exact_fields(bundle,{"version","election_id","configuration","snapshot","snapshot_evidence","tally"} | ({"publication"} if published else set()))
        require(type(bundle["version"]) is int and bundle["version"]==1 and bundle["election_id"]==election)
        require(len(rfc8785.dumps(bundle))<=MAX_BYTES)
        manifest,config_hash=verify_manifest(bundle["configuration"],trust.authority,election)
        snapshot=bundle["snapshot"];exact_fields(snapshot,{"schema_version","election_id","election_config_digest","ballots"})
        require(type(snapshot["schema_version"]) is int and snapshot["schema_version"]==1
            and snapshot["election_id"]==election and snapshot["election_config_digest"]==config_hash)
        rows=snapshot["ballots"];require(type(rows) is list and len(rows)<=1000)
        receipts=[receipt_hash(r["receipt_hash"]) for r in rows]
        require(receipts==sorted(set(receipts)) and len({r["serial"] for r in rows})==len(rows))
        evidence=bundle["snapshot_evidence"];exact_fields(evidence,{"manifest","signature"})
        expected={"manifest_version":1,"election_id":election,"election_config_digest":config_hash,"snapshot_schema_version":1,
            "snapshot_digest":digest(snapshot),"ballot_count":len(rows),"digest_algorithm":"SHA-256",
            "signature_algorithm":"Ed25519","signing_key_id":trust.evidence_key_id}
        require(rfc8785.dumps(evidence["manifest"])==rfc8785.dumps(expected))
        signature(trust.evidence,b"EVOTE-SNAPSHOT-v1\0",expected,evidence["signature"])
        # Reuse the reviewed frozen policy, credential, encrypted envelope and receipt verifier.
        config={"manifest_hex":rfc8785.dumps(manifest).hex(),"signature_hex":b64decode(bundle["configuration"]["signature"],64).hex(),
            "config_hash":config_hash,"opens_at":manifest["opens_at"],"closes_at":manifest["closes_at"]}
        from cryptography.hazmat.primitives import serialization
        public=Ed25519PublicKey.from_public_bytes(trust.authority)
        config["authority_fingerprint"]=hashlib.sha256(public.public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()
        _,frozen=policy(config,trust.authority,election)
        verifier=BallotService(FrozenPolicy(frozen),trust.authority)
        for record in rows: verify_record(record,election,verifier)
        tally=bundle["tally"];exact_fields(tally,{"report","report_digest","signature","signing_key_id"})
        report=tally["report"];exact_fields(report,REPORT_FIELDS)
        require(tally["signing_key_id"]==trust.evidence_key_id and tally["report_digest"]==digest(report))
        signature(trust.evidence,b"EVOTE-TALLY-REPORT-v1\0",report,tally["signature"])
        require(type(report["report_version"]) is int and report["report_version"]==1 and report["algorithm_version"]=="evote-tally-v1")
        require(report["election_id"]==election and report["election_config_digest"]==config_hash
            and report["snapshot_digest"]==expected["snapshot_digest"])
        for name in ("accepted_total","valid_total","invalid_total","counted_total"):
            require(type(report[name]) is int and 0<=report[name]<=1000)
        require(report["accepted_total"]==len(rows)==report["valid_total"]+report["invalid_total"]
            and report["counted_total"]==report["valid_total"])
        counts=report["candidate_counts"];require(type(counts) is list and len(counts)==len(manifest["candidates"]))
        require([r["candidate_id"] for r in counts]==[c["candidate_id"] for c in manifest["candidates"]])
        for row in counts:
            exact_fields(row,{"candidate_id","vote_count"});require(type(row["vote_count"]) is int and row["vote_count"]>=0)
        reasons=report["invalid_reasons"];exact_fields(reasons,{"KEY_WRAP","AEAD","PLAINTEXT"})
        require(all(type(n) is int and n>=0 for n in reasons.values()) and sum(reasons.values())==report["invalid_total"]
            and sum(r["vote_count"] for r in counts)==report["counted_total"])
        if published:
            pub=bundle["publication"];exact_fields(pub,{"manifest","signature"})
            require(rfc8785.dumps(pub["manifest"])==rfc8785.dumps(publication_manifest(bundle,trust)))
            signature(trust.publication,b"EVOTE-RESULTS-v1\0",pub["manifest"],pub["signature"])
        return bundle
    except BoardError: raise
    except Exception: raise BoardError(503,"INVALID") from None


def decode(raw):
    try: return artifact(raw)
    except Exception: raise BoardError(503,"INVALID") from None


def receipt_status(bundle, election, receipt, trust):
    receipt_hash(receipt)
    verified=verify(bundle,election,trust)
    return "VERIFIED" if any(r["receipt_hash"]==receipt for r in verified["snapshot"]["ballots"]) else "NOT_FOUND"


def from_input(value, election):
    """Convert existing restricted Tally RPC bytes without changing any signed bytes."""
    config,snapshot,report=value["config"],value["snapshot"],value["report"]
    return {"version":1,"election_id":election,
        "configuration":{"manifest":decode(bytes.fromhex(config["manifest_hex"])),"signature":b64encode(bytes.fromhex(config["signature_hex"]))},
        "snapshot":decode(bytes.fromhex(snapshot["bytes_hex"])),
        "snapshot_evidence":{"manifest":decode(bytes.fromhex(snapshot["manifest_hex"])),"signature":b64encode(bytes.fromhex(snapshot["signature_hex"]))},
        "tally":{"report":decode(bytes.fromhex(report["bytes_hex"])),"report_digest":report["digest"],
            "signature":b64encode(bytes.fromhex(report["signature_hex"])),"signing_key_id":snapshot["key_id"]}}
