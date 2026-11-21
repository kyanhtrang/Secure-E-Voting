"""Ephemeral signed publication fixtures, never production UI data."""
from types import SimpleNamespace
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
import rfc8785
from backend.board.verification import Trust, from_input, publication_manifest
from backend.crypto.credential_protocol import b64encode
from backend.tally.verification import EvidenceVault, build_snapshot, count, artifact
from tests.tally_helpers import material,ballot,stored


def evidence(directory):
    value=material()
    snapshot_key,pub_key=ed25519.Ed25519PrivateKey.generate(),ed25519.Ed25519PrivateKey.generate()
    pin=lambda k:k.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
    trust=Trust(value.pin,pin(snapshot_key),'test-evidence',pin(pub_key),'test-publication')
    vault=EvidenceVault(directory,snapshot_key,trust.evidence,trust.evidence_key_id)
    ballots=[ballot(value),ballot(value,candidate=value.manifest['candidates'][1]['candidate_id']),ballot(value,invalid='aead')]
    raw=build_snapshot([stored(value,p) for p in ballots],value.manifest['election_id'],value.config,value.pin)
    sealed=vault.seal(raw);report=count(artifact(raw),value.config,value.pin,lambda _:value.tally)
    encoded,sig=vault.sign_report(report)
    import hashlib
    source={'config':value.config,'snapshot':sealed,'records':None,
        'report':{'bytes_hex':encoded.hex(),'digest':hashlib.sha256(encoded).hexdigest(),'signature_hex':sig.hex()}}
    bundle=from_input(source,value.manifest['election_id'])
    pub=publication_manifest(bundle,trust)
    bundle['publication']={'manifest':pub,'signature':b64encode(pub_key.sign(b'EVOTE-RESULTS-v1\0'+rfc8785.dumps(pub)))}
    return SimpleNamespace(value=value,trust=trust,source=source,bundle=bundle,pub_key=pub_key,snapshot_key=snapshot_key,election=value.manifest['election_id'],directory=directory)
