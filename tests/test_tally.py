"""Database-free Tally correctness/privacy and fault injection. Not PostgreSQL evidence."""
import copy
import hashlib
from contextlib import contextmanager
from pathlib import Path
import threading
from unittest.mock import Mock
from uuid import uuid4

from alembic.config import Config
from alembic.script import ScriptDirectory
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from fastapi.testclient import TestClient
import pytest

from backend.tally.http import create_tally_app
from backend.tally.launcher import EncryptedTallyKey
from backend.tally.runtime import TallyAuthentication, TallyService, token_digest
from backend.tally.verification import TallyError, EvidenceVault, build_snapshot, artifact, count
from tests.tally_helpers import material, ballot, stored


@pytest.fixture(scope="module")
def value(): return material()


@pytest.fixture
def vault(tmp_path):
    key = ed25519.Ed25519PrivateKey.generate()
    pin = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return EvidenceVault(tmp_path, key, pin, "test-snapshot-authority")


def test_real_decryption_counts_identical_choices_and_all_invalid_classes(value, vault):
    rows = [stored(value, ballot(value)) for _ in range(2)]
    rows += [stored(value, ballot(value, candidate=value.manifest["candidates"][1]["candidate_id"]))]
    rows += [stored(value, ballot(value, invalid=reason)) for reason in ("aead", "wrap", "candidate", "schema")]
    raw = build_snapshot(rows, value.manifest["election_id"], value.config, value.pin)
    sealed = vault.seal(raw)
    snapshot = vault.verify(sealed, value.manifest["election_id"], value.config["config_hash"])
    result = count(snapshot, value.config, value.pin, lambda _: value.tally)
    assert result["accepted_total"] == 7 and result["valid_total"] == result["counted_total"] == 3
    assert result["invalid_total"] == 4 and result["invalid_reasons"] == {"AEAD": 1, "KEY_WRAP": 1, "PLAINTEXT": 2}
    assert [c["vote_count"] for c in result["candidate_counts"]] == [2, 1]
    assert build_snapshot(list(reversed(rows)), value.manifest["election_id"], value.config, value.pin) == raw
    assert vault.seal(raw) == sealed


@pytest.mark.parametrize("field", ["envelope_hash", "receipt_hash", "signature_hex", "serial_hex", "prepared_hex"])
def test_storage_or_credential_inconsistency_aborts_before_key(value, field):
    row = stored(value, ballot(value))
    row[field] = "00" * (384 if field == "signature_hex" else 32)
    with pytest.raises(TallyError) as error: build_snapshot([row], value.manifest["election_id"], value.config, value.pin)
    assert error.value.code == "INTEGRITY"


def test_duplicate_or_modified_configuration_rejected(value):
    row = stored(value, ballot(value))
    with pytest.raises(TallyError): build_snapshot([row, row], value.manifest["election_id"], value.config, value.pin)
    for field in ("config_hash", "signature_hex", "authority_fingerprint"):
        config = dict(value.config); config[field] = "00" * (64 if field == "signature_hex" else 32)
        with pytest.raises(TallyError): build_snapshot([], value.manifest["election_id"], config, value.pin)


def test_missing_or_wrong_key_is_whole_election_failure(value):
    snapshot = artifact(build_snapshot([stored(value, ballot(value))], value.manifest["election_id"], value.config, value.pin))
    for loader in (Mock(side_effect=FileNotFoundError("secret path")), Mock(return_value=rsa.generate_private_key(public_exponent=65537, key_size=3072))):
        with pytest.raises(TallyError) as error: count(snapshot, value.config, value.pin, loader)
        assert error.value.code == "KEY_UNAVAILABLE" and "secret" not in str(error.value)


def test_private_evidence_signature_and_replacement_fail_closed(value, vault):
    raw = build_snapshot([], value.manifest["election_id"], value.config, value.pin)
    sealed = vault.seal(raw)
    changed = dict(sealed, signature_hex="00" * 64)
    with pytest.raises(TallyError): vault.verify(changed, value.manifest["election_id"], value.config["config_hash"])
    target = vault.directory / (sealed["digest"] + ".json")
    target.write_bytes(b"{}")
    with pytest.raises(TallyError): vault.verify(sealed, value.manifest["election_id"], value.config["config_hash"])
    with pytest.raises(TallyError): vault.seal(raw)


def test_encrypted_key_load_is_real_and_identifier_bound(value, tmp_path):
    from pydantic import SecretStr
    path = tmp_path / "test.pem"
    path.write_bytes(value.tally.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.BestAvailableEncryption(b"synthetic-key-unlock")))
    loader = EncryptedTallyKey(path, SecretStr("synthetic-key-unlock"), value.manifest["tally_key"]["key_id"])
    assert loader(value.manifest["tally_key"]).private_numbers() == value.tally.private_numbers()
    with pytest.raises(ValueError): loader(dict(value.manifest["tally_key"], key_id="wrong-key"))


class MemoryTallyStore:
    """Explicit committed-phase model; real SQL lease/locking tests are separate."""
    def __init__(self, value, rows):
        self.value = {"config": value.config, "records": rows, "snapshot": None, "report": None}
        self.operator, self.sessions, self.lock = uuid4(), {}, threading.RLock()
        self.active = self.completed = self.fail_complete = self.lose_commit = False
        self.fence = 0; self.job = None; self.failures = []; self.phases = []
    def call(self, name, *args):
        if not self.lock.acquire(blocking=False): raise TallyError(409, "CONFLICT")
        try:
            if name == "login": self.sessions[args[1]] = True; return {"operator_id": str(self.operator), "role": "TALLY_OPERATOR"}
            if not self.sessions.get(args[0]): raise TallyError(401, "AUTHENTICATION")
            if name == "session": return {"operator_id": str(self.operator), "role": "TALLY_OPERATOR"}
            if name == "logout": self.sessions[args[0]] = False; return
            if name == "view":
                if not self.completed: raise TallyError(404)
                return copy.deepcopy(self.value)
            if name == "claim":
                if self.active: raise TallyError(409, "CONFLICT")
                if not self.completed: self.job = str(uuid4()); self.fence += 1; self.active = True
                return {"job_id": self.job, "fence": self.fence, "completed": self.completed}
            if name == "fail":
                if self.completed: raise TallyError(409)
                self.active = False; self.failures.append(args[-1]); return
            if name == "list": return []
            raise AssertionError("Unknown model operation")
        finally: self.lock.release()
    @contextmanager
    def transaction(self, digest, election, claim):
        with self.lock:
            before = copy.deepcopy(self.value)
            store = self
            class Transaction:
                value = copy.deepcopy(store.value)
                def seal(self, sealed):
                    store.value["snapshot"] = sealed; store.value["records"] = None; store.phases.append("snapshot")
                def complete(self, raw, sig):
                    if store.fail_complete: raise TallyError()
                    store.value["report"] = {"bytes_hex": raw.hex(), "signature_hex": sig.hex(), "digest": hashlib.sha256(raw).hexdigest()}
                    store.completed = True; store.active = False; store.phases.append("report")
            try: yield Transaction()
            except Exception:
                self.value = before; raise
            else:
                if self.completed and self.lose_commit:
                    self.lose_commit = False; raise TallyError()  # COMMIT happened, acknowledgement lost.


def service_for(value, vault, rows):
    store = MemoryTallyStore(value, rows)
    salt = bytes(16); password = "synthetic-operator"
    auth = TallyAuthentication(store, store.operator, "synthetic", salt, hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32))
    token = auth.limited.login("synthetic", password)
    loader = Mock(return_value=value.tally)
    return TallyService(auth, store, value.pin, vault, loader), token, store, loader


def test_durable_snapshot_precedes_key_load_and_idempotent_report(value, vault):
    service, token, store, loader = service_for(value, vault, [stored(value, ballot(value))])
    loader.side_effect = lambda _: value.tally if store.phases == ["snapshot"] else pytest.fail("key loaded too early")
    first = service.run(token, __import__('uuid').UUID(value.manifest["election_id"]))
    second = service.run(token, __import__('uuid').UUID(value.manifest["election_id"]))
    assert first == second and first["report"]["valid_total"] == 1
    assert store.phases == ["snapshot", "report"] and loader.call_count == 1
    assert not {"serial", "ballots", "envelope", "voter_id"} & set(first)


def test_rollback_and_committed_response_loss_recovery(value, vault):
    service, token, store, loader = service_for(value, vault, [stored(value, ballot(value))])
    election = __import__('uuid').UUID(value.manifest["election_id"])
    store.fail_complete = True
    with pytest.raises(TallyError): service.run(token, election)
    assert not store.completed and store.value["snapshot"] and store.value["report"] is None and store.failures == ["UNAVAILABLE"]
    store.fail_complete = False; store.lose_commit = True
    with pytest.raises(TallyError): service.run(token, election)
    assert store.completed
    result = service.report(token, election)
    loader.reset_mock()
    assert service.run(token, election) == result
    loader.assert_not_called()


def test_concurrent_execution_refused_in_model(value, vault):
    service, token, store, loader = service_for(value, vault, [stored(value, ballot(value))])
    entered, release = threading.Event(), threading.Event()
    loader.side_effect = lambda _: (entered.set(), release.wait(5), value.tally)[-1]
    errors = []
    def worker():
        try: service.run(token, __import__('uuid').UUID(value.manifest["election_id"]))
        except Exception as error: errors.append(error)
    thread = threading.Thread(target=worker); thread.start()
    try:
        assert entered.wait(5)
        with pytest.raises(TallyError) as error: service.run(token, __import__('uuid').UUID(value.manifest["election_id"]))
        assert error.value.status == 409
    finally: release.set(); thread.join(5)
    assert not errors and store.completed


@pytest.mark.parametrize("token", ["", "A" * 43, "adm1." + "A" * 43, "tly1." + "B" * 43, "tly1." + "A" * 43 + "="])
def test_admin_voter_and_noncanonical_tokens_rejected(token):
    with pytest.raises(TallyError) as error: token_digest(token)
    assert error.value.status == 401


def test_http_security_disabled_defaults_and_secret_errors(value, vault):
    service, token, store, _ = service_for(value, vault, [])
    with TestClient(create_tally_app(service), base_url="http://127.0.0.1", client=("127.0.0.1", 1)) as client:
        assert client.get("/api/v1/tally/elections", headers={"Authorization": "Bearer " + "A" * 43}).status_code == 401
        reply = client.post("/api/v1/tally/auth/login", json={"username": "SECRET_CANARY", "password": "SECRET_CANARY", "extra": True})
        assert reply.status_code == 422 and "SECRET_CANARY" not in reply.text and reply.headers["cache-control"] == "no-store"
        assert client.get("/api/v1/tally/auth/me", headers={"Authorization": "Bearer " + token}).json()["role"] == "TALLY_OPERATOR"
        store.sessions[token_digest(token)] = False
        assert client.get("/api/v1/tally/auth/me", headers={"Authorization": "Bearer " + token}).status_code == 401
    with TestClient(create_tally_app(), base_url="http://127.0.0.1", client=("127.0.0.1", 1)) as client:
        assert client.get("/api/v1/tally/elections").status_code == 503
    from backend.main import app
    assert not any(getattr(route, "path", "").startswith("/api/v1/tally") for route in app.routes)


def test_forward_migration_reuses_baseline_tables_and_preserves_old_heads():
    root = Path(__file__).resolve().parents[1]
    graph = ScriptDirectory.from_config(Config(str(root / "alembic_tally.ini")))
    assert graph.get_heads() == ["e6a90c72b541"] and graph.get_revision("e6a90c72b541").down_revision == "af821c9e7601"
    source = Path(graph.get_revision("e6a90c72b541").path).read_text(encoding="utf8")
    for text in ("SECURITY DEFINER", "SET search_path=pg_catalog", "REVOKE ALL ON ALL FUNCTIONS", "FOR UPDATE NOWAIT", "lease_until>clock_timestamp()", "fencing_token IS DISTINCT FROM", "ELSE false END"):
        assert text in source
    assert "CREATE ROLE" not in source and "GRANT SELECT" not in source
    assert "CREATE TABLE voting.tally_jobs" not in source and "CREATE TABLE voting.tally_reports" not in source
    assert ScriptDirectory.from_config(Config(str(root / "alembic_admin_voting.ini"))).get_heads() == ["af821c9e7601"]
