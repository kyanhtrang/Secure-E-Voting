"""Database-free contracts and saga fault injection; not PostgreSQL evidence."""
import copy
import hashlib
from contextlib import contextmanager
from pathlib import Path
from threading import Lock
from types import SimpleNamespace
from unittest.mock import Mock
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from alembic.config import Config
from alembic.script import ScriptDirectory

from backend.admin.auth import AdminAuthentication, token_digest
from backend.admin.launcher import connections, load_verifier
from backend.admin.router import create_admin_app, validate
from backend.admin.service import AdminService, ManifestAuthority
from backend.admin.store import AdminError, VotingAdminStore
from backend.crypto.credential_protocol import canonical_manifest, verify_manifest, b64encode
from tests.credential_helpers import credential_material

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def material():
    policy, _ = credential_material()
    import json
    return json.loads(policy.manifest_bytes)


class MemoryVoting:
    """Per-operation commits model response loss. SQL locking is tested in CI."""
    def __init__(self, manifest, events):
        self.row = dict(election_id=manifest["election_id"], title="Synthetic election", status="DRAFT", phase="DRAFT",
            opens_at=manifest["opens_at"], closes_at=manifest["closes_at"], candidates=manifest["candidates"],
            revision=1, ra_ready=False, keyset_id=None, config_hash=None, manifest_hex=None, signature_hex=None)
        self.events, self.lock = events, Lock()
    @contextmanager
    def operation(self, *_):
        if not self.lock.acquire(blocking=False): raise AdminError(409)
        try: yield self
        finally: self.lock.release()
    def read(self): return copy.deepcopy(self.row)
    def mutate(self, command, data):
        row = self.row
        if command == "reserve":
            if data["revision"] != row["revision"] or row["phase"] != "DRAFT": raise AdminError(409)
            row.update(phase="FINALIZING", manifest_hex=data["manifest_hex"], keyset_id=data["keyset_id"], config_hash=hashlib.sha256(bytes.fromhex(data["manifest_hex"])).hexdigest())
        elif command == "freeze": row.update(phase="FROZEN", signature_hex=data["signature_hex"])
        elif command == "open":
            if row["phase"] not in ("FROZEN", "OPEN"): raise AdminError(409)
            row.update(status="OPEN", phase="OPEN")
        elif command == "close":
            if row["phase"] not in ("OPEN", "CLOSED"): raise AdminError(409)
            row.update(status="CLOSED", phase="CLOSED", ra_ready=False)
        elif command == "ack": row["ra_ready"] = True
        elif command == "edit":
            if row["phase"] != "DRAFT": raise AdminError(409)
            row.update(data)
        self.events.append(command)
        return self.read()


@pytest.fixture
def system(material):
    key = ed25519.Ed25519PrivateKey.generate()
    pin = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    events = []
    voting = MemoryVoting(material, events)
    actor = str(uuid4())
    auth = Mock(); auth.identity.return_value = {"admin_id": actor, "role": "ELECTION_ADMIN"}
    publisher = Mock()
    publisher.prepare.side_effect = lambda e, raw, *_: events.append("prepare_ra") or {"config_hash": hashlib.sha256(raw).hexdigest()}
    def reconcile(e, h, closed, actor):
        events.append("reconcile_ra")
        return {"config_hash": h.hex(), "enabled": not closed, "closed": closed}
    publisher.reconcile.side_effect = reconcile
    catalogue = {"test-keyset": {"ra_key": material["ra_key"], "tally_key": material["tally_key"], "private_key_reference": "opaque-test-reference"}}
    service = AdminService(auth, voting, publisher, ManifestAuthority(key, pin), catalogue)
    return SimpleNamespace(service=service, voting=voting, publisher=publisher, events=events,
        token="adm1." + b64encode(bytes(32)), election=__import__('uuid').UUID(material["election_id"]))


def test_sign_freeze_before_publish_and_independent_pin(system):
    s = system
    result = s.service.finalize(s.token, s.election, 1, "test-keyset")
    assert s.events == ["reserve", "freeze", "prepare_ra"]
    manifest, digest = verify_manifest(result["bundle"], s.service.authority.pin, str(s.election))
    assert digest == result["config_hash"]
    assert canonical_manifest(manifest).hex() == s.voting.row["manifest_hex"]
    assert "private_key_reference" not in str(result)
    with pytest.raises(ValueError): verify_manifest(result["bundle"], bytes(32), str(s.election))


def test_crash_after_reservation_locks_configuration_and_exact_retry(system):
    s = system; original = s.service.authority.sign
    s.service.authority.sign = Mock(side_effect=RuntimeError("synthetic internal failure"))
    with pytest.raises(RuntimeError): s.service.finalize(s.token, s.election, 1, "test-keyset")
    assert s.voting.row["phase"] == "FINALIZING"
    with pytest.raises(AdminError): s.voting.mutate("edit", {"title": "replacement"})
    with pytest.raises(AdminError): s.service.finalize(s.token, s.election, 1, "other")
    s.service.authority.sign = original
    assert s.service.finalize(s.token, s.election, 1, "test-keyset")["phase"] == "FROZEN"
    assert s.events.count("reserve") == 1


def test_ra_failure_after_freeze_can_reconcile_without_new_signature(system):
    s = system; original = s.publisher.prepare.side_effect
    s.publisher.prepare.side_effect = AdminError(503)
    with pytest.raises(AdminError): s.service.finalize(s.token, s.election, 1, "test-keyset")
    signature = s.voting.row["signature_hex"]
    s.publisher.prepare.side_effect = original
    s.service.finalize(s.token, s.election, 1, "test-keyset")
    assert s.voting.row["signature_hex"] == signature
    assert s.events.count("freeze") == 1


def test_open_close_partial_failures_are_recoverable_and_ordered(system):
    s = system; s.service.finalize(s.token, s.election, 1, "test-keyset")
    normal = s.publisher.reconcile.side_effect
    s.publisher.reconcile.side_effect = AdminError(503)
    with pytest.raises(AdminError): s.service.transition(s.token, s.election, False)
    assert s.voting.row["phase"] == "OPEN" and not s.voting.row["ra_ready"]
    s.publisher.reconcile.side_effect = normal
    assert s.service.transition(s.token, s.election, False)["ra_ready"]
    s.publisher.prepare.side_effect = AdminError(503)
    with pytest.raises(AdminError): s.service.transition(s.token, s.election, True)
    assert s.voting.row["status"] == "CLOSED" and not s.voting.row["ra_ready"]
    with pytest.raises(AdminError): s.service.transition(s.token, s.election, False)
    assert s.events.index("open") < s.events.index("reconcile_ra")


def test_concurrent_operation_denied(system):
    s = system
    with s.voting.operation():
        with pytest.raises(AdminError) as error: s.service.finalize(s.token, s.election, 1, "test-keyset")
        assert error.value.status == 409


@pytest.mark.parametrize("phase", ["DRAFT", "FINALIZING", "CLOSED"])
def test_invalid_opening_state_never_publishes_policy(system, phase):
    system.voting.row["phase"] = phase
    with pytest.raises(AdminError) as error: system.service.transition(system.token, system.election, False)
    assert error.value.status == 409
    system.publisher.prepare.assert_not_called()
    system.publisher.reconcile.assert_not_called()


def test_wrong_ra_hash_never_opens_voting(system):
    s = system
    s.service.finalize(s.token, s.election, 1, "test-keyset")
    s.publisher.prepare.side_effect = None
    s.publisher.prepare.return_value = {"config_hash": "0" * 64}
    with pytest.raises(AdminError) as error: s.service.transition(s.token, s.election, False)
    assert error.value.status == 503
    assert s.voting.row["status"] == "DRAFT"
    s.publisher.reconcile.assert_not_called()


@pytest.mark.parametrize("token", ["", "a" * 43, "adm1.a", "adm1." + "A" * 42 + "B", "adm1." + "A" * 43 + "="])
def test_voter_and_noncanonical_token_rejected_before_database(token):
    store = Mock(); auth = AdminAuthentication(store, uuid4(), "synthetic-admin", bytes(16), bytes(32))
    with pytest.raises(AdminError) as error: auth.identity(token)
    assert error.value.status == 401
    store.call.assert_not_called()


def test_login_me_logout_digest_and_role_validation():
    password = "synthetic-test-only"
    salt = bytes(16); digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    actor = uuid4(); store = Mock(); store.call.return_value = {"admin_id": str(actor), "role": "ELECTION_ADMIN"}
    auth = AdminAuthentication(store, actor, "synthetic-admin", salt, digest)
    token = auth.limited.login("synthetic-admin", password)
    auth.identity(token); auth.logout(token)
    assert all(call.args[-1] == token_digest(token) for call in store.call.call_args_list)
    store.call.return_value = {"admin_id": str(actor), "role": "VOTER"}
    with pytest.raises(AdminError): auth.identity(token)


def test_http_no_sensitive_errors_rate_limit_and_default_disabled():
    store = Mock(); auth = AdminAuthentication(store, uuid4(), "synthetic-admin", bytes(16), bytes(32))
    service = SimpleNamespace(auth=auth)
    with TestClient(create_admin_app(service), base_url="http://127.0.0.1", client=("127.0.0.1", 1234)) as client:
        bad = client.post("/api/v1/admin/auth/login", json={"username": "secret-name", "password": "secret-value", "extra": "secret"})
        assert bad.status_code == 422 and "secret" not in bad.text and bad.headers["Cache-Control"] == "no-store"
        for _ in range(5): assert client.post("/api/v1/admin/auth/login", json={"username": "x", "password": "x"}).status_code == 401
        assert client.post("/api/v1/admin/auth/login", json={"username": "x", "password": "x"}).status_code == 429
        assert client.get("/api/v1/admin/elections", headers={"Authorization": "Bearer " + "A" * 43}).status_code == 401
        assert client.get("/api/v1/admin/elections", headers={"Origin": "https://example.invalid"}).status_code == 403
    store.call.assert_not_called()
    with TestClient(create_admin_app(), base_url="http://127.0.0.1", client=("127.0.0.1", 1)) as client:
        assert client.get("/api/v1/admin/elections").status_code == 503
    from backend.main import app
    assert not any(getattr(route, "path", "").startswith("/api/v1/admin") for route in app.routes)


@pytest.mark.parametrize("data,fields", [({"revision": True}, ["revision"]), ({"candidate_name": "\u0001"}, ["candidate_name"]),
    ({"opens_at": "2026-01-01", "closes_at": "2026-02-01"}, ["opens_at", "closes_at"])])
def test_strict_administrative_inputs(data, fields):
    with pytest.raises(AdminError): validate(data, fields)


def test_runtime_never_accepts_privileged_or_selected_target():
    for database, role in [("ra_db", "postgres"), ("voting_db", "voting_owner"), ("other", "voting_admin_login")]:
        with pytest.raises(ValueError): connections(database, role, "synthetic-unused")


def test_verifier_requires_explicit_local_configuration(tmp_path):
    import json
    file = tmp_path / "synthetic.json"
    data = {"enabled": False, "environment": "local-demo", "admin_id": str(uuid4()), "username": "synthetic", "salt": b64encode(bytes(16)), "digest": b64encode(bytes(32))}
    file.write_text(json.dumps(data))
    with pytest.raises(ValueError): load_verifier(file)
    data["enabled"] = True; file.write_text(json.dumps(data))
    assert load_verifier(file) == data
    data["password"] = "unexpected"; file.write_text(json.dumps(data))
    with pytest.raises(ValueError): load_verifier(file)


def test_commit_precedes_response_and_rollback_is_sanitized():
    conn = Mock(); conn.execute.return_value.fetchone.return_value = ({"committed": True},)
    store = VotingAdminStore(Mock())
    assert store._call(conn, "session", bytes(32)) == {"committed": True}
    conn.commit.assert_called_once()
    conn.execute.side_effect = RuntimeError("sensitive internal data")
    with pytest.raises(AdminError) as error: store._call(conn, "session", bytes(32))
    assert "sensitive" not in str(error.value)
    conn.rollback.assert_called_once()


@pytest.mark.parametrize("name,head,baseline", [("ra", "bf932d0f8702", "c84e13b9702d"), ("voting", "af821c9e7601", "d8f27a4c610b")])
def test_new_migration_heads_and_security_contract(name, head, baseline):
    scripts = ScriptDirectory.from_config(Config(str(ROOT / f"alembic_admin_{name}.ini")))
    assert scripts.get_heads() == [head]
    revision = scripts.get_revision(head)
    assert revision.down_revision == baseline
    source = Path(revision.path).read_text(encoding="utf8")
    assert "SECURITY DEFINER" in source and "SET search_path=pg_catalog" in source
    assert "REVOKE ALL ON ALL FUNCTIONS" in source and "FROM PUBLIC" in source
    assert "THEN has_sequence_privilege" in source and "ELSE false END" in source
    assert "CREATE ROLE" not in source and "GRANT SELECT" not in source
    baseline_scripts = ScriptDirectory.from_config(Config(str(ROOT / f"alembic_{name}.ini")))
    assert baseline_scripts.get_heads() == [baseline]


def test_admin_ci_refuses_local_execution_before_any_database_or_container_call(monkeypatch):
    from scripts import admin_postgres_ci as ci
    connect = Mock(side_effect=AssertionError("Must not connect"))
    monkeypatch.setattr(ci.psycopg, "connect", connect)
    monkeypatch.setattr(ci.ra_ci.sys, "platform", "win32")
    with pytest.raises(SystemExit) as error: ci.main(["--allow-ephemeral-ci-databases"])
    assert error.value.code == 1
    connect.assert_not_called()


def test_missing_hash_cannot_bypass_sql_readiness_and_session_ttl_is_stable():
    source = (ROOT / "migrations/admin_voting/versions/af821c9e7601_admin_elections.py").read_text(encoding="utf8")
    assert "c.config_hash<>" not in source
    assert source.count("c.config_hash IS DISTINCT FROM decode(") == 3
    assert "DEFAULT statement_timestamp()+interval '15 minutes'" in source
    assert "keyset_id text UNIQUE" in source
    assert "FOR UPDATE" in source and "pg_try_advisory_xact_lock" in source


def test_catalogue_rejects_reused_or_tally_equivalent_ra_keys(system):
    s = system
    duplicate = dict(s.service.keysets)
    duplicate["alias"] = duplicate["test-keyset"]
    with pytest.raises(ValueError): AdminService(s.service.auth, s.voting, s.publisher, s.service.authority, duplicate)
    entry = copy.deepcopy(duplicate["alias"]); entry["tally_key"] = entry["ra_key"]
    with pytest.raises(ValueError): AdminService(s.service.auth, s.voting, s.publisher, s.service.authority, {"bad": entry})


def test_credential_echo_fallback_is_forbidden(monkeypatch):
    import getpass
    import warnings
    from backend.admin.launcher import prompt
    def fallback(*_): warnings.warn("Synthetic console unavailable", getpass.GetPassWarning)
    monkeypatch.setattr(getpass, "getpass", fallback)
    with pytest.raises(getpass.GetPassWarning): prompt("Synthetic test: ")


def test_http_management_contract_and_sanitized_database_failure():
    service = Mock()
    service.auth.identity.return_value = {"admin_id": str(uuid4()), "role": "ELECTION_ADMIN"}
    service.list.return_value = []
    service.create.return_value = {"status": "DRAFT"}
    token = "adm1." + b64encode(bytes(32))
    headers = {"Authorization": "Bearer " + token}
    with TestClient(create_admin_app(service), base_url="http://127.0.0.1", client=("127.0.0.1", 1)) as client:
        assert client.get("/api/v1/admin/elections", headers=headers).json() == {"elections": []}
        assert client.post("/api/v1/admin/elections", headers=headers, json={"title": "Synthetic", "opens_at": "2026-01-01T00:00:00Z", "closes_at": "2027-01-01T00:00:00Z"}).status_code == 201
        service.list.side_effect = RuntimeError("private internal detail")
        reply = client.get("/api/v1/admin/elections", headers=headers)
        assert reply.status_code == 503 and "private" not in reply.text and reply.headers["cache-control"] == "no-store"
        assert client.post("/api/v1/admin/auth/logout", headers=headers, json={}).status_code == 204
