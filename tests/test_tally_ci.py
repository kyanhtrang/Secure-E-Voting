"""Database-free safety checks for the hosted Tally coordinator."""
from pathlib import Path
from unittest.mock import Mock
import pytest
import yaml

from scripts import tally_postgres_ci as ci


def test_local_refusal_before_database_container_or_key_access(monkeypatch):
    monkeypatch.setattr(ci.sys, "platform", "win32")
    connect, docker, read = Mock(), Mock(), Mock()
    monkeypatch.setattr(ci.psycopg, "connect", connect)
    monkeypatch.setattr(ci.guard.real.vote_ci, "docker", docker)
    monkeypatch.setattr(Path, "read_bytes", read)
    with pytest.raises(SystemExit) as error: ci.main(["--allow-ephemeral-ci-database"])
    assert str(error.value) == "FAIL: tally_postgres_ci stage=preflight category=assertion sqlstate=unavailable"
    connect.assert_not_called(); docker.assert_not_called(); read.assert_not_called()


def test_new_workflow_has_no_secrets_or_artifacts_and_runs_regressions_first():
    text = (ci.ROOT / ".github/workflows/tally-verification.yml").read_text(encoding="utf8")
    value = yaml.safe_load(text)
    assert value.get("on", value.get(True)) == {"push": {"branches": ["feat/tally-verification"]}, "workflow_dispatch": None}
    assert value["permissions"] == {"contents": "read"}
    job = value["jobs"]["tally-postgres"]
    assert job["runs-on"] == "ubuntu-24.04"
    assert not any(step.get("continue-on-error") for step in job["steps"])
    assert "secrets." not in text and "upload-artifact" not in text
    scripts = [step.get("run", "") for step in job["steps"]]
    run = next(i for i, script in enumerate(scripts) if "scripts/tally_postgres_ci.py" in script)
    for expected in ("-m pytest", "npm test", "test:tally-browser"):
        assert any(expected in script for script in scripts[:run])


def test_provisioning_uses_only_guarded_disposable_migrations_and_existing_tables():
    source = (ci.ROOT / "scripts/tally_postgres_ci.py").read_text(encoding="utf8")
    assert "ephemeral_postgres()" in source and 'guard.discover("voting", target)' in source
    assert '"scripts/ci_voting_migrations"' in source and '"disposable_marker"' not in source  # Structured attributes instead of a connection URL.
    assert "disposable_marker=target.marker" in source and "disposable_database=target.database" in source
    assert "hide_parameters=True" in source
    assert "RA_DEMO_DB_PASSWORD" not in source and 'dbname="voting_db"' not in source
    assert "counted_total" in source and "LEASE_EXPIRED" not in source  # Recovery is enforced in the DB migration.


def test_public_keys_and_plaintext_never_appear_in_tally_http_contract():
    source = (ci.ROOT / "backend/tally/http.py").read_text(encoding="utf8")
    assert 'parts[2] == "run"' in source and 'parts[2] == "report"' in source
    assert "decrypt" not in source and "ballot_id" not in source and "voter_id" not in source
