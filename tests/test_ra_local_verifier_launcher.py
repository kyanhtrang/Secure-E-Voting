import getpass
import json
import sys
import warnings
from unittest.mock import patch

import pytest

from backend.ra.demo_auth_config import REQUIRED_KEYS
from backend.ra.demo_launcher import load_local_verifier, main
from tests.demo_auth_helpers import demo_environment


@pytest.fixture
def local_file(tmp_path):
    path = tmp_path / "Secure-E-Voting" / "ra-demo-auth.local.json"
    path.parent.mkdir()
    payload = demo_environment()
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path, payload, {"LOCALAPPDATA": str(tmp_path)}


def test_only_expected_verifier_fields_loaded(local_file):
    path, payload, environment = local_file
    payload.update({"RA_DEMO_DB_USER": "postgres", "password": "IGNORED_SECRET"})
    path.write_text(json.dumps(payload), encoding="utf-8")
    loaded = load_local_verifier(environment)
    assert set(loaded) == {*REQUIRED_KEYS, "RA_ENVIRONMENT", "RA_DEMO_AUTH_ENABLED"}
    assert loaded["RA_DEMO_SUBJECT"] == "demo-voter-001"
    assert "RA_DEMO_DB_PASSWORD" not in loaded
    assert "IGNORED_SECRET" not in repr(loaded)


@pytest.mark.parametrize("key,value", [
    ("RA_DEMO_AUTH_ENABLED", "false"), ("RA_ENVIRONMENT", "production"),
    ("RA_DEMO_SUBJECT", "wrong-subject"), ("RA_DEMO_PROVIDER", "wrong-provider"),
    ("RA_DEMO_USERNAME", None), ("RA_DEMO_SALT_HEX", "invalid"),
    ("RA_DEMO_DIGEST_HEX", "invalid"), ("RA_DEMO_AUTH_ENABLED", True),
])
def test_local_file_validation_fails_without_leaking_input(local_file, key, value):
    path, payload, environment = local_file
    payload[key] = value
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="^Local verifier configuration unavailable or invalid$"):
        load_local_verifier(environment)


@pytest.mark.parametrize("contents", [
    '{"password":"JSON_SECRET', '[]', '"JSON_SECRET"', "x" * 16385,
    '{"RA_DEMO_AUTH_ENABLED":"false","RA_DEMO_AUTH_ENABLED":"true"}',
])
def test_bad_local_file_is_sanitized(local_file, contents):
    path, _, environment = local_file
    path.write_text(contents, encoding="utf-8")
    with pytest.raises(ValueError) as caught:
        load_local_verifier(environment)
    assert "JSON_SECRET" not in str(caught.value)
    assert str(path) not in str(caught.value)


def test_missing_file_and_missing_localappdata_are_safe(local_file):
    path, _, environment = local_file
    path.unlink()
    for values in (environment, {}, {"LOCALAPPDATA": "relative-directory"}):
        with pytest.raises(ValueError):
            load_local_verifier(values)


@pytest.mark.parametrize("flags", [[], ["--enable-local-demo"], ["--load-local-verifier"]])
def test_file_is_never_read_without_both_opt_ins(flags, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["demo_launcher", *flags])
    with patch("backend.ra.demo_launcher.load_local_verifier") as load, \
         patch("backend.ra.demo_launcher.getpass.getpass") as prompt:
        with pytest.raises(SystemExit):
            main()
        load.assert_not_called()
        prompt.assert_not_called()


def test_launcher_prompts_without_persisting_or_printing_password(local_file, monkeypatch, capsys, caplog):
    path, _, environment = local_file
    before = path.read_bytes()
    monkeypatch.setenv("LOCALAPPDATA", environment["LOCALAPPDATA"])
    monkeypatch.setenv("RA_DEMO_DB_PASSWORD", "IGNORED_ENV_PASSWORD")
    monkeypatch.setattr(sys, "argv", ["demo_launcher", "--enable-local-demo", "--load-local-verifier"])
    with patch("backend.ra.demo_launcher.getpass.getpass", return_value="PROMPTED_DB_SECRET") as prompt, \
         patch("backend.ra.demo_auth_runtime.psycopg.connect") as connect, \
         patch("backend.ra.demo_launcher.uvicorn.run") as run:
        main()
        prompt.assert_called_once_with("PostgreSQL password for ra_auth_login: ")
        connect.assert_not_called()
        assert run.call_args.kwargs["host"] == "127.0.0.1"
        assert run.call_args.kwargs["proxy_headers"] is False
        assert run.call_args.kwargs["access_log"] is False
    assert path.read_bytes() == before
    captured = capsys.readouterr()
    assert "PROMPTED_DB_SECRET" not in captured.out + captured.err + caplog.text
    assert "IGNORED_ENV_PASSWORD" not in captured.out + captured.err + caplog.text


def test_nonlocal_file_is_rejected_before_password_prompt(local_file, monkeypatch, capsys):
    path, payload, environment = local_file
    payload["RA_ENVIRONMENT"] = "production"
    path.write_text(json.dumps(payload), encoding="utf-8")
    monkeypatch.setenv("LOCALAPPDATA", environment["LOCALAPPDATA"])
    monkeypatch.setattr(sys, "argv", ["demo_launcher", "--enable-local-demo", "--load-local-verifier"])
    with patch("backend.ra.demo_launcher.getpass.getpass") as prompt:
        with pytest.raises(SystemExit):
            main()
        prompt.assert_not_called()
    assert "production" not in capsys.readouterr().err


def test_launcher_refuses_echoing_getpass_fallback(local_file, monkeypatch):
    _, _, environment = local_file
    monkeypatch.setenv("LOCALAPPDATA", environment["LOCALAPPDATA"])
    monkeypatch.setattr(sys, "argv", ["demo_launcher", "--enable-local-demo", "--load-local-verifier"])

    def fallback(prompt):
        warnings.warn("Cannot control echo", getpass.GetPassWarning)
        raise AssertionError("Must not read an echoing password")

    with patch("backend.ra.demo_launcher.getpass.getpass", side_effect=fallback), \
         patch("backend.ra.demo_launcher.uvicorn.run") as run:
        with pytest.raises(SystemExit):
            main()
        run.assert_not_called()
