import sys
from unittest.mock import MagicMock, Mock, patch

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from backend.main import app as default_app
from backend.ra.auth_service import AuthenticationUnavailable
from backend.ra.demo_auth_runtime import compose_demo_services, demo_connection_factory
from backend.ra.demo_launcher import create_demo_app, main
from tests.demo_auth_helpers import DemoDatabaseDouble, PASSWORD, demo_environment


@pytest.fixture(scope="module")
def environment():
    return demo_environment()


@pytest.mark.parametrize("key,value", [
    ("RA_DEMO_AUTH_ENABLED", None), ("RA_DEMO_AUTH_ENABLED", "TRUE"),
    ("RA_ENVIRONMENT", "production"), ("RA_ENVIRONMENT", None),
    ("RA_DEMO_DB_PASSWORD", ""), ("RA_DEMO_SUBJECT", "another-subject"),
    ("RA_DEMO_PROVIDER", "another-provider"),
    ("RA_DEMO_DB_USER", "postgres"), ("RA_DEMO_DB_USER", "ra_owner"),
    ("RA_DEMO_DB_USER", "ra_migrator_login"),
    ("RA_DEMO_DB_HOST", "0.0.0.0"), ("RA_DEMO_DB_NAME", "voting_db"),
    ("RA_DEMO_DB_PORT", "5433"), ("RA_DEMO_DIGEST_HEX", "invalid"),
])
def test_configuration_fails_closed_without_connecting(environment, key, value):
    config = dict(environment)
    if value is None:
        config.pop(key)
    else:
        config[key] = value
    with patch("backend.ra.demo_auth_runtime.psycopg.connect") as connect:
        with pytest.raises((RuntimeError, ValueError)):
            create_demo_app(config)
        connect.assert_not_called()


def test_default_app_ignores_opt_in_environment(environment, monkeypatch):
    for key, value in environment.items():
        monkeypatch.setenv(key, value)
    with patch("backend.ra.demo_auth_runtime.psycopg.connect") as connect:
        response = TestClient(default_app).post("/api/v1/ra/auth/login", json={
            "username": "demo-voter", "password": PASSWORD
        })
        assert response.status_code == 503
        connect.assert_not_called()


def test_configuration_is_lazy(environment):
    with patch("backend.ra.demo_auth_runtime.psycopg.connect") as connect:
        compose_demo_services(environment)
        connect.assert_not_called()


def test_database_factory_uses_explicit_runtime_identity(monkeypatch):
    monkeypatch.setenv("PGUSER", "postgres")
    monkeypatch.setenv("PGDATABASE", "voting_db")
    monkeypatch.setenv("PGOPTIONS", "-c role=ra_owner")
    conn = MagicMock()
    conn.execute.return_value.fetchone.return_value = (
        "ra_db", "ra_auth_login", "ra_auth_login"
    )
    with patch("backend.ra.demo_auth_runtime.psycopg.connect", return_value=conn) as connect:
        factory = demo_connection_factory(SecretStr("SYNTHETIC_DB_CANARY"))
        assert "SYNTHETIC_DB_CANARY" not in repr(factory)
        assert factory() is conn
    kwargs = connect.call_args.kwargs
    assert kwargs["host"] == "127.0.0.1"
    assert kwargs["port"] == 5432
    assert kwargs["dbname"] == "ra_db"
    assert kwargs["user"] == "ra_auth_login"
    assert kwargs["password"] == "SYNTHETIC_DB_CANARY"
    assert kwargs["connect_timeout"] == 5
    assert kwargs["options"] == "-c statement_timeout=5000 -c lock_timeout=2000"
    conn.execute.assert_called_once_with(
        "SELECT current_database(), session_user, current_user"
    )
    conn.commit.assert_called_once_with()


@pytest.mark.parametrize("identity", [
    ("ra_db", "postgres", "ra_auth_login"),
    ("ra_db", "ra_auth_login", "ra_owner"),
    ("voting_db", "ra_auth_login", "ra_auth_login"), None,
])
def test_wrong_database_identity_closes_connection(identity):
    conn = MagicMock()
    conn.execute.return_value.fetchone.return_value = identity
    with patch("backend.ra.demo_auth_runtime.psycopg.connect", return_value=conn):
        with pytest.raises(AuthenticationUnavailable, match="^Authentication unavailable$"):
            demo_connection_factory(SecretStr("synthetic"))()
    conn.close.assert_called_once_with()
    conn.commit.assert_not_called()


def test_database_connect_failure_is_sanitized():
    with patch("backend.ra.demo_auth_runtime.psycopg.connect", side_effect=RuntimeError("DB_SECRET")):
        with pytest.raises(AuthenticationUnavailable) as caught:
            demo_connection_factory(SecretStr("synthetic"))()
    assert "DB_SECRET" not in str(caught.value)


@pytest.mark.parametrize("client,host,origin", [
    ("192.0.2.1", "127.0.0.1:8000", None),
    ("127.0.0.1", "attacker.example", None),
    ("127.0.0.1", "127.0.0.1.attacker.example", None),
    ("127.0.0.1", "127.0.0.1:8000", "https://attacker.example"),
    ("127.0.0.1", "127.0.0.1:8000", "null"),
])
def test_local_access_enforced(environment, client, host, origin):
    database = DemoDatabaseDouble()
    app = create_demo_app(environment, connection_factory=database.factory)
    headers = {"Host": host, "X-Forwarded-For": "127.0.0.1"}
    if origin:
        headers["Origin"] = origin
    response = TestClient(app, client=(client, 1234)).post(
        "/api/v1/ra/auth/login", headers=headers,
        json={"username": "demo-voter", "password": PASSWORD},
    )
    assert response.status_code == 403
    assert response.headers["cache-control"] == "no-store"
    assert "access-control-allow-origin" not in response.headers
    database.factory.assert_not_called()


def test_launcher_requires_explicit_flag_and_sanitizes_config_failure(monkeypatch, capsys, environment):
    monkeypatch.setattr(sys, "argv", ["demo_launcher"])
    with patch("backend.ra.demo_launcher.create_demo_app") as create:
        with pytest.raises(SystemExit):
            main()
        create.assert_not_called()
    monkeypatch.setattr(sys, "argv", ["demo_launcher", "--enable-local-demo", "--load-local-verifier"])
    with patch("backend.ra.demo_launcher.load_local_verifier", return_value=dict(environment)), \
         patch("backend.ra.demo_launcher.getpass.getpass", return_value="synthetic-password"), \
         patch("backend.ra.demo_launcher.create_demo_app", side_effect=ValueError("CONFIG_SECRET")):
        with pytest.raises(SystemExit):
            main()
    assert "CONFIG_SECRET" not in capsys.readouterr().err


def test_launcher_binds_only_loopback_and_disables_proxy_and_access_logs(monkeypatch, environment):
    monkeypatch.setattr(sys, "argv", ["demo_launcher", "--enable-local-demo", "--load-local-verifier"])
    with patch("backend.ra.demo_launcher.load_local_verifier", return_value=dict(environment)), \
         patch("backend.ra.demo_launcher.getpass.getpass", return_value="synthetic-password"), \
         patch("backend.ra.demo_launcher.create_demo_app", return_value=Mock()) as create:
        with patch("backend.ra.demo_launcher.uvicorn.run") as run:
            main()
    assert run.call_args.args == (create.return_value,)
    assert run.call_args.kwargs == {
        "host": "127.0.0.1", "port": 8000, "proxy_headers": False,
        "forwarded_allow_ips": "", "access_log": False, "workers": 1,
        "log_level": "warning", "server_header": False,
    }
