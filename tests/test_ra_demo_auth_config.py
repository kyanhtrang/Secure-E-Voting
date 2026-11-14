import hashlib

import pytest

from backend.ra.demo_auth_config import (
    load_demo_credential_verifier,
)


PASSWORD = "synthetic-local-password"


@pytest.fixture(scope="module")
def config():
    salt = bytes(range(16))

    digest = hashlib.scrypt(
        PASSWORD.encode("utf-8"),
        salt=salt,
        n=2**14,
        r=8,
        p=1,
        dklen=32,
    )

    return {
        "RA_ENVIRONMENT": "local",
        "RA_DEMO_AUTH_ENABLED": "true",
        "RA_DEMO_USERNAME": "demo-voter",
        "RA_DEMO_PROVIDER": "demo-local",
        "RA_DEMO_SUBJECT": "demo-001",
        "RA_DEMO_SALT_HEX": salt.hex(),
        "RA_DEMO_DIGEST_HEX": digest.hex(),
    }


def test_disabled_by_default(config):
    values = dict(config)
    values.pop("RA_DEMO_AUTH_ENABLED")

    with pytest.raises(RuntimeError, match="disabled"):
        load_demo_credential_verifier(values)


def test_explicit_disable(config):
    values = dict(config)
    values["RA_DEMO_AUTH_ENABLED"] = "false"

    with pytest.raises(RuntimeError, match="disabled"):
        load_demo_credential_verifier(values)


def test_nonlocal_environment_rejected(config):
    values = dict(config)
    values["RA_ENVIRONMENT"] = "production"

    with pytest.raises(RuntimeError, match="local"):
        load_demo_credential_verifier(values)


def test_valid_local_configuration(config):
    verifier = load_demo_credential_verifier(config)

    identity = verifier.verify_credentials(
        "demo-voter", PASSWORD
    )

    assert identity is not None
    assert identity.provider == "demo-local"
    assert identity.subject == "demo-001"


def test_wrong_password_rejected(config):
    verifier = load_demo_credential_verifier(config)

    assert verifier.verify_credentials(
        "demo-voter", "wrong-password"
    ) is None


def test_missing_configuration_rejected(config):
    values = dict(config)
    values.pop("RA_DEMO_DIGEST_HEX")

    with pytest.raises(ValueError, match="Incomplete"):
        load_demo_credential_verifier(values)


def test_invalid_digest_rejected(config):
    values = dict(config)
    values["RA_DEMO_DIGEST_HEX"] = "invalid-hex"

    with pytest.raises(ValueError, match="Invalid"):
        load_demo_credential_verifier(values)