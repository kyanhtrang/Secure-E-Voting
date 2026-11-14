import hashlib
import secrets

import pytest

from backend.ra.auth_service import VerifiedIdentity
from backend.ra.demo_credential_verifier import DemoCredentialVerifier


USERNAME = "demo-voter"
PASSWORD = "synthetic-demo-password"
PROVIDER = "demo-local"
SUBJECT = "demo-subject-001"


@pytest.fixture(scope="module")
def password_material():
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(
        PASSWORD.encode("utf-8"),
        salt=salt,
        n=2**14,
        r=8,
        p=1,
        dklen=32,
    )
    return salt, digest


@pytest.fixture
def verifier(password_material):
    salt, digest = password_material
    return DemoCredentialVerifier(
        username=USERNAME,
        password_salt=salt,
        password_digest=digest,
        provider=PROVIDER,
        subject=SUBJECT,
        enable_demo=True,
    )


def test_demo_disabled_by_default(password_material):
    salt, digest = password_material

    with pytest.raises(RuntimeError, match="disabled"):
        DemoCredentialVerifier(
            username=USERNAME,
            password_salt=salt,
            password_digest=digest,
            provider=PROVIDER,
            subject=SUBJECT,
        )


def test_demo_explicitly_disabled(password_material):
    salt, digest = password_material

    with pytest.raises(RuntimeError, match="disabled"):
        DemoCredentialVerifier(
            username=USERNAME,
            password_salt=salt,
            password_digest=digest,
            provider=PROVIDER,
            subject=SUBJECT,
            enable_demo=False,
        )


def test_correct_credentials(verifier):
    result = verifier.verify_credentials(USERNAME, PASSWORD)

    assert isinstance(result, VerifiedIdentity)
    assert result.provider == PROVIDER
    assert result.subject == SUBJECT


def test_wrong_password(verifier):
    assert verifier.verify_credentials(
        USERNAME, "wrong-password"
    ) is None


def test_wrong_username(verifier):
    assert verifier.verify_credentials(
        "wrong-user", PASSWORD
    ) is None


def test_username_case_sensitive(verifier):
    assert verifier.verify_credentials(
        USERNAME.upper(), PASSWORD
    ) is None


def test_empty_password(verifier):
    assert verifier.verify_credentials(USERNAME, "") is None


def test_oversized_password(verifier):
    assert verifier.verify_credentials(
        USERNAME, "x" * 1025
    ) is None


def test_nonstring_username(verifier):
    assert verifier.verify_credentials(
        123, PASSWORD
    ) is None


def test_nonstring_password(verifier):
    assert verifier.verify_credentials(
        USERNAME, 123
    ) is None


def test_password_not_normalized(verifier):
    assert verifier.verify_credentials(
        USERNAME, " " + PASSWORD + " "
    ) is None


@pytest.mark.parametrize(
    "salt",
    [b"short", "not-bytes"],
)
def test_invalid_salt_rejected(salt, password_material):
    _, digest = password_material

    with pytest.raises(ValueError):
        DemoCredentialVerifier(
            username=USERNAME,
            password_salt=salt,
            password_digest=digest,
            provider=PROVIDER,
            subject=SUBJECT,
            enable_demo=True,
        )


@pytest.mark.parametrize(
    "digest",
    [b"short", "not-bytes"],
)
def test_invalid_digest_rejected(digest, password_material):
    salt, _ = password_material

    with pytest.raises(ValueError):
        DemoCredentialVerifier(
            username=USERNAME,
            password_salt=salt,
            password_digest=digest,
            provider=PROVIDER,
            subject=SUBJECT,
            enable_demo=True,
        )


def test_blank_username_rejected(password_material):
    salt, digest = password_material

    with pytest.raises(ValueError):
        DemoCredentialVerifier(
            username="   ",
            password_salt=salt,
            password_digest=digest,
            provider=PROVIDER,
            subject=SUBJECT,
            enable_demo=True,
        )


def test_invalid_provider_rejected(password_material):
    salt, digest = password_material

    with pytest.raises(ValueError):
        DemoCredentialVerifier(
            username=USERNAME,
            password_salt=salt,
            password_digest=digest,
            provider="",
            subject=SUBJECT,
            enable_demo=True,
        )


def test_invalid_subject_rejected(password_material):
    salt, digest = password_material

    with pytest.raises(ValueError):
        DemoCredentialVerifier(
            username=USERNAME,
            password_salt=salt,
            password_digest=digest,
            provider=PROVIDER,
            subject="",
            enable_demo=True,
        )