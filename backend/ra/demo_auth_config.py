import os
from collections.abc import Mapping

from backend.ra.demo_credential_verifier import (
    DemoCredentialVerifier,
)


REQUIRED_KEYS = (
    "RA_DEMO_USERNAME",
    "RA_DEMO_PROVIDER",
    "RA_DEMO_SUBJECT",
    "RA_DEMO_SALT_HEX",
    "RA_DEMO_DIGEST_HEX",
)


def load_demo_credential_verifier(
    environment: Mapping[str, str] | None = None,
) -> DemoCredentialVerifier:
    values = os.environ if environment is None else environment

    # Explicit opt-in is mandatory.
    if values.get("RA_DEMO_AUTH_ENABLED") != "true":
        raise RuntimeError(
            "Demo authentication is disabled"
        )

    # Never enable the demo verifier in a nonlocal environment.
    if values.get("RA_ENVIRONMENT") != "local":
        raise RuntimeError(
            "Demo authentication requires local environment"
        )

    if any(not values.get(key) for key in REQUIRED_KEYS):
        raise ValueError(
            "Incomplete demo authentication configuration"
        )

    try:
        salt = bytes.fromhex(values["RA_DEMO_SALT_HEX"])
        digest = bytes.fromhex(values["RA_DEMO_DIGEST_HEX"])
    except ValueError:
        raise ValueError(
            "Invalid demo authentication credential material"
        ) from None

    return DemoCredentialVerifier(
        username=values["RA_DEMO_USERNAME"],
        password_salt=salt,
        password_digest=digest,
        provider=values["RA_DEMO_PROVIDER"],
        subject=values["RA_DEMO_SUBJECT"],
        enable_demo=True,
    )