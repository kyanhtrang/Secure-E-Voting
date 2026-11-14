import getpass
import hashlib
import json
import os
import secrets
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.ra.demo_auth_config import (
    load_demo_credential_verifier,
)


USERNAME = "demo-voter"
PROVIDER = "demo-local"
SUBJECT = "demo-voter-001"


def main():
    local_app_data = os.environ.get("LOCALAPPDATA")

    if not local_app_data:
        raise RuntimeError("LOCALAPPDATA is unavailable")

    output = (
        Path(local_app_data)
        / "Secure-E-Voting"
        / "ra-demo-auth.local.json"
    )

    if output.exists():
        raise FileExistsError(
            "Local demo credentials already exist. "
            "Refusing to overwrite them."
        )

    password = getpass.getpass(
        "Create demo password (at least 12 characters): "
    )

    confirmation = getpass.getpass(
        "Confirm demo password: "
    )

    if password != confirmation:
        raise ValueError("Passwords do not match")

    if not 12 <= len(password) <= 128:
        raise ValueError(
            "Demo password must contain 12-128 characters"
        )

    salt = secrets.token_bytes(16)

    digest = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=2**14,
        r=8,
        p=1,
        dklen=32,
    )

    config = {
        "RA_ENVIRONMENT": "local",
        "RA_DEMO_AUTH_ENABLED": "true",
        "RA_DEMO_USERNAME": USERNAME,
        "RA_DEMO_PROVIDER": PROVIDER,
        "RA_DEMO_SUBJECT": SUBJECT,
        "RA_DEMO_SALT_HEX": salt.hex(),
        "RA_DEMO_DIGEST_HEX": digest.hex(),
    }

    verifier = load_demo_credential_verifier(config)

    identity = verifier.verify_credentials(
        USERNAME, password
    )

    assert identity is not None
    assert identity.provider == PROVIDER
    assert identity.subject == SUBJECT

    assert verifier.verify_credentials(
        "invalid-demo-user", password
    ) is None

    print("PASS 1/3: Password hashing and verification")

    output.parent.mkdir(parents=True, exist_ok=True)

    # Exclusive creation: never overwrite existing credentials.
    with output.open("x", encoding="utf-8") as file:
        json.dump(config, file, indent=2)

    saved_config = json.loads(
        output.read_text(encoding="utf-8")
    )

    assert saved_config == config

    print("PASS 2/3: Hashed configuration saved")
    print("PASS 3/3: Configuration verified")
    print("Saved outside Git repository:", output)
    print("RA demo credential setup: PASS 3/3")


if __name__ == "__main__":
    main()