"""Explicit Gate 2 local launcher. Never run by importing backend.main."""

import argparse
import getpass
import warnings
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from pydantic import SecretStr
import uvicorn

from backend.crypto.credential_protocol import b64decode
from backend.ra.credential_recovery import CredentialRecovery
from backend.ra.credential_runtime import create_credential_app, credential_connection_factory
from backend.ra.credential_service import CredentialIssuanceService
from backend.ra.credential_signer import LocalCIRCLSigner
from backend.ra.demo_launcher import load_local_verifier
from backend.ra.postgres_credential_store import PostgreSQLCredentialStore


def prompt(label):
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        value = getpass.getpass(label)
    if not value:
        raise ValueError("Missing local credential configuration")
    return value


def main():
    parser = argparse.ArgumentParser(description="Explicit local RA credential demo")
    for flag in ("--enable-local-demo", "--load-local-verifier", "--enable-credential-issuance"):
        parser.add_argument(flag, action="store_true", required=True)
    parser.add_argument("--signer-binary", type=Path, required=True)
    parser.add_argument("--encrypted-signing-key", type=Path, required=True)
    parser.add_argument("--manifest-authority-pin", type=Path, required=True,
                        help="Independently trusted raw Ed25519 PUBLIC key (32 bytes)")
    parser.add_argument("--key-id", required=True)
    parser.add_argument("--recovery-key-id", required=True)
    args = parser.parse_args()
    signer = None
    try:
        config = load_local_verifier(os.environ)
        config["RA_DEMO_DB_PASSWORD"] = prompt("PostgreSQL password for ra_auth_login: ")
        password = SecretStr(prompt("PostgreSQL password for ra_issuance_login: "))
        recovery_key = b64decode(prompt("Persistent AES-256 recovery key (base64url): "), 32)
        unlock = prompt("RA encrypted signing-key passphrase: ").encode()
        private = serialization.load_pem_private_key(args.encrypted_signing_key.read_bytes(), password=unlock)
        del unlock
        pin = args.manifest_authority_pin.read_bytes()
        signer = LocalCIRCLSigner(args.signer_binary, private, args.key_id)
        del private
        service = CredentialIssuanceService(PostgreSQLCredentialStore(credential_connection_factory(password)),
            signer, CredentialRecovery({args.recovery_key_id: recovery_key}, args.recovery_key_id), pin)
        app = create_credential_app(config, service)
        config.pop("RA_DEMO_DB_PASSWORD", None)
        uvicorn.run(app, host="127.0.0.1", port=8000, proxy_headers=False,
                    forwarded_allow_ips="", access_log=False, workers=1, log_level="warning", server_header=False)
    except Exception:
        parser.exit(2, "Local credential service unavailable or invalid configuration\n")
    finally:
        if 'config' in locals():
            config.pop("RA_DEMO_DB_PASSWORD", None)
        if signer is not None:
            signer.close()


if __name__ == "__main__":
    main()
