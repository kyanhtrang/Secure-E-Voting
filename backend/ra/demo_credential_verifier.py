import hashlib
import hmac

from backend.ra.auth_service import VerifiedIdentity


class DemoCredentialVerifier:
    """
    Local development credential verifier.

    NOT suitable for proving real voter identity.
    Not connected to FastAPI automatically.
    """

    def __init__(
        self,
        *,
        username: str,
        password_salt: bytes,
        password_digest: bytes,
        provider: str,
        subject: str,
        enable_demo: bool = False,
    ):
        if not enable_demo:
            raise RuntimeError(
                "Demo authentication is disabled by default"
            )

        if not isinstance(username, str) or not username.strip():
            raise ValueError("Invalid demo username")

        if not isinstance(password_salt, bytes) or len(password_salt) < 16:
            raise ValueError("Invalid password salt")

        if not isinstance(password_digest, bytes) or len(password_digest) != 32:
            raise ValueError("Invalid password digest")

        self._username = username
        self._salt = password_salt
        self._digest = password_digest
        self._identity = VerifiedIdentity(
            provider=provider,
            subject=subject,
        )

    def verify_credentials(
        self,
        username: str,
        password: str,
    ) -> VerifiedIdentity | None:
        if not isinstance(username, str) or not isinstance(password, str):
            return None

        if not password or len(password) > 1024:
            return None

        calculated = hashlib.scrypt(
            password.encode("utf-8"),
            salt=self._salt,
            n=2**14,
            r=8,
            p=1,
            dklen=32,
        )

        username_ok = hmac.compare_digest(
            username.encode("utf-8"),
            self._username.encode("utf-8"),
        )

        password_ok = hmac.compare_digest(
            calculated,
            self._digest,
        )

        if username_ok and password_ok:
            return self._identity

        return None