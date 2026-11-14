"""AES-256-GCM recovery; persistent keys are operator-managed, never DB data."""

import os
from types import MappingProxyType

import rfc8785
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from backend.crypto.credential_protocol import key_id
from backend.ra.credential_service import CredentialUnavailable


class CredentialRecovery:
    def __init__(self, keys: dict[str, bytes], active_key_id: str):
        for name, value in keys.items():
            key_id(name)
            if not isinstance(value, bytes) or len(value) != 32:
                raise ValueError("Invalid recovery key configuration")
        if active_key_id not in keys:
            raise ValueError("Missing active recovery key")
        self._keys = MappingProxyType(dict(keys))
        self._active = active_key_id

    @staticmethod
    def _aad(context, storage_key_id):
        return b"EVOTE-RA-RECOVERY-v1\x00" + rfc8785.dumps({
            "reservation_id": str(context.reservation_id), "voter_id": str(context.voter_id),
            "election_id": str(context.election_id), "request_id": str(context.request_id),
            "blinded_hash": context.blinded_hash.hex(), "key_id": context.key_id,
            "config_hash": context.config_hash.hex(), "storage_key_id": storage_key_id,
            "recovery_expires_at": context.recovery_expires_at.isoformat(),
        })

    def encrypt(self, signature, context):
        try:
            if not isinstance(signature, bytes) or len(signature) != 384:
                raise ValueError
            nonce = os.urandom(12)
            ciphertext = AESGCM(self._keys[self._active]).encrypt(
                nonce, signature, self._aad(context, self._active)
            )
            return ciphertext, nonce, self._active
        except Exception:
            raise CredentialUnavailable() from None

    def decrypt(self, context):
        try:
            if (context.ciphertext is None or len(context.ciphertext) != 400
                or context.nonce is None or len(context.nonce) != 12):
                raise ValueError
            value = AESGCM(self._keys[context.storage_key_id]).decrypt(
                context.nonce, context.ciphertext, self._aad(context, context.storage_key_id)
            )
            if len(value) != 384:
                raise ValueError
            return value
        except Exception:
            raise CredentialUnavailable() from None
