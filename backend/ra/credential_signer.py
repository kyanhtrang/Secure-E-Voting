"""Bounded local CIRCL process adapter, not a production key-isolation claim."""

import hashlib
import json
import queue
import subprocess
import threading

from cryptography.hazmat.primitives import serialization

from backend.crypto.credential_protocol import b64decode, b64encode, key_id, strict_json
from backend.ra.credential_service import CredentialUnavailable


class LocalCIRCLSigner:
    def __init__(self, executable, signing_key, signing_key_id, *, timeout=3):
        key_id(signing_key_id)
        if signing_key.key_size != 3072 or signing_key.public_key().public_numbers().e != 65537:
            raise ValueError("Invalid signing key profile")
        self._key_id = signing_key_id
        self._fingerprint = hashlib.sha256(signing_key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).digest()
        self._timeout = timeout
        self._lock = threading.Lock()
        self._lines = queue.Queue(maxsize=8)
        self._process = None
        try:
            self._process = subprocess.Popen([str(executable)], stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            threading.Thread(target=self._read, daemon=True).start()
            # Bootstrap is a private pipe, never HTTP, argv, environment, or disk.
            private_der = signing_key.private_bytes(serialization.Encoding.DER,
                serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
            reply = self._call({"op": "init", "key_id": signing_key_id,
                                "private_key_pkcs8": b64encode(private_der)})
            del private_der
            if reply != {"key_id": signing_key_id, "fingerprint": self._fingerprint.hex()}:
                raise CredentialUnavailable()
        except Exception:
            self.close()
            raise CredentialUnavailable() from None

    def _read(self):
        try:
            while True:
                line = self._process.stdout.readline(4097)
                if not line or len(line) > 4096:
                    break
                self._lines.put(line, timeout=self._timeout)
        except Exception:
            pass
        finally:
            try:
                self._lines.put_nowait(None)
            except queue.Full:
                pass

    def _call(self, request):
        self._process.stdin.write(json.dumps(request, separators=(",", ":")).encode()+b"\n")
        self._process.stdin.flush()
        line = self._lines.get(timeout=self._timeout)
        if line is None:
            raise CredentialUnavailable()
        return strict_json(line)

    def matches(self, key, fingerprint):
        return key == self._key_id and fingerprint == self._fingerprint

    def sign(self, original_blinded_msg):
        if not isinstance(original_blinded_msg, bytes) or len(original_blinded_msg) != 384:
            raise CredentialUnavailable()
        with self._lock:
            try:
                reply = self._call({"op": "sign", "key_id": self._key_id,
                                    "blinded_msg": b64encode(original_blinded_msg)})
                if set(reply) != {"blind_sig"}:
                    raise CredentialUnavailable()
                return b64decode(reply["blind_sig"], 384)
            except Exception:
                self.close()  # Never reuse an uncertain/late RPC response.
                raise CredentialUnavailable() from None

    def close(self):
        process = self._process
        if process is None:
            return
        if process.poll() is None:
            process.kill()
        process.wait(timeout=5)
        for stream in (process.stdin, process.stdout):
            if stream is not None:
                stream.close()
        self._process = None
