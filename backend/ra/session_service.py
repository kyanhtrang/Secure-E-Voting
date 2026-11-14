import base64
import hashlib
import re
import secrets

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable, Protocol
from uuid import UUID


TOKEN_BYTES = 32
DEFAULT_SESSION_TTL = timedelta(minutes=15)

_TOKEN_PATTERN = re.compile(r"[A-Za-z0-9_-]{43}\Z")


class InvalidRASession(Exception):
    """The RA session is invalid, expired, or revoked."""


@dataclass(frozen=True)
class RASessionRecord:
    token_digest: str
    voter_id: UUID
    created_at: datetime
    expires_at: datetime
    revoked_at: datetime | None = None


class RASessionStore(Protocol):
    def save_session(self, record: RASessionRecord) -> None:
        ...

    def find_session(
        self, token_digest: str
    ) -> RASessionRecord | None:
        ...

    def revoke_session(
        self, token_digest: str, revoked_at: datetime
    ) -> bool:
        ...


class RASessionService:
    def __init__(
        self,
        store: RASessionStore,
        ttl: timedelta = DEFAULT_SESSION_TTL,
        clock: Callable[[], datetime] | None = None,
    ):
        if ttl <= timedelta(0):
            raise ValueError("Session TTL must be positive")

        self.store = store
        self.ttl = ttl
        self.clock = clock or (
            lambda: datetime.now(timezone.utc)
        )

    def _now(self) -> datetime:
        now = self.clock()

        if (
            now.tzinfo is None
            or now.utcoffset() is None
        ):
            raise RuntimeError(
                "Session clock must be timezone-aware"
            )

        return now.astimezone(timezone.utc)

    @staticmethod
    def _digest(token: str) -> str:
        if (
            not isinstance(token, str)
            or _TOKEN_PATTERN.fullmatch(token) is None
        ):
            raise InvalidRASession(
                "Invalid RA session"
            )

        try:
            raw = base64.urlsafe_b64decode(token + "=")
        except (ValueError, base64.binascii.Error) as exc:
            raise InvalidRASession(
                "Invalid RA session"
            ) from exc

        canonical = base64.urlsafe_b64encode(
            raw
        ).rstrip(b"=").decode("ascii")

        if (
            len(raw) != TOKEN_BYTES
            or not secrets.compare_digest(
                canonical, token
            )
        ):
            raise InvalidRASession(
                "Invalid RA session"
            )

        return hashlib.sha256(raw).hexdigest()

    def issue_ra_session(self, voter_id: UUID) -> str:
        if not isinstance(voter_id, UUID):
            raise ValueError("Invalid voter ID")

        now = self._now()

        token = secrets.token_urlsafe(TOKEN_BYTES)
        digest = self._digest(token)

        record = RASessionRecord(
            token_digest=digest,
            voter_id=voter_id,
            created_at=now,
            expires_at=now + self.ttl,
        )

        self.store.save_session(record)

        return token

    def resolve_voter_id(self, token: str) -> UUID:
        digest = self._digest(token)
        record = self.store.find_session(digest)

        if (
            record is None
            or record.token_digest != digest
            or record.revoked_at is not None
        ):
            raise InvalidRASession(
                "Invalid RA session"
            )

        if (
            record.expires_at.tzinfo is None
            or record.expires_at.utcoffset() is None
            or record.expires_at <= self._now()
        ):
            raise InvalidRASession(
                "Invalid RA session"
            )

        return record.voter_id

    def revoke_ra_session(self, token: str) -> bool:
        digest = self._digest(token)

        return self.store.revoke_session(
            digest,
            self._now(),
        )