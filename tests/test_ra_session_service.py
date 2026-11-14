import base64
import hashlib
import re

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from uuid import UUID

import pytest

from backend.ra.session_service import (
    InvalidRASession,
    RASessionService,
)


VOTER_ID = UUID("11111111-1111-4111-8111-111111111111")


class InMemorySessionStore:
    """Test double only. Not a production session store."""

    def __init__(self):
        self.records = {}

    def save_session(self, record):
        self.records[record.token_digest] = record

    def find_session(self, token_digest):
        return self.records.get(token_digest)

    def revoke_session(self, token_digest, revoked_at):
        record = self.records.get(token_digest)

        if record is None or record.revoked_at is not None:
            return False

        self.records[token_digest] = replace(
            record,
            revoked_at=revoked_at,
        )
        return True


@pytest.fixture
def session_env():
    state = {
        "now": datetime(
            2026, 11, 13, 1, 0,
            tzinfo=timezone.utc,
        )
    }

    store = InMemorySessionStore()

    service = RASessionService(
        store=store,
        ttl=timedelta(minutes=15),
        clock=lambda: state["now"],
    )

    return service, store, state


def get_record(store):
    assert len(store.records) == 1
    return next(iter(store.records.values()))


def test_issue_and_resolve_session(session_env):
    service, store, state = session_env

    token = service.issue_ra_session(VOTER_ID)

    assert service.resolve_voter_id(token) == VOTER_ID
    assert len(store.records) == 1


def test_token_uses_canonical_base64url(session_env):
    service, _, _ = session_env

    token = service.issue_ra_session(VOTER_ID)

    assert re.fullmatch(r"[A-Za-z0-9_-]{43}", token)
    assert "=" not in token
    assert "+" not in token
    assert "/" not in token


def test_tokens_are_unique(session_env):
    service, store, _ = session_env

    first = service.issue_ra_session(VOTER_ID)
    second = service.issue_ra_session(VOTER_ID)

    assert first != second
    assert len(store.records) == 2

    assert service.resolve_voter_id(first) == VOTER_ID
    assert service.resolve_voter_id(second) == VOTER_ID


def test_store_contains_digest_not_plaintext(session_env):
    service, store, _ = session_env

    token = service.issue_ra_session(VOTER_ID)
    record = get_record(store)

    raw = base64.urlsafe_b64decode(token + "=")
    expected_digest = hashlib.sha256(raw).hexdigest()

    assert len(raw) == 32
    assert record.token_digest == expected_digest
    assert token not in store.records
    assert token not in repr(record)


def test_session_valid_just_before_expiry(session_env):
    service, store, state = session_env

    token = service.issue_ra_session(VOTER_ID)
    record = get_record(store)

    state["now"] = record.expires_at - timedelta(
        microseconds=1
    )

    assert service.resolve_voter_id(token) == VOTER_ID


def test_session_rejected_at_expiry(session_env):
    service, store, state = session_env

    token = service.issue_ra_session(VOTER_ID)
    record = get_record(store)

    state["now"] = record.expires_at

    with pytest.raises(InvalidRASession):
        service.resolve_voter_id(token)


def test_session_rejected_after_expiry(session_env):
    service, store, state = session_env

    token = service.issue_ra_session(VOTER_ID)
    record = get_record(store)

    state["now"] = record.expires_at + timedelta(
        seconds=1
    )

    with pytest.raises(InvalidRASession):
        service.resolve_voter_id(token)


def test_revoked_session_rejected(session_env):
    service, store, state = session_env

    token = service.issue_ra_session(VOTER_ID)

    assert service.revoke_ra_session(token) is True

    record = get_record(store)
    assert record.revoked_at == state["now"]

    with pytest.raises(InvalidRASession):
        service.resolve_voter_id(token)


def test_repeated_revocation_returns_false(session_env):
    service, _, _ = session_env

    token = service.issue_ra_session(VOTER_ID)

    assert service.revoke_ra_session(token) is True
    assert service.revoke_ra_session(token) is False


def test_unknown_token_rejected(session_env):
    service, _, _ = session_env

    known_token = service.issue_ra_session(VOTER_ID)
    unknown_token = service.issue_ra_session(VOTER_ID)

    # Remove the second session from the test store.
    unknown_digest = service._digest(unknown_token)
    del service.store.records[unknown_digest]

    assert service.resolve_voter_id(known_token) == VOTER_ID

    with pytest.raises(InvalidRASession):
        service.resolve_voter_id(unknown_token)


@pytest.mark.parametrize(
    "token",
    [
        "",
        "abc",
        "A" * 42,
        "A" * 44,
        "bad token",
        "a" * 42 + "=",
        "@" * 43,
        None,
    ],
)
def test_malformed_tokens_rejected(session_env, token):
    service, _, _ = session_env

    with pytest.raises(InvalidRASession):
        service.resolve_voter_id(token)


@pytest.mark.parametrize(
    "ttl",
    [
        timedelta(0),
        timedelta(seconds=-1),
    ],
)
def test_invalid_ttl_rejected(ttl):
    with pytest.raises(ValueError):
        RASessionService(
            store=InMemorySessionStore(),
            ttl=ttl,
        )


def test_naive_clock_rejected():
    service = RASessionService(
        store=InMemorySessionStore(),
        clock=lambda: datetime(2026, 11, 13),
    )

    with pytest.raises(RuntimeError):
        service.issue_ra_session(VOTER_ID)


def test_naive_expiry_rejected(session_env):
    service, store, _ = session_env

    token = service.issue_ra_session(VOTER_ID)

    digest = service._digest(token)
    record = store.records[digest]

    store.records[digest] = replace(
        record,
        expires_at=datetime(2026, 11, 13),
    )

    with pytest.raises(InvalidRASession):
        service.resolve_voter_id(token)


def test_session_store_failure_fails_closed(
    session_env, monkeypatch
):
    service, store, _ = session_env

    def broken_save(record):
        raise RuntimeError("Synthetic storage failure")

    monkeypatch.setattr(
        store,
        "save_session",
        broken_save,
    )

    with pytest.raises(
        RuntimeError,
        match="Synthetic storage failure",
    ):
        service.issue_ra_session(VOTER_ID)

    assert len(store.records) == 0