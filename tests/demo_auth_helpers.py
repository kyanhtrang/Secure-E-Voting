"""Synthetic credentials and a stateful database double; never opens sockets."""

import hashlib
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, Mock
from uuid import UUID

from fastapi.testclient import TestClient

from backend.ra.demo_launcher import create_demo_app
from backend.ra.session_service import RASessionRecord


VOTER_ID = UUID("11111111-1111-4111-8111-111111111111")
PASSWORD = "synthetic-demo-password"


def demo_environment():
    salt = bytes(range(16))
    return {
        "RA_ENVIRONMENT": "local",
        "RA_DEMO_AUTH_ENABLED": "true",
        "RA_DEMO_USERNAME": "demo-voter",
        "RA_DEMO_PROVIDER": "demo-local",
        "RA_DEMO_SUBJECT": "demo-voter-001",
        "RA_DEMO_SALT_HEX": salt.hex(),
        "RA_DEMO_DIGEST_HEX": hashlib.scrypt(
            PASSWORD.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32
        ).hex(),
        "RA_DEMO_DB_PASSWORD": "synthetic-database-password",
    }


class DemoDatabaseDouble:
    def __init__(self):
        self.records = {}
        self.active = True
        self.error = None
        self.commit_error = None
        self.queries = []
        self.factory = Mock(side_effect=self.connect)

    def connect(self):
        conn = MagicMock()
        conn.__enter__.return_value = conn
        conn.__exit__.side_effect = self.finish
        conn.execute.side_effect = self.execute
        conn.cursor.return_value.__enter__.return_value.execute.side_effect = self.execute
        return conn

    def finish(self, exc_type, exc, traceback):
        if exc_type is None and self.commit_error:
            raise self.commit_error
        return False

    def execute(self, sql, params):
        if self.error:
            raise self.error
        self.queries.append((sql, params))
        row = None
        if "find_active_demo_voter_id" in sql:
            row = (VOTER_ID if self.active else None,)
        elif "issue_demo_session" in sql:
            digest, voter_id = params
            assert voter_id == VOTER_ID
            now = datetime.now(timezone.utc)
            self.records[digest] = RASessionRecord(
                digest, voter_id, now, now + timedelta(minutes=15)
            )
        elif "find_active_demo_session" in sql:
            record = self.records.get(params[0])
            if record and self.active and record.revoked_at is None:
                row = (
                    record.voter_id, record.created_at,
                    record.expires_at, record.revoked_at,
                )
        elif "revoke_demo_session" in sql:
            from dataclasses import replace

            record = self.records.get(params[0])
            changed = record is not None and record.revoked_at is None
            if changed:
                self.records[params[0]] = replace(
                    record, revoked_at=datetime.now(timezone.utc)
                )
            row = (changed,)
        else:
            raise AssertionError("Unexpected SQL in demo")
        result = MagicMock()
        result.fetchone.return_value = row
        return result


def demo_client(database, environment):
    return TestClient(
        create_demo_app(environment, connection_factory=database.factory),
        base_url="http://127.0.0.1:8000",
        client=("127.0.0.1", 50000),
    )
