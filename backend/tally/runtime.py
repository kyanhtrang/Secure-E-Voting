"""Restricted RPC adapters, independent operator sessions and durable tally orchestration."""
from contextlib import contextmanager
import hashlib
import secrets
from uuid import UUID

from psycopg.types.json import Jsonb
import rfc8785

from backend.crypto.credential_protocol import b64decode
from backend.ra.auth_service import AuthenticationDenied
from backend.ra.demo_credential_verifier import DemoCredentialVerifier
from backend.ra.login_rate_limit import LimitedDemoAuthentication
from backend.tally.verification import TallyError, artifact, build_snapshot, count, policy, integrity


def token_digest(token):
    try:
        if type(token) is not str or not token.startswith("tly1."): raise ValueError()
        b64decode(token[5:], 32)
        return hashlib.sha256(b"EVOTE-TALLY-SESSION-v1\0" + token.encode("ascii")).digest()
    except (ValueError, UnicodeError): raise TallyError(401, "AUTHENTICATION") from None


def translated(error):
    if isinstance(error, TallyError): return error
    state = getattr(error, "sqlstate", None)
    status, code = {"P5301": (401, "AUTHENTICATION"), "P5302": (409, "CONFLICT"),
        "P5303": (503, "INTEGRITY"), "P5304": (404, "UNAVAILABLE"), "55P03": (409, "CONFLICT"),
        "23505": (409, "CONFLICT"), "22P02": (503, "INTEGRITY"), "22021": (503, "INTEGRITY")}.get(state, (503, "UNAVAILABLE"))
    return TallyError(status, code)


class TallyStore:
    QUERIES = {
        "login": "SELECT voting_tally.login_session(%s::uuid,%s::bytea)",
        "session": "SELECT voting_tally.session(%s::bytea)", "logout": "SELECT voting_tally.logout(%s::bytea)",
        "list": "SELECT voting_tally.list_elections(%s::bytea)", "view": "SELECT voting_tally.view_report(%s::bytea,%s::uuid)",
        "claim": "SELECT voting_tally.claim(%s::bytea,%s::uuid)",
        "work": "SELECT voting_tally.work(%s::bytea,%s::uuid,%s::uuid,%s::bigint)",
        "seal": "SELECT voting_tally.seal(%s::bytea,%s::uuid,%s::uuid,%s::bigint,%s::jsonb)",
        "complete": "SELECT voting_tally.complete(%s::bytea,%s::uuid,%s::uuid,%s::bigint,%s::bytea,%s::bytea)",
        "fail": "SELECT voting_tally.fail(%s::bytea,%s::uuid,%s::uuid,%s::bigint,%s::text)",
    }
    def __init__(self, connect): self.connect = connect

    def execute(self, conn, name, *args):
        row = conn.execute(self.QUERIES[name], args).fetchone()
        if row is None or len(row) != 1: raise TallyError()
        return row[0]

    def call(self, name, *args):
        try:
            with self.connect() as conn: result = self.execute(conn, name, *args)
            return result  # Commit precedes any externally visible success.
        except Exception as error: raise translated(error) from None

    @contextmanager
    def transaction(self, digest, election, claim):
        try:
            with self.connect() as conn:
                args = (digest, election, UUID(claim["job_id"]), claim["fence"])
                value = self.execute(conn, "work", *args)
                yield TallyTransaction(self, conn, args, value)
        except Exception as error: raise translated(error) from None


class TallyTransaction:
    def __init__(self, store, conn, args, value): self.store, self.conn, self.args, self.value = store, conn, args, value
    def seal(self, value): self.store.execute(self.conn, "seal", *self.args, Jsonb(value))
    def complete(self, raw, sig): self.store.execute(self.conn, "complete", *self.args, raw, sig)


class TallyAuthentication:
    def __init__(self, store, operator_id, username, salt, digest):
        self.store, self.operator_id = store, UUID(str(operator_id))
        self.verifier = DemoCredentialVerifier(username=username, password_salt=salt, password_digest=digest,
            provider="local-tally", subject=str(self.operator_id), enable_demo=True)
        self.limited = LimitedDemoAuthentication(self)

    def _identity(self, value):
        if type(value) is not dict or value != {"operator_id": str(self.operator_id), "role": "TALLY_OPERATOR"}:
            raise TallyError(401, "AUTHENTICATION")
        return value

    def login(self, username, password):
        if self.verifier.verify_credentials(username, password) is None: raise AuthenticationDenied()
        token = "tly1." + secrets.token_urlsafe(32)
        self._identity(self.store.call("login", self.operator_id, token_digest(token)))
        return token

    def identity(self, token): return self._identity(self.store.call("session", token_digest(token)))
    def logout(self, token): self.store.call("logout", token_digest(token))


class TallyService:
    def __init__(self, auth, store, pin, vault, load_key):
        if type(pin) is not bytes or len(pin) != 32 or pin == vault.pin: raise ValueError("Distinct independently pinned authorities required")
        self.auth, self.store, self.pin, self.vault, self.load_key = auth, store, pin, vault, load_key

    def _report(self, value, election):
        manifest, _ = policy(value["config"], self.pin, str(election))
        snapshot = self.vault.verify(value["snapshot"], str(election), value["config"]["config_hash"])
        # All encrypted records remain private; only verified aggregate evidence escapes.
        response = self.vault.verify_report(value["report"], snapshot, value["config"]["config_hash"])
        report = response["report"]
        fields = {"report_version", "election_id", "election_config_digest", "snapshot_digest", "algorithm_version",
            "accepted_total", "valid_total", "invalid_total", "counted_total", "candidate_counts", "invalid_reasons"}
        integrity(set(report) == fields and type(report["report_version"]) is int and report["report_version"] == 1 and report["algorithm_version"] == "evote-tally-v1")
        for name in ("accepted_total", "valid_total", "invalid_total", "counted_total"):
            integrity(type(report[name]) is int and 0 <= report[name] <= 1000)
        expected = [candidate["candidate_id"] for candidate in manifest["candidates"]]
        integrity([row["candidate_id"] for row in report["candidate_counts"]] == expected)
        integrity(all(set(row) == {"candidate_id", "vote_count"} and type(row["vote_count"]) is int and row["vote_count"] >= 0 for row in report["candidate_counts"]))
        integrity(set(report["invalid_reasons"]) == {"KEY_WRAP", "AEAD", "PLAINTEXT"}
            and all(type(n) is int and n >= 0 for n in report["invalid_reasons"].values()))
        integrity(report["accepted_total"] == report["valid_total"] + report["invalid_total"]
            and report["counted_total"] == report["valid_total"] == sum(row["vote_count"] for row in report["candidate_counts"])
            and report["invalid_total"] == sum(report["invalid_reasons"].values()))
        response["candidates"] = manifest["candidates"]
        return response

    def elections(self, token):
        self.auth.identity(token)
        return self.store.call("list", token_digest(token))

    def report(self, token, election):
        self.auth.identity(token)
        try: return self._report(self.store.call("view", token_digest(token), election), election)
        except TallyError: raise
        except Exception: raise TallyError(503, "INTEGRITY") from None

    def run(self, token, election):
        self.auth.identity(token)
        digest = token_digest(token)
        claim = self.store.call("claim", digest, election)  # Durable BEFORE external file/key work.
        try:
            if claim["completed"]: return self.report(token, election)
            with self.store.transaction(digest, election, claim) as transaction:
                value = transaction.value
                policy(value["config"], self.pin, str(election))
                if value["snapshot"] is None:
                    raw = build_snapshot(value["records"], str(election), value["config"], self.pin)
                    sealed = self.vault.seal(raw)
                    transaction.seal(sealed)
            # Snapshot FINALIZED commit precedes RSA key loading/decryption.
            with self.store.transaction(digest, election, claim) as transaction:
                value = transaction.value
                snapshot = self.vault.verify(value["snapshot"], str(election), value["config"]["config_hash"])
                report = count(snapshot, value["config"], self.pin, self.load_key)
                raw, signature = self.vault.sign_report(report)
                transaction.complete(raw, signature)
            return self.report(token, election)
        except Exception as error:
            failure = error if isinstance(error, TallyError) else TallyError()
            # Unknown COMMIT outcome may already be SUCCEEDED. Never overwrite it.
            try: self.store.call("fail", digest, election, UUID(claim["job_id"]), claim["fence"],
                failure.code if failure.code in {"KEY_UNAVAILABLE", "INTEGRITY"} else "UNAVAILABLE")
            except Exception: pass  # Durable lease/fencing enables later recovery; no success is claimed.
            raise failure from None
