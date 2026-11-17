"""Closed-vocabulary test diagnostics. Never expose error messages or inputs."""

from contextlib import contextmanager
import re
from threading import BrokenBarrierError

import psycopg

from backend.crypto.credential_protocol import ProtocolError
from backend.voting.ballot_service import VotingUnavailable


STAGES = frozenset({
    "migration_head", "initial_snapshot", "fixture_seed", "concurrency_20",
    "duplicate_retry", "receipt_recovery", "identity_and_signature_rejection",
    "rollback", "lost_response", "closing_first_race", "acceptance_first_race",
    "election_time", "acl_verification", "cleanup", "final_snapshot",
})
CATEGORIES = frozenset({"assertion_error", "database_error", "voting_unavailable", "protocol_error",
                        "timeout_error", "concurrency_error", "system_exit", "unexpected_error"})
ASSERTIONS = {
    "A distinct voting_demo_test_ database is required": "database_designation",
    "Canonical marker required": "marker_format",
    "Disposable marker mismatch; refusing all writes": "database_marker",
    "Invalid loopback port": "loopback_port",
    "Unexpected test connection identity": "connection_identity",
    "Empty test password refused": "test_password_required",
    "Reviewed Voting migration head required": "fixture_migration_head",
    "Refusing to reuse an existing election": "new_fixture_election",
    "Expected PostgreSQL election-lock contention did not occur": "lock_contention_observed",
    "20-way serial uniqueness failed": "same_serial_outcomes",
    "Unexpected ballot count": "one_committed_ballot",
    "Retry inserted a second ballot": "duplicate_status",
    "Lost-response recovery or SQL/Python receipt interoperability failed": "receipt_consistency",
    "Identity metadata accepted": "identity_metadata_rejected",
    "RA bearer accepted": "ra_bearer_rejected",
    "Invalid cryptographic binding accepted": "invalid_credential_rejected",
    "Identical candidate choice rejected": "independent_same_choice_accepted",
    "Rollback retained a receipt": "rollback_receipt_absent",
    "Rolled-back serial consumed": "rollback_serial_reusable",
    "Response-loss injection failed": "lost_response_injected",
    "Committed response loss unrecoverable": "committed_receipt_recovered",
    "Response loss allowed another acceptance": "lost_response_duplicate_rejected",
    "Closing race worker absent": "closing_worker_started",
    "Closed election accepted a racing ballot": "closing_first_rejected",
    "Closed election prevented recovery": "closed_receipt_recovered",
    "Acceptance-first receipt mismatch": "acceptance_first_receipt",
    "Database voting window ignored": "db_window_enforced",
    "Unexpected Voting functions": "function_inventory",
    "Unsafe Voting function boundary": "function_boundary",
    "Another worker can invoke anonymous ballot functions": "worker_execute_denied",
    "PUBLIC function execution remains": "public_execute_denied",
    "Runtime has direct table access": "table_access_denied",
    "Unauthorized SQL succeeded": "unauthorized_sql_denied",
    "Frozen policy mutation succeeded": "policy_update_denied",
    "Fixture cleanup failed": "fixture_removed",
    "Uncommitted migration head": "committed_migration_head",
    "Fixture database must be fresh": "initial_tables_empty",
    "Committed Voting fixture cleanup failed": "committed_cleanup",
}
ASSERTION_IDS = frozenset((*ASSERTIONS.values(), "none", "unclassified"))


class IntegrationDiagnostics:
    def __init__(self):
        self.stage = "migration_head"
        self.failures = 0
        self._reported = set()

    def set_stage(self, stage):
        if stage not in STAGES:
            raise ValueError("Unknown integration diagnostic stage")
        self.stage = stage

    @staticmethod
    def category(error):
        for kind, label in ((AssertionError, "assertion_error"), (psycopg.Error, "database_error"),
            (VotingUnavailable, "voting_unavailable"), (ProtocolError, "protocol_error"),
            (TimeoutError, "timeout_error"), (BrokenBarrierError, "concurrency_error"),
            (SystemExit, "system_exit")):
            if isinstance(error, kind):
                return label
        return "unexpected_error"

    def failure(self, error):
        root = getattr(error, "orig", None) or error
        state = getattr(root, "sqlstate", None)
        state = state if isinstance(state, str) and re.fullmatch(r"[0-9A-Z]{5}", state) else "unavailable"
        assertion = "none"
        if isinstance(error, AssertionError):
            label = error.args[0] if error.args and type(error.args[0]) is str else None
            assertion = ASSERTIONS.get(label, "unclassified")
        return ("stage="+self.stage+" category="+self.category(root)+" SQLSTATE="+state+
                " assertion="+assertion)

    def report(self, error):
        if id(error) not in self._reported:
            self._reported.add(id(error))
            self.failures += 1
            print(self.failure(error), flush=True)

    @contextmanager
    def at(self, stage):
        self.set_stage(stage)
        try:
            yield
        except (Exception, SystemExit) as error:
            self.report(error)
            raise
