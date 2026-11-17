# Voting PostgreSQL integration stage diagnostics

Status: ready for human review and a full isolated CI rerun. **The current
integration failure's stage and functional root cause are not yet established.**

## Confirmed findings versus hypotheses

The supplied CI evidence establishes that provisioning and all three real
migrations passed at head `d8f27a4c610b`. Those results were not rerun locally.

Source inspection identifies two distinct boundaries:

1. [The coordinator](../scripts/voting_postgres_ci.py) checks the committed
   migration head and snapshots nine application tables BEFORE invoking
   `integration.main()`, then verifies the final snapshot AFTER it returns.
2. [The real harness](../scripts/voting_disposable_integration.py) catches
   ordinary exceptions in `main()` and converts them to `SystemExit`. The
   coordinator's former outer `except Exception` cannot catch that conversion.
   The harness also runs fixture cleanup in `finally`; a cleanup exception can
   replace the propagated original exception.

The supplied evidence does not distinguish these paths. No deterministic
functional defect was established in fixture SQL, the session-free service,
restricted store, transaction contexts, receipt calculation, concurrent requests
or election-lock tests. These remain investigation areas, not asserted causes.
Only safe test diagnostics and failure propagation are changed. No application
or migration correction is guessed.

## Exact scope of the diff

* New [diagnostic formatter](../scripts/voting_integration_diagnostics.py):
  explicit stage/category/assertion vocabularies, exact static assertion-message
  mapping, validated SQLSTATE and duplicate-record suppression.
* Coordinator: shared diagnostic object around head/snapshots/harness entry;
  observe `SystemExit` and retain a nonzero failure even for unexpected exit 0.
* Harness: set fixed phase identifiers, report the original failure BEFORE
  cleanup, independently report cleanup failure, and emit the safe record before
  `main()` performs its existing sanitized `SystemExit` conversion.
* New [failure-injection tests](../tests/test_voting_integration_diagnostics.py)
  and this report. Existing tests/assertions are unchanged.

AST comparisons confirmed every original `check`/`AssertionError` expression and
message, and every original SQL literal in both scripts, is unchanged. The
diagnostics do not alter query parameters, fixture ownership, transaction
contexts, request payloads, HTTP responses, locks or test outcomes. The added
cleanup context records and re-raises failures; it never suppresses them.

No committed migration, frozen cryptographic code, backend service/store/router,
role/ACL, dependency lock, guarded Alembic environment, workflow or UI is edited.

## Stage boundaries and failure format

| Stage | Location / source operation |
|---|---|
| `migration_head` | Coordinator fixture connection and committed-head assertion, before `main()` |
| `initial_snapshot` | Coordinator initial snapshot/freshness assertion and read-transaction exit |
| `fixture_seed` | Enter `main()`, validate target/collect test credentials, generate TEST material and commit owned fixture seed |
| `concurrency_20` | Twenty HTTP requests, outcome counts and exactly one stored ballot |
| `duplicate_retry` | Repeated submission must return 409 |
| `receipt_recovery` | Existing receipt and Python/PostgreSQL digest equality |
| `identity_and_signature_rejection` | Identity/bearer/modified-proof rejection and independent same-choice acceptance |
| `rollback` | Deliberate rollback, absent receipt and unspent serial |
| `lost_response` | Real committed acceptance with injected response loss and recovery |
| `closing_first_race` | Closing-first lock contention, rejection and recovery after close |
| `acceptance_first_race` | Acceptance-first receipt/lock contention and closing completion |
| `election_time` | OPEN-but-expired and not-yet-open windows |
| `acl_verification` | Function inventory/boundaries, PUBLIC/worker denial, table denial and policy immutability |
| `cleanup` | Guarded cleanup of owned elections, including cleanup commit failures |
| `final_snapshot` | Coordinator committed-cleanup comparison after `main()` returns |

New failure records have exactly these four fields:

```text
stage=<allowlisted-stage> category=<allowlisted-category> SQLSTATE=<five-character-code-or-unavailable> assertion=<allowlisted-ID>
```

For example (illustrative, **not observed CI output**):

```text
stage=initial_snapshot category=database_error SQLSTATE=42501 assertion=none
stage=concurrency_20 category=assertion_error SQLSTATE=unavailable assertion=same_serial_outcomes
stage=receipt_recovery category=assertion_error SQLSTATE=unavailable assertion=receipt_consistency
stage=cleanup category=database_error SQLSTATE=42501 assertion=none
```

Categories are assertion/database/Voting-unavailable/protocol/timeout/concurrency/
SystemExit/unexpected errors, each rendered as a fixed snake-case identifier.
Unknown assertion messages become `unclassified`; non-assertion failures use
`none`. Every existing explicit harness assertion has a mapped ID.

Passwords, connection strings, SQL text/parameters, exception messages, payloads,
keys, tokens, tracebacks, diagnostic object fields and environment values are
never printed by the formatter. Reading an assertion's first string argument
only performs exact membership lookup; unknown text is never echoed. Records
flush before `argparse` emits its existing generic failure message. Existing
sanitized CLI/CI boilerplate remains; external API sanitization is unchanged.

If the original phase AND cleanup fail, both safe records are printed. Reporting
the same exception through several layers does not relabel it as cleanup or
duplicate it. A real `main()` conversion to `SystemExit` remains observable by
the shared record, and the coordinator makes that path fail the job. No final
snapshot/success is attempted after such a failure.

HTTP errors deliberately hide internal database details. An HTTP 503 followed
by a failed status assertion therefore reports the stage/assertion with SQLSTATE
`unavailable`; it does NOT prove the database caused that response. No HTTP error
is unsanitized to improve diagnostics.

## Actual local validation

* `python -m pytest tests/ crypto_interop/ -q`: **588 passed in 18.03 seconds**,
  including the original 558 and 30 new diagnostic regressions.
* `node --test crypto_interop/dist/pending_state.test.js`: **2 passed**.
* Eight pinned Voting dependency versions and `python -m pip check`: passed.
* Python syntax, workflow YAML and every Bash run-step syntax check: passed.
* Original-assertion/SQL AST comparisons and `git diff --check`: passed.
* Changed-source secret-pattern and whitespace scans: passed.

Failure injection covers every stage's closed vocabulary, unknown-field
redaction, coordinator head/initial/final snapshot failures, real `main()`
SystemExit conversion, unexpected SystemExit(0), original concurrency failure
with both successful and failed cleanup, and fixture-seed permission failure.
The 20-request injected test uses mocks, not PostgreSQL; no real DB result is
claimed from these tests. No local PostgreSQL access or migrations occurred.

The full existing GitHub job can be rerun after human review/publication. It
must still pass the real harness, committed fixture cleanup and owned-container
teardown. Capture the four-field failure line if it fails; map its assertion ID
to the unchanged source check before proposing a functional correction.
No commit, push or merge was performed. Stop for review.
