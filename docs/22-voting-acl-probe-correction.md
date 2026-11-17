# Voting PostgreSQL ACL probe correction

Status: implemented for final review; **real PostgreSQL rerun remains pending**.

## Confirmed versus suspected cause

The supplied CI record confirms `acl_verification / assertion_error /
unauthorized_sql_denied`. The former loop used that same assertion for direct
SELECT, direct DELETE and the internal receipt helper. It does not identify which
query succeeded; no specific failed operation or new privilege grant is proven.

The all-NULL helper invocation was an unreliable execution-ACL probe. The
migration declares the helper IMMUTABLE STRICT SECURITY DEFINER, and PostgreSQL
18's optimizer can replace a STRICT call with a constant NULL when an argument
is constant NULL. See
[evaluate_function in the PostgreSQL 18 source](https://github.com/postgres/postgres/blob/REL_18_STABLE/src/backend/optimizer/util/clauses.c).
That establishes the source-level test weakness; it is not a reproduction or
proof that this particular helper caused the reported CI failure. A NULL result
does not establish that the caller executed its body or possesses EXECUTE.

## Exact targeted changes

[The harness](../scripts/voting_disposable_integration.py) replaces the former
three-query loop with a small explicit `ACL_PROBES` table and `run_acl_probes`.
All three forbidden operations remain. Each probe has its own fixed ID and
checks effective privileges for the ACTUAL runtime connection's `current_user`:

| Probe ID | Metadata check must return exactly `(False,)` | Forbidden operation |
|---|---|---|
| `direct_table_select` | `has_table_privilege(current_user,'voting.accepted_ballots','SELECT')` | `SELECT * FROM voting.accepted_ballots` |
| `direct_table_delete` | `has_table_privilege(current_user,'voting.accepted_ballots','DELETE')` | `DELETE FROM voting.accepted_ballots` |
| `internal_receipt_execute` | `has_function_privilege(current_user,'voting._ballot_receipt(uuid,bytea,bytea,bytea,bytea)','EXECUTE')` | Parameterized non-NULL helper invocation |

The actual metadata functions are qualified with `pg_catalog`. Existing broad
fixture-role table/column/function ACL inventory checks remain unchanged.

The function invocation changes exactly as follows:

```diff
-SELECT voting._ballot_receipt(NULL,NULL,NULL,NULL,NULL)
+SELECT voting._ballot_receipt(%s::uuid,%s::bytea,%s::bytea,%s::bytea,%s::bytea)
```

Bound arguments are one fixed synthetic UUID, 32 zero bytes, `b"{}"`, 33 zero
bytes and 384 zero bytes. All five values are non-NULL and have the declared
types. They are not a real credential or ciphertext. The pure receipt helper
does not read/modify election or ballot records. No output or parameters are logged.

After explicit metadata denial, the forbidden query must itself raise
`psycopg.errors.InsufficientPrivilege` with SQLSTATE `42501`. The helper retains
the identity of that query exception and verifies the same exception propagates
through transaction rollback. A denial during connection creation, metadata
lookup or context exit is not mistaken for a successful negative test. Wrong
SQLSTATEs, other exceptions and successful queries all fail.

Unexpected success raises INSIDE the connection context, so an accidentally
allowed DELETE is rolled back rather than committed. Correct denial also exits
the context with the exception and rolls back. Each probe uses a separate
guarded restricted-runtime connection; fixture-owner and runtime roles stay separate.

[The diagnostic formatter](../scripts/voting_integration_diagnostics.py) adds only
the three allowlisted probe identifiers and a small probe context. Any failure
within a probe uses that identifier in the existing `assertion` field, including
database errors and unexpected exceptions. It is recorded before outer handlers
and cleanup; duplicate reporting does not replace it with the generic ID.
Existing stage/category/SQLSTATE redaction and four-field output are retained.

Illustrative failure records, not observed CI results:

```text
stage=acl_verification category=assertion_error SQLSTATE=unavailable assertion=direct_table_select
stage=acl_verification category=assertion_error SQLSTATE=unavailable assertion=direct_table_delete
stage=acl_verification category=database_error SQLSTATE=42883 assertion=internal_receipt_execute
```

Expected 42501 denials are successful tests and emit no failure record. No query
text, exception message, private data or parameters are included in diagnostics.

## Validation and remaining CI gate

Added [23 database-free regressions](../tests/test_voting_acl_probes.py): all three
operations/metadata queries/IDs, typed non-NULL helper parameters, correct denials,
unexpected success rollback, wrong SQLSTATE/exception, granted/malformed metadata,
connection- or context-exit-only denial, distinct rollback errors, and invalid IDs.
Tests use mocks only; they do not establish actual PostgreSQL privilege results.

Executed locally:

* `python -m pytest tests/ crypto_interop/ -q`: **611 passed in 14.55 seconds**.
* `node --test crypto_interop/dist/pending_state.test.js`: **2 passed**.
* Pinned dependency verification and `python -m pip check`: passed.
* Python syntax, workflow YAML and all Bash run-step syntax: passed.
* `git diff --check` and changed-source secret/whitespace scans: passed.

Only four files change: harness, diagnostic formatter, new regression tests and
this report. Voting migrations, grants/ACLs, frozen cryptography, acceptance and
receipt implementation, backend HTTP behavior, workflow and dependency locks
are unchanged. No existing test/assertion was weakened or removed.

The full isolated PostgreSQL 18 CI job must still execute all three negative
probes, confirm effective privileges are false and receive actual query-level
42501 denials, then finish policy-immutability checks, fixture cleanup, final
snapshot comparison and container teardown. A new failure must identify the
specific probe, rather than be assumed to be the former all-NULL invocation.

No local PostgreSQL/ra_db access, migration execution, commit, push or merge
occurred. No real database integration PASS is claimed. Stop for review.
