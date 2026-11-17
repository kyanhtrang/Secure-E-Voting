# Voting CI SQLSTATE 42809: targeted diagnostics

Status: **the failing CI SQL statement is not yet confirmed**. This change adds
safe evidence collection; it does not claim that PostgreSQL integration passes
or apply a speculative migration correction. A diagnostic CI rerun is required.

## Established evidence and static triage

The user reports dependency/regression/provisioning/SCRAM/role/marker checks
passed, then `migrate()` failed with SQLSTATE 42809 before the real harness.
Current branch HEAD before this change is `595ee95`. No PostgreSQL connection or
migration was executed locally to investigate.

Inspected the coordinator, guarded Alembic environment and all three revisions:

* `643decaa90ab`: creates the baseline tables, constraints and indexes. The
  references name actual tables; the composite FKs have matching unique keys.
* `b5bd58a07ceb`: schema-wide table/sequence/function revocations and default
  function-EXECUTE revocation. PostgreSQL object-kind selection for these
  commands is separate from the later catalog privilege-query hazard.
* `d8f27a4c610b`: catalog ACL preflight, five function definitions, two triggers,
  function ownership/revocations/grants and ACL postflight. Trigger creation
  targets baseline tables, and ALTER FUNCTION names include the trigger-returning
  function correctly; no evidence currently identifies these as failing.

The strongest candidate is the first `op.execute` block in
[d8f27a4c610b](../migrations/voting/versions/d8f27a4c610b_anonymous_ballot_acceptance.py),
specifically the sequence-ACL EXISTS expression:

```sql
WHERE n.nspname='voting' AND c.relkind='S' AND
  pg_catalog.has_sequence_privilege(r.rolname,c.oid,'USAGE,SELECT,UPDATE')
```

PostgreSQL 18's `has_sequence_privilege_name_id` explicitly raises
`ERRCODE_WRONG_OBJECT_TYPE` when the OID is not a sequence. Boolean AND/WHERE
evaluation order is not a guaranteed guard against calling a type-specific
function on the wrong relation kind. These facts establish a type-safety hazard,
not proof of the plan/statement executed in this failed CI run. The baseline
uses UUIDs rather than sequence-generated identifiers; absence of Voting
sequences does not itself prove that a catalog function will never be evaluated
on another pg_class row during execution.

Primary evidence:
[PostgreSQL 18 privilege implementation](https://github.com/postgres/postgres/blob/REL_18_STABLE/src/backend/utils/adt/acl.c),
[expression evaluation rules](https://www.postgresql.org/docs/18/sql-expressions.html#SYNTAX-EXPRESS-EVAL).
The exact failing statement/source routine still needs runtime diagnostics.

## Minimal diagnostic change

[MigrationDiagnostics](../scripts/voting_postgres_ci.py) parses only known
upgrade functions and hashes their literal `op.execute` strings to labels such
as `d8f27a4c610b / upgrade_sql_01`. A connection-scoped SQLAlchemy
`before_execute` listener classifies those literals before driver escaping. It
does not change, suppress, retry or skip any statement. Nonliteral/internal
statements receive a fixed fallback label. The listener is removed in `finally`.

Controlled stages also cover connection acquisition, marker validation,
identity, empty-schema verification, Alembic execution and commit. On an error,
the coordinator prints only stage, last recognized revision, fixed check label,
validated SQLSTATE and available exact-allowlisted schema/table/source-routine
fields. It re-raises the original error so the outer transaction rolls back and
the job/container teardown remain fail-closed.

No SQL text, bind parameters, exception message, DETAIL, CONTEXT, connection
string or arbitrary object identifier is printed. Even a syntactically valid
but unknown diagnostic identifier becomes `redacted`. Statement contents are
used only in memory for hashing; the hashes themselves are not logged.

If the candidate is responsible, an expected diagnostic form is:

```text
FAIL: Voting migration stage=alembic revision=d8f27a4c610b check=upgrade_sql_01 SQLSTATE=42809 source_function=has_sequence_privilege_name_id
```

This is an example of the controlled format, **not observed PostgreSQL output**.
Some diagnostic object fields may be absent. The revision identifies the last
recognized literal; `alembic_internal_or_nonliteral` is explicitly less precise.
The existing final sanitized CI failure message is retained as well.

## History and security preservation

No migration, guarded environment, SQL function, role/ACL, search_path, locking,
uniqueness rule, cryptographic protocol or production behavior was edited.
All three revisions remain byte-for-byte unchanged relative to HEAD. The
reported failing CI runs the chain inside one outer engine transaction; failure
does not commit that chain in its disposable database. This is not evidence of
deployment state in any other database, which was not inspected.

A later correction must follow the actual runtime evidence and explicitly
resolve deployment/history safety. Merely adding a later revision cannot repair
an earlier revision that fails before it can complete. This diagnostic change
does not bypass the earlier revision or weaken its permission assertions.

## Validation

Targeted diagnostic/CI/migration tests: **53 passed**. New tests classify all
three real first statements, reject unrecognized SQL as a label, redact arbitrary
diagnostic data/invalid SQLSTATE, test actual SQLAlchemy listener attachment and
removal, and inject a failure through `migrate()` to require re-raise/rollback
and no successful completion. A SQLite in-memory SELECT checks event API wiring
only; no PostgreSQL connection or migration SQL is executed by that test.

The existing migration-chain test only gains mocks for the added event hooks
and assertions requiring their removal. Its original checks remain intact.
Final local execution: **553 pytest tests passed in 10.28 seconds**, including
the migration static tests and all earlier regressions; **2 TypeScript recovery
tests passed**. The eight pinned dependency versions and `pip check` passed.
Workflow YAML and all Bash run-step syntax checks passed, as did Python syntax,
`git diff --check` and a four-file changed-source secret/whitespace scan.
All three migration revisions and the guarded environment were compared with
HEAD and are unchanged. No PostgreSQL test or migration was run locally.

GitHub must rerun the same isolated job and provide the controlled
failure line or demonstrate successful migrations plus the complete real
acceptance/concurrency/recovery/ACL/cleanup harness. Neither result is claimed
from database-free tests.

Files changed in this correction: coordinator, its existing test's event wiring,
[new diagnostic tests](../tests/test_voting_migration_diagnostics.py), and this
report. No workflow or dependency lock edits were necessary. No commit, push or
merge was performed. Stop for human review before publishing/rerunning CI.
