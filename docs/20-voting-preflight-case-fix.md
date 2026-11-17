# PostgreSQL 18 Voting preflight correction

Status: corrected for final human review; real PostgreSQL rerun remains pending.

The reported CI diagnostic confirms SQLSTATE 42809 at revision `d8f27a4c610b`,
stage `alembic`, check `upgrade_sql_01`, source routine
`has_sequence_privilege_name_id`. The first migration block contains exactly one
call to that function. Its adjacent `AND c.relkind='S'` predicate did not ensure
that the type-specific privilege function received only sequence OIDs.

The project maintainer confirmed no successful deployment in any known project
environment: both disposable CI attempts failed before completion, the revision
was not applied locally, and no other successful deployment was reported.
The maintainer explicitly authorized correcting this existing unreleased
revision. This is deployment-status attestation, not a database inspection.

## Exact migration change

Only the two catalog privilege predicates change in
[d8f27a4c610b](../migrations/voting/versions/d8f27a4c610b_anonymous_ballot_acceptance.py):

```diff
-        WHERE n.nspname='voting' AND c.relkind IN ('r','p','v','m','f') AND
-          (pg_catalog.has_table_privilege(r.rolname,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
-           OR pg_catalog.has_any_column_privilege(r.rolname,c.oid,'SELECT,INSERT,UPDATE,REFERENCES'))
+        WHERE n.nspname='voting' AND CASE WHEN c.relkind IN ('r','p','v','m','f')
+          THEN (pg_catalog.has_table_privilege(r.rolname,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
+                OR pg_catalog.has_any_column_privilege(r.rolname,c.oid,'SELECT,INSERT,UPDATE,REFERENCES'))
+          ELSE FALSE END
```

```diff
-        WHERE n.nspname='voting' AND c.relkind='S' AND
-          pg_catalog.has_sequence_privilege(r.rolname,c.oid,'USAGE,SELECT,UPDATE')
+        WHERE n.nspname='voting' AND CASE WHEN c.relkind='S'
+          THEN pg_catalog.has_sequence_privilege(r.rolname,c.oid,'USAGE,SELECT,UPDATE')
+          ELSE FALSE END
```

The sequence check's row-dependent CASE evaluates the privilege function only
for sequences. The adjacent table/column checks receive the same defensive
guard for their existing relation-kind domain. All privilege names, namespace
filters and rejection assertions remain intact. No grants are removed from
inspection or silently allowed. See PostgreSQL's
[CASE semantics](https://www.postgresql.org/docs/18/functions-conditional.html#FUNCTIONS-CASE).

An exact source comparison against HEAD confirmed that replacing those two
predicates reproduces the entire modified migration. Revision metadata,
SECURITY DEFINER functions, ownership, search_path, EXECUTE grants/revocations,
transaction/locking rules and uniqueness remain unchanged. Both earlier Voting
revisions, RA migrations and frozen cryptography were compared with HEAD and
remain unchanged. The existing safe CI diagnostics are retained.

## Regression coverage and actual validation

[Five new tests](../tests/test_voting_preflight_kinds.py) extract the actual two
CASE expressions from the migration's first SQL literal. They execute them over
ten simulated pg_class kinds: ordinary/partitioned tables, views, materialized
views, foreign tables, sequences, ordinary/partitioned indexes, composite types
and TOAST tables. Strict test functions reject wrong-kind calls, record the
unchanged privilege lists and verify positive table, column and sequence grants
are still detected. A negative control verifies that an unguarded sequence call
on a table really fails the test probe.

These probes use SQLite in memory, not PostgreSQL catalogs or its planner. They
validate branch evaluation and retained detection; they are not a real-DB PASS.

Executed locally:

* `python -m pytest tests/ crypto_interop/ -q`: **558 passed in 10.07 seconds**,
  including existing migration static and TypeScript client/RFC regressions.
* `node --test crypto_interop/dist/pending_state.test.js`: **2 passed**.
* Voting dependency version verification and `python -m pip check`: passed.
* Changed Python syntax, workflow YAML and every Bash run step's syntax: passed.
* Exact two-replacement migration comparison and `git diff --check`: passed.
* Changed-source secret-pattern and whitespace scans: passed.

Only three files changed: this report, the unreleased migration and the new test
file. No PostgreSQL connection, migration execution, commit, push or merge was
performed. No existing test/assertion was changed. No dependency or workflow edit
was needed.

GitHub must rerun the full existing isolated PostgreSQL 18 job: all three real
migrations, acceptance, 20-way serial contention, rollback, committed-response
recovery, receipt equality, closing races, deadlines, effective ACL denial and
fixture/container cleanup. A separate diagnostic-only run is no longer required
to locate this confirmed call site. PostgreSQL integration is still pending
until that full run succeeds. Stop for human review.
