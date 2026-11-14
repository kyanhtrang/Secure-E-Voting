# Gate 2 disposable PostgreSQL CI

The user reports that commit `91049c6` passed native Go, runtime signer build
and the existing crypto interoperability gate on GitHub Actions. The new
PostgreSQL job described here is **not yet executed**. Nothing in this change
connects to, migrates, or provisions the user's existing database locally.

## Workflow and confinement

The separate `ra-postgres-integration` job in the
[existing workflow](../.github/workflows/rsabssa-interop.yml) runs on a fresh
Ubuntu 24.04 GitHub-hosted runner after the same commit's `crypto-interop` job
passes. It is restricted to the Gate 2 branch, has contents: read, uses pinned
setup/checkout actions with credential persistence and caches disabled, and
uploads no artifacts. Errors fail the job; no continue-on-error is used.

Node 24.22.3, Go 1.25.14, Python 3.11.9, the combined existing Python locks,
npm ci --ignore-scripts, CIRCL v1.6.5 with read-only module flags, and the real
runtime signer build are used. It runs the complete database-free regression
suite and protected TypeScript state tests before database work.

The [CI coordinator](../scripts/ra_gate2_ci.py) accepts only an explicit CI opt-in,
the built signer path and Node path. There are no host/database/password/URL
options. It refuses non-Linux, self-hosted/non-Actions environments, missing
runner temp storage and inherited PG*/Docker endpoint or configuration settings.
Docker is explicitly pinned to the hosted runner's local Unix socket. These are accident guards;
the independent target protection comes from owning a new container and never
accepting an existing endpoint.

The coordinator creates one UUID-named container, checks its exact ID, name,
ownership label, pinned image and sole loopback port mapping, and discovers its
random host port. It never uses host port 5432 or Docker prune. PostgreSQL 18
uses the official postgres:18-bookworm OCI index pinned at
`sha256:ece55f7868da684e400f82f1030a050718adbdd65c23aa500c486f6e2950dc0f`,
resolved from the official Docker Registry on 2026-11-15. Startup asserts server
major version 18. Image updates require an explicit reviewed pin change.

All database passwords are generated per run. Only the bootstrap password is
temporarily written, mode 0600 inside a private runner-temp directory, and
mounted read-only into the owned container using POSTGRES_PASSWORD_FILE.
No password is placed in a shell command, workflow environment, report or
artifact. This follows the [official image's file-based password support](https://hub.docker.com/_/postgres).
Host authentication uses SCRAM-SHA-256, local container authentication uses peer,
and the job checks HBA rules and proves an incorrect runtime password is rejected.
SQL/error parameter logging is disabled. Failures expose only a static label and
an optional validated SQLSTATE, never exception text, SQL parameters or tracebacks.

## Trusted setup and migration execution

Bootstrap uses generated postgres credentials only against the just-created
container. It rejects a cluster containing ra_db, creates a unique
`ra_demo_test_ci_<UUID hex>` database and installs a separate random UUID comment:
`secure-evoting-disposable:<UUID>`. The runtime cannot set that marker.

Trusted setup creates restricted NOLOGIN owner/service/audit group roles and
restricted NOINHERIT logins. Only ra_migrator_login gets SET membership in
ra_owner, with inheritance disabled. Auth/issuance logins have no memberships,
superuser, create-db, create-role, replication or BYPASSRLS attributes. PUBLIC
database privileges are revoked on the test and initial databases; only the
migrator, auth and issuance logins receive CONNECT on the test database. The
owner gets its own empty ra schema. Migration preflights and ACL postconditions
are retained and must pass.

The [CI-only Alembic environment](../scripts/ci_ra_migrations/env.py) receives an
already-open connection through Config.attributes, using the
[documented Alembic connection-sharing pattern](https://alembic.sqlalchemy.org/en/latest/cookbook.html#sharing-a-connection-across-one-or-more-programmatic-migration-commands).
It requires an injected guard that validates hosted CI, database/comment,
migrator identity and initially empty RA schema before any role switch or DDL.
It then uses SET LOCAL ROLE ra_owner and the existing RA search path. Normal
Alembic command.upgrade executes every revision in order and commits atomically;
there is no schema approximation or stamp-to-head shortcut. The original
production migration environment, fixed to ra_db, remains unchanged and is
never loaded by the coordinator.

### Forward-only SQL compatibility correction

Source review while wiring the real gate found that the baseline
blind_issuances.storage_key_id is varchar(128), while the Gate 2 composite
request_context field is text. The existing RETURN QUERY selects the varchar
directly; PostgreSQL composite result matching can require an explicit cast.
See the [PostgreSQL return-value contract](https://www.postgresql.org/docs/18/plpgsql-control-structures.html#PLPGSQL-STATEMENTS-RETURNING).

Revision 7b2d91a6c840 is preserved byte-for-byte. New forward-only
[revision c84e13b9702d](../migrations/ra/versions/c84e13b9702d_ra_credential_result_type.py)
replaces only the private _request function, adding `b.storage_key_id::text` to
its result. A regression test compares its full definition to the prior one and
requires that cast and CREATE OR REPLACE to be the only definition differences.
Owner/private-ACL preconditions fail closed; CREATE OR REPLACE preserves those
permissions. No table, role, grant, authorization, timestamp, audit, TTL or
cryptographic protocol change is introduced by this correction.

Both the coordinator and real harness now require head c84e13b9702d: all 14 RA
revisions are applied, including 7b2d91a6c840, followed by this compatibility fix.
Existing applied migration files are unchanged. No migration has been executed
locally; SQL execution remains part of the pending CI evidence.

## Existing real harness and stronger assertions

The coordinator invokes the existing
[real integration harness](../scripts/ra_credential_disposable_integration.py)
through its main entrypoint. Only this test harness accepts an in-memory
password-provider callback and explicit argument list. Standalone CLI behavior
still requires the existing opt-in/name/marker flags and getpass prompts. There
are no password command-line flags or production credential-provider changes.

The same disposable designation and per-connection identity/comment checks run
for every fixture, runtime and cleanup connection. Fixture work remains
ra_migrator_login SET LOCAL ROLE ra_owner; runtime is ra_issuance_login. All
voters, sessions, signing/recovery keys and manifests are generated test data.
No live demo voter or election credential is selected or consumed.

The job must pass actual TS Prepare/Blind -> authenticated HTTP -> PostgreSQL
reservation -> CIRCL original-byte BlindSign -> encrypted completion -> TS
Finalize -> Python Verify. It also requires:

- Real concurrent different requests yield one completion and one conflict;
  concurrent identical requests yield one completion and one exact replay.
- Reservation, signing, pre-commit and post-commit fault injection retains one
  authorization. Separate fixture transactions assert committed reservation,
  issuance and issuance-audit counts before retry, including audit rollback.
- Exact recovery returns the protected stored response after committed response
  loss. A different request is rejected after signer failure or lost signing
  response. Audit/completion counts remain one after successful recovery.
- Ineligible, disabled, expired and revoked sessions are rejected. Recovery
  expiry never releases the slot. Malformed inputs and incorrect trust pins fail.
- Policy/key immutability, expected SERVICE audit actor, definer ownership,
  search paths, only four exported runtime functions, no PUBLIC/unexpected
  function EXECUTE grants, no general RA schema/function access, and no runtime
  table/column privileges are verified against PostgreSQL.
- Cleanup commits before a new fixture connection compares complete RA-table
  snapshots. An unrelated generated sentinel voter/session must remain exactly
  unchanged, and no owned fixture/audit rows may remain. ra_db must stay absent.

The coordinator verifies container ownership again before removing that exact
container and its anonymous data volumes. Private temporary bootstrap material
is removed. Teardown failure fails the job. A forcibly cancelled job can bypass
Python finally handling; the fresh GitHub-hosted VM and its storage are discarded
at job teardown. No external persistent server or reusable volume is used.

## Execution, evidence and remaining limitations

The workflow runs this command only on its approved hosted runner:

```bash
"$RUNNER_TEMP/gate2-python/bin/python" scripts/ra_gate2_ci.py \
  --allow-ephemeral-ci-database \
  --signer-binary "$RUNNER_TEMP/gate2-runtime-signer" \
  --node "$(command -v node)"
```

There is deliberately no local-existing-database variant. Do not set fake CI
environment flags to bypass the host guard. Operator passwords and real election
keys are neither needed nor accepted. No commit/push/merge or local PostgreSQL
operation is performed by preparing this workflow.

Evidence must be the new job for the exact reviewed commit, not the previously
passed 91049c6 crypto run. Logs include static PASS labels for provisioning,
committed migration head, each real harness stage, committed cleanup/sentinel
preservation, and final owned-container teardown. Any failed check exits nonzero.
No new PostgreSQL integration PASS is claimed until that job actually executes.

Database-free tests cover host/target/container confinement, temporary credential
handling/teardown, bootstrap roles and password rejection, the real Alembic
revision graph with mocked connections, guard-before-DDL ordering, credential
callback behavior, cleanup comparison failures, failure redaction, forward SQL
equivalence and workflow configuration. These are not substitutes for the live
PostgreSQL job. Actual local validation results are recorded after checks finish.

Local validation for this change:

| Check | Actual result |
| --- | --- |
| Complete database-free pytest suite | 424 passed in 46.93s; all prior tests retained, 30 new CI/migration regression cases |
| TypeScript compile and protected-state tests | PASS; 2 tests passed |
| Runtime Go signer build | PASS (compilation only on Windows) |
| Workflow YAML and CI configuration checks | PASS within pytest |
| Forward SQL definition equivalence | PASS; one explicit result cast, no authorization/body changes |
| Whitespace/source parsing/secret-pattern checks | PASS; no secret-pattern findings |
| Existing migration files, production Alembic environment, auth/crypto, locks | Unchanged |
| Actual new PostgreSQL CI job | NOT RUN; awaiting human review and publication |

No PostgreSQL server/container was started, no database connection was opened,
no migration/role/grant was applied, and no real credentials were read locally.
Database/Docker unit-test operations are doubles. No commit, push or merge occurred.

Fault tests simulate process/response failures around real transaction boundaries;
they are not PostgreSQL-server crash, disk-loss or power-failure tests. A hosted
runner/image/supply-chain compromise remains outside this local-demo trust model.
Production key isolation, anonymous Voting/Tally, timing privacy, coercion
resistance and full end-to-end verifiability remain outside Gate 2.
