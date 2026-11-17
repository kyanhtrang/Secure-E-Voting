# Commit 6: real disposable Voting PostgreSQL CI

Status: implemented for human review; **real PostgreSQL CI NOT EXECUTED**.
No local PostgreSQL connection or migration was used during implementation.
The existing anonymous Voting implementation and its three migration revisions
are preserved. This adds infrastructure to execute the already reviewed harness.

## Job and confinement

[The workflow](../.github/workflows/voting-postgres-integration.yml) runs on pushes
to `feat/anonymous-voting-backend` or a manual dispatch of that same branch. It
uses a fresh `ubuntu-24.04` GitHub-hosted runner, `contents: read`, SHA-pinned
checkout/setup actions, Python 3.11.9 and Node 24.22.3. Checkout credentials are
not persisted. Required steps use Bash with `-euo pipefail`. No repository secrets,
services database, caches, artifact upload or continue-on-error are configured.

[The coordinator](../scripts/voting_postgres_ci.py) requires explicit
`--allow-ephemeral-ci-database`, hosted-Linux runner metadata and an absolute
runner temp directory before generating credentials or contacting Docker/PG.
It refuses inherited PG configuration and Docker endpoint overrides, uses only
the runner's local Docker socket, and accepts no database/host/password arguments.
The separate `--verify-dependencies` mode is entirely database-free.

It owns one unique container from the same immutable official PostgreSQL 18
image already pinned in RA Gate 2 CI:

```text
postgres:18-bookworm@sha256:ece55f7868da684e400f82f1030a050718adbdd65c23aa500c486f6e2950dc0f
```

The only exposed port is `127.0.0.1:<Docker-assigned-random-port> -> 5432`.
Both `/var/lib/postgresql` and `/run/evote-secrets` use tmpfs. There are no host
bind mounts or persistent database volumes. Inspection verifies the container
ID/name/ownership label/image, loopback binding, nonprivileged mode and tmpfs-only
mount configuration before supplying a password, and again before deleting it.

A generated bootstrap password is streamed through `docker exec --interactive`
stdin into a mode-0600 file owned by postgres inside container tmpfs. Atomic
rename releases the startup wrapper. No password value appears in CLI arguments,
Docker-config environment, host files, workflow outputs or logs. The standard
image's internal initialization still necessarily handles that password in its
isolated process memory. Runtime/fixture passwords are generated independently
and retained in Python `SecretStr` objects. SQL logging/parameter logging are
disabled and errors expose at most a validated SQLSTATE. Docker logs and fixtures
are never uploaded.

`finally` removes only the verified owned container; ordinary teardown failures
fail the job. Runner cancellation/VM failure may bypass Python cleanup, so the
fresh hosted runner and tmpfs lifetime are the final confinement boundary.

## Database and roles

Bootstrap may connect only to maintenance database `postgres` in this newly owned
container. Before provisioning it verifies PostgreSQL 18 and that only system
databases exist. It never connects to `ra_db` or `voting_db`.

It creates a fresh `voting_demo_test_ci_<random-hex>` database and independently
assigns comment `secure-evoting-disposable:<canonical-random-UUID>`. Every subsequent
connection to that database verifies BOTH name and comment before work. Initial
maintenance bootstrap necessarily precedes creation of that marker. All actual
migration, runtime, fixture, observation and cleanup connections retain the
existing harness's independent database guard.

Eight pre-existing-model groups are provisioned as restricted NOLOGIN roles:
`voting_owner`, `voting_admin_service`, `voting_ballot_service`,
`voting_snapshot_worker`, `voting_tally_worker`, `voting_publication_service`,
`voting_board_reader`, `voting_audit_reader`. None receive superuser, createdb,
createrole, replication or bypassrls attributes.

| Test login | Membership | Inheritance / switching | Connection limit |
|---|---|---|---|
| `voting_migrator_login` | `voting_owner` | NOINHERIT; membership INHERIT FALSE, SET TRUE | 4 |
| `voting_ballot_login` | `voting_ballot_service` | INHERIT; membership INHERIT TRUE, SET FALSE | 40 |

PUBLIC access to maintenance/test databases and the public schema is revoked.
Only these two logins get test-database CONNECT; schema `voting` belongs to
`voting_owner`. No runtime owner membership or table grant is added. Host
authentication must be SCRAM; an incorrect generated password must actually fail.
The server allows 80 connections for the 20-way HTTP test and fixture observers.
No RA schema, voter fixture or real election is used.

The actual chain is inspected before execution and must be exactly:

```text
643decaa90ab -> b5bd58a07ceb -> d8f27a4c610b
```

The schema must be empty. Alembic receives a guarded fixture connection and uses
only [the disposable environment](../scripts/ci_voting_migrations/env.py), sets the
owner locally and checks identity/search_path. It executes real revisions in a
transaction, with no stamping or copied table DDL. No production INI or secret
URL is discovered. Existing applied migrations are unchanged. The new revision's
role/effective-ACL preflight remains required and can fail the job.

## Existing real harness and small correction

The coordinator calls the actual
[integration main entrypoint](../scripts/voting_disposable_integration.py) with
the existing opt-in/database/marker/port arguments. An optional in-memory password
collector supplies fixture then runtime credentials. The CLI still defaults to
the same non-echoing getpass function; designation is checked before either
collector, and every connection/cleanup guard remains intact. No production
launcher or credential collection path is changed.

The lock-race observer now calls `pg_stat_clear_snapshot()` before each activity
poll without committing or releasing its election lock. PostgreSQL caches
current-session activity information within transactions; refreshing that cache
lets a poll observe newly connected blocked backends. See the
[PostgreSQL 18 statistics documentation](https://www.postgresql.org/docs/18/monitoring-stats.html#MONITORING-STATS-VIEWS).
A new database-free regression requires refresh on each poll and prohibits
commit/rollback during observation. This strengthens the race test rather than
relaxing its lock-wait assertion.

The unchanged harness assertions exercise:

* Full HTTP credential/manifest/envelope verification and real SQL acceptance.
* Invalid final signatures, wrong election/config/envelope and identity rejection.
* Twenty same-serial submissions: one 201, nineteen 409, one accepted row.
* Duplicate retry, independent encryption/serials for identical candidate choices.
* Real rollback leaving the serial unspent, then successful acceptance.
* Real COMMIT followed by injected response loss, receipt recovery and replay rejection.
* Independent Python/PostgreSQL receipt calculations.
* Closing-first and acceptance-first races with observed PostgreSQL lock waits.
* OPEN-but-expired and not-yet-open windows using DB time.
* PUBLIC, unrelated-worker and internal-helper EXECUTE denial; runtime table denial.
* Immutable policy UPDATE guards and fixture cleanup.

The coordinator also checks all nine application tables are empty before the
harness and identical after committed cleanup. This catches leftovers that an
uncommitted fixture cleanup assertion could miss. Any assertion or cleanup error
fails the job; the container is then removed. Private TEST keys are generated
only in memory by the existing fixtures. They test finalized verification, not
blind signing; Gate 1/Gate 2 remain separate reviewed interoperability evidence.
Synthetic rejection canaries are not RA sessions or real identities.

## Dependencies and exact Ubuntu commands

[The new Voting dependency entrypoint](../backend/voting/requirements.lock.txt)
includes the existing application and crypto locks, plus the same five database
pins already reviewed for RA. No existing lock or package version was changed:

```text
rfc8785==0.1.4                 cryptography==50.0.2
fastapi==0.162.4               psycopg==3.3.9
psycopg-binary==3.3.9          alembic==1.20.1
SQLAlchemy==2.1.8              Mako==1.4.3
```

The included locks pin all composed transitive packages. Installation uses
`--no-deps`; `pip check` rejects incomplete/inconsistent installation, and the
coordinator verifies the eight actual installed versions above. A regression
checks that the complete Voting dependency set equals the existing RA composition
and handles the unchanged root lock's UTF-16 BOM. These are version locks, not
hash-locked package artifacts; fresh Linux installation remains CI evidence.

Workflow run steps execute:

```bash
umask 077
python -m venv "$RUNNER_TEMP/voting-python"
"$RUNNER_TEMP/voting-python/bin/python" -m pip install --no-deps -r backend/voting/requirements.lock.txt
"$RUNNER_TEMP/voting-python/bin/python" -m pip check
"$RUNNER_TEMP/voting-python/bin/python" scripts/voting_postgres_ci.py --verify-dependencies
npm --prefix crypto_interop ci --ignore-scripts
npm --prefix crypto_interop run build

export EVOTE_TEST_NODE="$(command -v node)"
"$RUNNER_TEMP/voting-python/bin/python" -m pytest tests/ crypto_interop/ -q
node --test crypto_interop/dist/pending_state.test.js

"$RUNNER_TEMP/voting-python/bin/python" scripts/voting_postgres_ci.py --allow-ephemeral-ci-database

git diff --exit-code
git diff --check
```

## Validation and review gate

Final local results: **542 database-free pytest tests passed in 13.23 seconds**
(the prior 504 plus 38 CI safety regressions); **2 TypeScript recovery tests passed**.
The first full attempt exposed a missing temporary Node executable and the new
test parser's incorrect assumption that the root lock was UTF-8. The parser now
handles the existing BOM without changing the lock. The exact Node 24.22.3 tool
was restored outside the repository from the official archive, verified against
its published SHA-256; no security policy was changed. The final suite above
ran with that executable. Original tests and assertions were not weakened.

The local dependency verifier and `pip check` passed. Workflow YAML and every
run step's Bash syntax passed parsing; structural/security regressions check
branch scope, runner, permissions, immutable action refs, required tests and no
uploads/secrets/continue-on-error. No Docker/PostgreSQL test was run locally.

Relative to the previously reviewed implementation, this task adds the workflow,
coordinator, Voting dependency entrypoint, CI safety tests and this document;
it modifies only the disposable harness's injectable argument/password collector
and activity-cache refresh. Authentication, frozen crypto, applied migrations,
acceptance SQL, Voting APIs, Tally and UI remain unchanged.

After human review and publication of this branch, inspect the new workflow in
GitHub Actions. Its run must pass dependency installation, all regression tests,
real migration, real harness, committed cleanup and owned-container teardown.
Capture the run URL/commit and sanitized PASS output before declaring PostgreSQL
integration passed. A failing job remains FAIL; fix the cause and rerun without
weakening assertions. No current CI PASS or migration readiness is claimed here.

Remaining limitations: trusted Voting runtime cryptographic enforcement, encrypted
candidate validation deferred to Tally, timing/IP/metadata correlation, no browser
or real-RA-to-Voting integration in this job, and no forced server death during
COMMIT. See [the acceptance architecture report](17-anonymous-voting-backend.md).
