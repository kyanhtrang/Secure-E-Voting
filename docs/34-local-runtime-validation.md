# Phase 11B.1 — human-review and validation report

Inspected worktree: `Secure-E-Voting-local-runtime`, branch
`feat/guarded-local-runtime`, HEAD `bd15d7dd659208bb9a8df18806d32b2322da1666`.
Changes are uncommitted. Both pre-existing backup stashes are retained. No branch
switch, reset, clean, worktree removal, commit, push or merge was performed.

**Implemented code and offline regression evidence are delivered. New hosted CI
is NOT RUN. Local VM deployment is NOT RUN and is not approved by this report.**

## Review outcome and architecture

The new path composes existing RA/Voting/Admin/Tally/Publisher/Board services
through isolated local-profile connection factories and service-scoped private
configuration. It does not relax existing launchers or masquerade as hosted CI.
The trusted root controller holds setup/key custody capabilities; ten dedicated
non-root service accounts receive only their own private package. Live container
inspection is brokered over inherited private socketpairs. Runtime connections
check the exact generated destination, marker, owner, PG18, login, effective ACLs,
function signatures, SECURITY DEFINER owner and applied search path before use.

Two generated synthetic voters use the unchanged reviewed two-voter RPC SQL in a
test-only schema. Their HTTP sessions are independently bound to the process's
configured voter. The installer refuses existing/conflicting data, inserts active
explicitly, verifies ACLs transactionally, and rechecks rather than rewriting on
restart. Actual credential reservations/recovery continue through the reviewed
native CIRCL and PostgreSQL components; no new blind-signature implementation.

Encrypted, create-once software custody retains matching original RSA keys,
three independent Ed25519 authorities, RA recovery data, separate DB credentials
and synthetic password verifiers. Runtime receives no bootstrap/migrator secret.
Named volumes/evidence survive stops; no local destructive cleanup API exists.
Owned-process records precede readiness; pidfds protect stop against PID reuse.
Readiness checks actual socket ownership, and startup/stop failures preserve
unknown resources for review. See [architecture, exact configuration, future
approved commands and trust boundaries](./33-guarded-local-runtime.md).

Source inspection also caught a setup compatibility issue before CI: the old
baselines use unqualified CREATE TABLE. The **new** migration environment now
matches their existing reviewed schema-first creation context and verifies the
current schema. No applied migration or pg_catalog-first SECURITY DEFINER path
was changed. Regression coverage checks actual signatures/search paths against
the applied source, including the existing distinct per-function paths.

## Actual validation on this checkout

| Check | Result and limits |
|---|---|
| Complete `pytest tests/ crypto_interop/ -q` | **1,157 passed, 2 skipped**. Existing tests/assertions unchanged. Skips are Linux-only actual pidfd/listener identity tests on Windows. |
| Focused new guard suite | **71 passed, 2 skipped**; included in the complete count, not added to it. SQL doubles are not live database evidence. |
| Frontend unit/component/crypto | **167 passed**, 12 files. |
| Existing authentication / voting / Admin / Tally / Board browsers | **7 / 7 / 4 / 2 / 3 passed** (23 total). Existing synthetic-service browser suites on Windows Edge, not real PG/CIRCL deployment. |
| Frontend TypeScript + production Vite build | **PASS**; existing blindrsa browser-externalization notice remains. |
| Crypto TypeScript build and pending-state recovery | **PASS**, 2 recovery tests. |
| Dependency integrity | Both npm locked installs with ignore-scripts, both complete npm trees, pip check and existing reviewed backend version assertions **PASS**. No lock edits. |
| Syntax | **184 Python**, **8 JSON**, **13 YAML**, **84 Bash scripts/workflow bodies** parsed. This is static parsing, not GitHub execution or SQL-engine validation. |
| SQL contracts / migration graph | Offline signature/search_path/CASE guard regressions **PASS**. RA head bf932d0f8702 / 15 revisions; Voting/Board head f8b31c2d970a / 6 revisions. No upgrade executed. |
| Standard-library public-plan preflight | **PASS**, OFFLINE_VALIDATED_NOT_DEPLOYED, execution_ready=false. Reviewed base/source fingerprint refreshed; synthetic IDs unchanged in the example. |
| Changed-source secret patterns and manual data flow | **PASS**; no embedded credentials, private-key bodies or bearer values found. This is not an exhaustive secret-detection guarantee. |
| Whitespace / conflicts | `git diff --check` and explicit new-file whitespace checks **PASS**; no unresolved index entries. |
| New native Go build/tests | **NOT RUN locally**; Go is unavailable on the current tool path. Pinned native build/tests are in the new Ubuntu job. |
| New disposable PostgreSQL gate | **NOT RUN**; requires human-reviewed publication and actual GitHub execution. |
| VM / SSH / Docker / real local runtime / database migrations | **NOT RUN**. No user DB or production key/credential access. |

Local toolchain: Python3.11.9, Node24.22.3, npm11.19.1. Windows regression imports
used the existing supported PSYCOPG_IMPL=python / installed libpq18 path; loading
the client library does not connect to PostgreSQL or change Application Control.
The first frontend attempt selected system Python (missing rfc8785), and the
first browser attempt omitted that libpq configuration. Both were rerun using the
project environment and passed; no test assertion or application code was changed
to suppress those environment failures.

## Complete changed-file inventory (19 files)

| File | Change |
|---|---|
| [Public policy](../deployment/local_demo_policy.py) | Updated reviewed base and bound new runtime/CI sources into the existing strict public fingerprint. |
| [Public example plan](../deployment/evote-local-demo-plan.json) | Refreshed base/source digest only; remains review-only, not deployment authority. |
| [Database adapters](../deployment/local_runtime_database.py) | New per-connection identity/role/effective-ACL checks; no privileged login/DSN/discovery. |
| [VM/container boundary](../deployment/local_runtime_boundary.py) | New live guest/raw Docker checks, independent approval, fixed PG command, pinned SSH argv construction. |
| [Container lifecycle](../deployment/local_runtime_containers.py) | New explicit creation/start/stop, persistent named storage and owned journals; no removal path. |
| [Custody](../deployment/local_runtime_custody.py) | New encrypted create-once storage and service capability projection. |
| [Two voters](../deployment/local_runtime_voters.py) | New separately authorized local installer reusing reviewed RPC DDL. |
| [Trusted setup](../deployment/local_runtime_setup.py) | New fresh-cluster roles/DBs and explicit synthetic operator/Publisher enrollment. |
| [Migration driver](../deployment/local_runtime_migrations.py) | New injected setup-only guarded migration adapter. |
| [Migration environment](../deployment/local_migrations/env.py) | New strict no-URL/no-offline environment using unchanged migration history. |
| [Application composition](../deployment/local_runtime_apps.py) | New existing-service composition with exact scoped material and frozen key binding. |
| [Worker](../deployment/local_runtime_worker.py) | New private pipe configuration, loopback readiness, signal cleanup, no Docker access. |
| [Process manager](../deployment/local_runtime_processes.py) | New dedicated UID checks, root-owned code/binary provenance, private ownership broker and pidfd stop. |
| [Operator controller](../scripts/local_demo_runtime.py) | New explicit approved actions, locking, eligibility binding, immutable public-pin export and read-only evidence mirror. |
| [Disposable CI coordinator](../scripts/guarded_local_runtime_ci.py) | New hosted-only real PG18/local-profile factory/two-voter/native issuance contract gate. |
| [Guarded runtime workflow](../.github/workflows/guarded-local-runtime.yml) | New exact feature-branch push plus manual dispatch, pinned tools/actions, contents:read, no secrets/artifacts. |
| [Focused regressions](../tests/test_guarded_local_runtime.py) | New offline mutation, boundary, private config, lifecycle, key and schema contract tests; Linux-only live OS tests. |
| [Startup/security guide](./33-guarded-local-runtime.md) | New architecture, public/private config, guarded journey and outstanding VM prerequisites. |
| [This report](./34-local-runtime-validation.md) | New measured validation, full inventory and review gate. |

Existing backend/frontend/crypto implementation, production/demo launchers,
hosted coordinators/workflows, all dependency locks and all applied migrations are
unchanged. The new local modules can execute only on explicit later invocation;
imports and the original offline CLI do not provision or start a deployment.

## Security traceability delta

| Control | Status and evidence scope |
|---|---|
| Strict generated local DB identity / role confusion rejection | IMPLEMENTED; offline mutation tests pass; real new PG job pending. |
| Effective ACLs / exact RPC metadata / mixed relation types | IMPLEMENTED; offline contract tests pass; real PG semantics pending new job. |
| Local two-voter install / exact restart / no eligibility reset | IMPLEMENTED; offline guards pass; new real two-voter issuance gate pending. |
| Scoped credentials, no runtime owner/migrator access | IMPLEMENTED; offline package/dataflow checks pass; VM filesystem/UID evidence pending. |
| Key/recovery custody, wrong-key rejection | IMPLEMENTED; generated-test-key encryption/scope tests pass; actual deployment ceremony NOT RUN. |
| Process ownership / partial startup / reverse stop | IMPLEMENTED; offline fault tests pass; actual Linux OS tests pending CI, full VM stop/restart untested. |
| Non-destructive local storage | IMPLEMENTED; no local deletion API; named volume retention needs actual VM validation. |
| Host identity/shares/SSH/forwarding | PARTIAL; guest checks/strict SSH args implemented; independent live Windows/hypervisor inspection and key ceremony MISSING. |
| Public pin distribution / evidence sharing | IMPLEMENTED; immutable public-only export and root-controlled read-only mirror; actual separated-account publication pending VM rehearsal. |
| TLS/HSM/zeroization/coercion resistance/full E2E proof | MISSING; not claimed by this demo. |

## Remaining approval and verification gates

1. Review root controller, custody format, privileged setup, live Docker projection,
   process/broker handling and read-only evidence mirror. The acknowledgement in
   the public contract is not proof of host isolation.
2. Human-reviewed commit/push may trigger the dedicated Ubuntu job. No such action
   was performed. Require actual native Go, PG18 migration/ACL/auth/issuance/recovery
   and owned teardown PASS before considering that evidence established.
3. Separately approve/build the dedicated VM/accounts/root-owned toolchain, inspect
   host-only/NAT exposure and no shares/host DB forwards, create dedicated SSH keys,
   verify host fingerprint independently and capture current VM IDs. No personal
   SSH agent/key/config discovery is used by the provided argv builder, but key
   freshness, Windows ACLs and hypervisor integrity are not automatically proven.
4. Separately approve the explicit local key/container/bootstrap/migration/fixture
   operations. Use only the generated profile targets. Never point at ra_db or
   voting_db; never copy user secrets or production keys into this profile.
5. Rehearse real startup, two browser voters, Tally A=1/B=1, publication, verification,
   stop and restart in the actual approved VM. Retain all original custody, volumes,
   tombstones, receipts/evidence and journals. Slow/orphaned/mismatched processes or
   partial setup require review, not automatic killing/deletion/reset.

Residual boundaries: the root operator and compromised RA authentication runtime
are trusted; A/B share reviewed RA SQL capabilities/signing material while HTTP
binding separates their sessions. The single profile is one synthetic election,
not production identity proofing, full anonymity or complete E2E tally correctness.
No results are published by this implementation work. **Stop for human review.**
