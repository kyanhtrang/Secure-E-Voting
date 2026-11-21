# Complete election real-service gate: human review

Branch `test/full-election-e2e`, base `7dcdc60`. This change composes the reviewed
two-voter/Tally journey with the real Publisher and Public Board, ending at
PUBLISHED. Run 1 reached PUBLISHED and passed public verification/immutability,
then failed at `board_acl`. The targeted correction below has **not** run on
Ubuntu Actions. Local regression results are not a complete real-service PASS.

## Run 1 board_acl correction: review against 65c7288

The defect is in the combined test's role model, not an established excess
database privilege. Its blanket assertion required every runtime role to have
NOINHERIT and no memberships. The unchanged trusted
[Voting provisioning](../scripts/voting_postgres_ci.py) explicitly creates
`voting_ballot_login` with INHERIT and grants exactly `voting_ballot_service`
WITH INHERIT TRUE, SET FALSE (ADMIN defaults false). The unchanged
[Voting migration](../migrations/voting/versions/d8f27a4c610b_anonymous_ballot_acceptance.py)
grants that capability role only the reviewed Voting schema USAGE and three
ballot RPC EXECUTEs, with no direct table access. The original combined role
predicate necessarily rejects this intentionally provisioned login.

The passing standalone [Board gate](../scripts/board_postgres_ci.py) checks the
same Board execution surfaces and forbidden SQL but does not impose the erroneous
blanket NOINHERIT/no-membership condition. Admin, Tally, Board and Publisher logins
are separately provisioned NOINHERIT with no memberships; they retain that strict
policy. Source proves the combined assertion is incompatible with provisioning.
Run 1 did not identify its individual failing assertion, so the correction does
not claim all subsequent checks have passed or exclude an additional later fault.

The replacement role assertion checks the exact expected session role, LOGIN,
absence of all elevated flags, and the appropriate INHERIT flag. Only
`voting_ballot_login` may have the single expected parent edge, with ADMIN=false,
INHERIT=true, SET=false. Extra incoming/outgoing edges, duplicate grants, another
parent or changed membership options fail. The inherited service role must remain
NOLOGIN/NOINHERIT/non-elevated, have no parents, and have no other members. No
permissions, provisioning SQL, applied migration or production code changes.

All existing CREATE, exact Board EXECUTE, SQLSTATE-42501 direct denial, PUBLIC
grant, eight-function owner/SECURITY DEFINER/search_path and exact publication
audit actor assertions remain strict. In particular, no permissive proconfig
normalization was introduced: the exact per-function array must still match the
unchanged migration. Formatting or other discrepancies will fail under their own
fixed identifier. Source comparison confirms every non-role ACL query and every
forbidden SQL probe is unchanged. Diagnostic contexts annotate and rethrow the
same exception; they issue no SQL, change no transactions, and retain the most
specific nested check if a connection boundary also observes the exception.

Only these fixed identifiers can enter ACL diagnostics:

```text
board_acl_role_attributes
board_acl_schema_create
board_acl_function_execute
board_acl_direct_sql
board_acl_public_grants
board_acl_function_metadata
board_acl_audit_actor
```

Failures contain fixed stage/check, assertion_error or database_error, and only
an explicitly allowlisted SQLSTATE (otherwise unavailable). No SQL, result rows,
parameters, response bodies, exception messages, tracebacks or HTTP status are
included in these ACL diagnostics. Example:

```text
FAIL: full_election_e2e stage=board_acl check=board_acl_role_attributes category=assertion_error sqlstate=unavailable
FAIL: full_election_e2e stage=board_acl check=board_acl_direct_sql category=database_error sqlstate=25006
```

The second example is a **failed test**, not an accepted ACL denial: only the
unchanged strict deny helper's InsufficientPrivilege/42501 outcome succeeds.
An unauthorized SQL success, unexpected database exception or other exception
still fails. The new catalogue-projection unit tests run the actual assertions
and strict deny helper, mutate each security property, and verify rejection and
sanitized diagnostics. They do not execute PostgreSQL or establish actual ACLs.

Current validation on this corrected checkout:

| Check | Actual result |
|---|---|
| Full backend/crypto pytest | 1,002 passed, including 55 new ACL regressions. |
| Frontend unit/component/crypto | 108 passed. |
| Existing authentication / voting / Admin / Tally / Board browser suites | 7 / 7 / 2 / 2 / 3 passed (21 total), synthetic services. |
| Frontend TypeScript checks and production build | PASS. |
| Crypto TypeScript build / recovery tests | PASS / 2 passed. |
| Dependency checks | pip check, reviewed Python versions, both locked npm trees PASS; no lock changes. |
| Syntax and migration graphs | 163 Python, 7 JSON, 10 YAML, 67 Bash bodies/scripts PASS; unchanged RA 15 and Voting/Board 6 revisions. |
| Offline PostgreSQL SQL syntax | All three corrected role SELECTs and 125 unchanged migration literals parsed with pglast 8.9; no execution or application namespace/type resolution. |
| Non-role SQL / standalone gates / protected sources | Unchanged versus reviewed HEAD. |
| Changed-source secret scan / git diff --check | PASS. |
| Corrected live combined gate / standalone PG gates locally | NOT RUN; no local PostgreSQL access. |

Windows browser runs used the existing Edge configuration; Ubuntu uses Chromium.
The existing Vite blindrsa browser-externalization notice remains. No dependency,
browser fixture or frontend source changes were needed.

Changed-file inventory for this correction (three files):

- [Combined coordinator](../scripts/full_election_e2e.py): narrow role model fix and diagnostics.
- [New ACL regressions](../tests/test_full_election_acl.py).
- [This updated review report](./29-full-election-e2e.md).

The existing standalone Board and Tally coordinators/tests, workflow, migration
history, production services, original regression assertions and dependency locks
are unchanged. The user's evidence establishes standalone Board PASS in Run 1;
that is prior CI evidence, not a new local execution. The same workflow retains
both standalone gates before the combined journey.

A human-approved push of this patch to `test/full-election-e2e` triggers the
unchanged Ubuntu workflow. Rerunning an old run without publishing the correction
tests the old commit. The next run must pass `board_acl`, then original browser
receipt recovery, remaining lifecycle ACL/audit checks and verified owned cleanup.
Expected success tail is `checkpoint=board_acl`, `checkpoint=receipts`,
`checkpoint=acl`, and the existing/final `checkpoint=cleanup` lines. Any failure
inside the seven ACL groups now identifies the exact group without sensitive
data. Live membership projections, proconfig representation and all later checks
remain pending that run. No commit, push, merge, database connection, migration,
real-credential/production-private-key access or stash removal was performed
during this fix. Unit/crypto tests use generated test material only.

## Architecture and key custody

```text
Coordinator -> Admin HTTP -> voting_admin_login -> owned Voting PostgreSQL 18
                         -> ra_election_publisher_login -> owned RA PostgreSQL 18
Chromium A/B -> separate Vite/RA processes -> ra_auth_login / ra_issuance_login
                                        -> native Go CIRCL BlindSign
Chromium A/B -> anonymous Voting HTTP -> voting_ballot_login -> Voting PG18
Separate Tally operator -> Tally HTTP -> voting_tally_login -> committed evidence
Enrolled Publisher -> publication HTTP -> voting_publication_login -> PUBLISHED
Anonymous auditor -> Board HTTP -> voting_board_login -> immutable public bundle
Offline verifier -> explicitly provisioned public pins -> evidence + both receipts
```

The [coordinator](../scripts/full_election_e2e.py) imports and calls the existing
[real two-voter/Tally journey](../scripts/voting_tally_e2e.py). Four narrow optional
composition hooks provision Board, start publication services, reject voter
credentials, and publish after all original Tally assertions. The default journey
has `publication=None`; all previous assertions and CLI behavior are preserved.
Original browser contexts wait until publication completes before proving their
original receipts recover identically and duplicate voting still returns 409.

No accepted ballot is inserted by a privileged fixture in the complete journey.
Both ballots traverse browser AES-256-GCM / RSA-OAEP-SHA256 encryption, frozen v2
RSABSSA Prepare/Blind, authenticated durable RA issuance, original blinded bytes
to native CIRCL, browser Finalize/verification, and anonymous Voting acceptance.
Two distinct voters use independently bound real PostgreSQL sessions. The
existing hosted-only two-subject authentication schema and its cross-voter,
third-identity, expired/revoked-session and ACL assertions remain in use. Applied
single-subject demo SQL is unchanged.

The trusted coordinator generates all synthetic test keys. The original RA and
Tally RSA-3072 keys remain matched to the signed public configuration throughout
the journey; no replacement occurs after encryption. Three independent Ed25519
authorities are pinned: manifest, snapshot/report, and publication. Only Admin
receives the manifest private key; only RA its RSA key and native signer; only
Tally its RSA key and snapshot/report key; only Publisher the publication key.
Private keys are encrypted PKCS8, mode 0600, under a mode-0700 runner-temp
directory outside the checkout. Unlocks/configuration travel through bounded
private stdin pipes, never argv or environment. Board child schemas reject keys,
evidence directories and cross-service credentials. Board receives only its own
restricted database password and public pins. These are separate processes under
one trusted runner user, not OS sandboxing or production key isolation.

## Real APIs and scenario matrix

Admin operations use the existing `/api/v1/admin/auth/*` and election APIs:
draft, candidates, window, approved keyset, finalize, open, close and audit. Voters
use the existing RA authentication/catalogue/issuance and anonymous Voting
acceptance/receipt-recovery contracts. Tally uses its separate operator login,
`/api/v1/tally/elections/{id}/run` and `/report` endpoints.

Publisher authentication deliberately reuses a separately issued real Admin
session, with **additional active `voting_board.publishers` enrollment**. It does
not introduce a fake Publisher login or accept Tally/Voter tokens. Publication is
`POST /api/v1/publication/elections/{id}/publish`, body exactly `{}`. Board uses
the existing read-only `/api/v1/board` catalogue, election evidence, configuration,
results, ballot pages, receipt and final-snapshot endpoints. The gate verifies
their actual responses; it adds no application endpoints or protocol fields.

| Scenario | Required live assertion |
|---|---|
| Admin configuration | Real HTTP draft, two candidates, signed finalization; post-finalization edits denied. |
| Interrupted OPEN/CLOSE | Existing permission-fault tests prove reconciliation failure stays unready and Tally cannot run; exact retry reconciles. |
| Separate identities | Both RA `/me` identities match distinct synthetic UUIDs; cross-voter substitution, third subject, revoked/expired sessions fail. |
| Voter A and B | Separate Chromium contexts cast candidate A/B; each HTTP 201 matches one committed receipt and its own RA issuance/reservation. |
| Premature publication | Enrolled Publisher receives 409 while OPEN; public results remain 404. |
| Publication authorization | Real unenrolled Admin session gets 403; Tally and each Voter session get 401. |
| Tally | OPEN denied; reconciled CLOSED succeeds; accepted=valid=counted=2, invalid=0, A=1/B=1. Snapshot/report signatures, digests, committed rows, idempotency and wrong manifest authority rejection remain checked. |
| Missing/tampered original evidence | Temporarily hidden snapshot and modified temporary file each produce 503 and no publication/audit row; exact original bytes restored in `finally`. |
| Uncommitted publication | Restricted real `finish` SQL executes inside an uncommitted transaction; separate Board HTTP still sees 404. Rollback leaves TALLIED and zero publication/audit rows. |
| Publication contention | Four concurrent real HTTP requests return identical evidence; retry unchanged; exactly one publication and one immutable publication audit. |
| Public verification | Real Board bundle equals committed expected bytes; exact signed Tally, snapshot, configuration and A/B receipts; deterministic two-page pagination. |
| Independent verifier | Existing offline CLI runs in separate Python processes with coordinator-provisioned pins and both real receipts; both return VERIFIED. |
| Negative verification | Modified snapshot/signatures, missing publication, wrong election and each wrong authority pin fail offline verification. Unknown receipt is NOT_FOUND after full verification, HTTP receipt lookup 404. |
| Public privacy/mutation | Exact public record field allowlist, no synthetic identities/passwords/tokens; POST/PUT/PATCH/DELETE return 405; identity-bearing Board request rejected 400. No decrypted selections are published. |
| Immutable publication | Conflicting `finish` rejects P6403; state rollback rejects P6403; publication/audit mutation P6405; snapshot/report mutation P5303. Retry digest remains unchanged. |
| ACLs | Exact Board RPC scopes, no PUBLIC EXECUTE, owner/fixed search_path checks, direct table access/delete and owner escalation denied with 42501 for Board/Publisher/Admin/Tally/Voting. All original RA/Admin/Voting/Tally ACL assertions still run. |
| Final state/recovery | Voting and Admin control both PUBLISHED and ra_ready=true; original receipt recovery remains successful, duplicate 409, exactly two accepted ballots; original lifecycle audit plus Publisher ADMIN actor checked. |
| Cleanup | Child shutdown, native signer shutdown, private files removed, both exact owned container IDs absent; immutable fixture rows disappear with owned disposable clusters. |

Evidence-negative tests mutate temporary copies or restore exact temporary file
bytes. They never alter committed snapshot/report/publication rows successfully.
The direct SQL rollback/conflict probes supplement real HTTP publication rather
than substituting for it. Existing standalone Tally classification/fencing and
publication component PostgreSQL gates also execute before the complete journey;
their seeded component fixtures are separate clusters, not substitutes for its
two browser votes.

## Disposable migrations and ACL review

No new migration or applied migration edits. Existing guarded environments apply:

- RA baseline 14 revisions through `c84e13b9702d`, then Admin RA `bf932d0f8702`.
- Voting `643decaa90ab -> b5bd58a07ceb -> d8f27a4c610b`, Admin Voting
  `af821c9e7601`, Tally `e6a90c72b541`, Board `f8b31c2d970a` (six revisions).

Board roles are provisioned by existing trusted test setup **after** Tally
migration and **before** Board migration: `voting_publication_login` and
`voting_board_login`, NOINHERIT LOGIN, no elevated flags or memberships. Board
preflight rejects unsafe inherited/effective privileges and any existing
publication/PUBLISHED records. It applies only inside this newly owned cluster.
The gate does not revise these preconditions or change grants to make tests pass.

Every runtime connection uses the existing owned-container verification and
guarded connection wrapper: generated name (`ra_demo_test_ci_*` or
`voting_demo_test_ci_*`), independent UUID comment marker, exact database owner,
session/current role and PostgreSQL 18. The digest-pinned official PG18 containers
use tmpfs data, random loopback-only port mappings, SCRAM, no persistent host
volume and exact owned name/ID/label/image checks. CLI accepts no database names,
ports, URLs or passwords. Inherited PG/remote Docker/service configuration is
refused. No local or production database is accessed.

Existing Board functions remain `SECURITY DEFINER`, owned by `voting_owner`, with
per-function fixed pg_catalog-first, pg_temp-last search paths. Publisher can
execute only `publication_input(bytea,uuid) -> jsonb` and
`finish(bytea,uuid,bytea,bytea,bytea) -> bytea`; Board only
`read_public(uuid) -> bytea` and `catalogue(uuid,integer) -> jsonb`. No runtime
table grants or RA connection are introduced. PUBLIC EXECUTE remains revoked.
New live assertions compare all eight actual Board function owners, security
flags and exact search paths against the unchanged migration.

Publication authorizes active Admin session/principal/enrollment, locks the
election, verifies committed successful Tally/snapshot/configuration consistency,
and atomically commits publication bytes, public bundle, terminal lifecycle and
audit. Publisher independently verifies signatures before invoking restricted
`finish`; success returns only after its connection context commits. Concurrent
publication is serialized by the election lock and existing unique election
publication constraint. No cross-database atomicity is claimed: earlier Admin
OPEN/CLOSE reconciliation and fail-closed readiness checks remain authoritative.

## CI and exact startup

[The separate workflow](../.github/workflows/full-election-e2e.yml) triggers only
on pushes to `test/full-election-e2e`, plus input-free `workflow_dispatch` for
future manual runs. It is ubuntu-24.04, contents:read, SHA-pinned Actions,
Node 24.22.3, Go 1.25.14 and Python 3.11.9. Existing workflow files are untouched.
Locked installs use the existing Voting Python lock and both npm locks, followed
by dependency checks; no lock changes. All required failures stop CI. There are
no repository secrets, continue-on-error, private artifact uploads, traces or
screenshots. No new screenshots are captured, avoiding secret-bearing browser
artifacts. Only allowlisted checkpoints/category/SQLSTATE/HTTP-status diagnostics
are emitted; arbitrary exception text and subprocess stderr are suppressed.

Workflow order: locked dependencies; native Go tests/runtime build; official RFC
vectors and original TS->Go->TS->Python RSA3072 gate; full pytest and recovery;
frontend tests/check/build and all five browser suites; standalone real Tally and
Board security gates; complete election; source integrity and always-run binary
cleanup. Coordinator contexts remove services/private directories/owned containers
on failures; abrupt runner loss relies on disposal of the hosted environment.

The new real journey entrypoint, **only on its owned hosted runner**, is:

```bash
"$EVOTE_TEST_PYTHON" scripts/full_election_e2e.py \
  --allow-ephemeral-ci-databases \
  --node "$(command -v node)" \
  --signer-binary "$RUNNER_TEMP/admin-voter-circl-signer"
```

Services are started by the coordinator over private pipes with input-free
loopback origins; no operator password commands or production-launcher overrides
are required. Do not invoke this against a manually selected cluster.

Expected successful-run checkpoints (reference output; Run 1 evidence and the
still-pending tail are distinguished in the correction review above):

```text
PASS: full_election_e2e checkpoint=publication_migration
PASS: voting_tally_e2e checkpoint=migrations
PASS: voting_tally_e2e checkpoint=open_tally_denied
PASS: full_election_e2e checkpoint=publisher_authorization
PASS: voting_tally_e2e checkpoint=voter_a_authenticated
PASS: voting_tally_e2e checkpoint=accepted_first
PASS: voting_tally_e2e checkpoint=voter_b_authenticated
PASS: voting_tally_e2e checkpoint=accepted_second
PASS: voting_tally_e2e checkpoint=close_interrupted
PASS: voting_tally_e2e checkpoint=close_reconciled
PASS: voting_tally_e2e checkpoint=tally
PASS: voting_tally_e2e checkpoint=evidence
PASS: voting_tally_e2e checkpoint=idempotency
PASS: voting_tally_e2e checkpoint=configuration_rejected
PASS: full_election_e2e checkpoint=publication_evidence
PASS: full_election_e2e checkpoint=publication_rollback
PASS: full_election_e2e checkpoint=publication_concurrent
PASS: full_election_e2e checkpoint=public_verification
PASS: full_election_e2e checkpoint=publication_immutable
PASS: full_election_e2e checkpoint=board_acl
PASS: voting_tally_e2e checkpoint=receipts
PASS: voting_tally_e2e checkpoint=acl
PASS: voting_tally_e2e checkpoint=cleanup
PASS: full_election_e2e checkpoint=cleanup
```

Example failure: `FAIL: full_election_e2e stage=publication_concurrent
category=assertion_error sqlstate=unavailable http_status=503`. Status is included
only when known and allowlisted. No raw exception, SQL, parameters or payload.

## Actual validation and changed files

Original pre-publication validation (before Run 1; superseded for this correction
by the current results above), executed on the combined Windows checkout:

| Validation | Actual result |
|---|---|
| Complete backend/crypto pytest | 947 passed; includes 26 new full-gate regressions. |
| Frontend unit/component/crypto | 108 passed, 10 files. |
| Browser authentication / voting / Admin / Tally / Board | 7 / 7 / 2 / 2 / 3 passed (21 total); existing synthetic-service suites. |
| TypeScript credential recovery | 2 passed. |
| Frontend TypeScript checks + production build | PASS. |
| Crypto TypeScript build | PASS. |
| Locked npm installs and full dependency trees | PASS; npm audit reported zero vulnerabilities for both installs; locks unchanged. |
| Python dependency integrity | pip check PASS; rfc8785 0.1.4, psycopg/psycopg-binary 3.3.9, cryptography 50.0.2, FastAPI 0.162.4, Alembic 1.20.1, SQLAlchemy 2.1.8, Mako 1.4.3 match reviewed pins. |
| Source syntax | 162 Python, 7 JSON, 10 YAML files; 67 Bash workflow/script bodies parsed; real browser driver JavaScript syntax PASS. |
| Migration graphs | RA head bf932d0f8702 (15); Voting/Board head f8b31c2d970a (6), PASS offline. |
| Offline PostgreSQL parser | 125 literal SQL statements parsed with pglast 8.9; not executed. |
| Changed-source secret scan/manual data-flow review and diff whitespace | PASS; no detected embedded secrets; five changed source/report files. |
| Native Go tests/build and RFC TS/Go/Python gate locally | NOT RUN: Go unavailable on local PATH; required in Ubuntu workflow. |
| New complete real PostgreSQL/Chromium/CIRCL/Publisher journey | NOT RUN; awaiting human-reviewed push and Ubuntu Actions. |

The first frontend run reported 106 passes/two cross-language import failures:
the system Python lacked rfc8785. Rerunning with `EVOTE_TEST_PYTHON` pointing at
the project venv passed all 108 without source/test changes. The workflow exports
that variable from its locked venv through GITHUB_ENV. Local browsers used the
existing Windows Edge setting; the new Ubuntu job installs real Chromium.
Python used the supported PSYCOPG_IMPL=python/libpq18 import path because Windows
Application Control blocks the bundled psycopg DLL. No security setting changed,
and loading libpq did not connect to PostgreSQL. Vite emits the existing blindrsa
`crypto` browser-externalization notice; all browser and crypto checks above pass.

An attempted offline PL/pgSQL semantic parse reported the parser's unsupported
application namespace lookup. It is not a PostgreSQL execution result. SQL syntax
parsing, graph checks and function/search-path comparison pass; application type,
ACL, transaction and PL/pgSQL resolution require the live disposable CI run.

Changed files (five):

- [New coordinator](../scripts/full_election_e2e.py).
- [Optional composition hooks in the existing coordinator](../scripts/voting_tally_e2e.py).
- [Dedicated scoped workflow](../.github/workflows/full-election-e2e.yml).
- [Database-free safety/contract/verification regressions](../tests/test_full_election_e2e.py).
- [This human-review report](./29-full-election-e2e.md).

## Limitations and approval boundary

PUBLISHED proves a committed signed evidence chain and receipt inclusion under
explicitly trusted authorities. It does not prove individual decryption correctness,
prevent malicious-authority equivocation, supply zero-knowledge tally proofs,
coercion resistance, full anonymity or complete end-to-end verifiability. Public
serials/proofs/encrypted envelopes are required by existing receipt/snapshot
recomputation and can be correlated with external metadata; later Tally-key
compromise can expose archived ciphertext. A small two-voter election is a
synthetic functional test, not a privacy demonstration.

Admin, Publisher and Tally use real HTTP APIs; the Voter UI uses real Chromium.
This is not new Admin/Publisher/Public-UI browser E2E coverage; existing synthetic
browser suites remain separately identified. The independent offline verifier
reuses reviewed verification primitives and external pins, not an independently
authored cryptographic implementation. No decryption keys or individual plaintext
are published. The same-user runner and loopback HTTP are local-demo boundaries.

Run 1 exercised real migration resolution, inter-service authorization, both
browser acceptances, Tally, concurrent publication/rollback and public evidence
verification, according to the supplied CI checkpoints. It did not pass the
complete gate: corrected ACL assertions, final PUBLISHED browser recovery,
remaining checks and verified teardown still require the next Ubuntu run.
No local PostgreSQL connection, migration execution, production key access,
commit/push/merge or stash/worktree deletion was performed during this correction.
Stop for human review before publishing this patch.
