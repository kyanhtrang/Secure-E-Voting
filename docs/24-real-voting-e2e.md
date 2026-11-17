# Real browser / RA / CIRCL / Voting / PostgreSQL gate

Status: implemented for human review; **the new real-service gate has NOT RUN**.
Do not treat the existing synthetic browser tests or the database-free safety
tests as evidence that this combined journey passed. The first Ubuntu run is
required before making that claim.

## Architecture and isolation

The separately named [workflow](../.github/workflows/real-voting-e2e.yml) runs on
a fresh GitHub-hosted Ubuntu 24.04 runner. It preserves the existing crypto, RA,
Voting PostgreSQL and web workflows. No repository secrets are referenced.
Automatic execution is restricted to pushes to `feat/voter-voting-ui`; there
are no PR, tag, path or broad branch triggers. `workflow_dispatch` is retained
without target/credential inputs for future manual execution.

```text
Playwright Chromium -> real Vite local proxy -> real FastAPI RA
                                                | ra_auth_login: auth/session functions
                                                | ra_issuance_login: issuance functions
                                                +-> LocalCIRCLSigner -> native Go CIRCL
Playwright Chromium -> separate anonymous proxy -> real FastAPI Voting
                                                | voting_ballot_login
                 owned RA PostgreSQL 18 <--------+ (RA connections only)
                 owned Voting PostgreSQL 18 <----+ (Voting connections only)
```

The [coordinator](../scripts/real_voting_e2e.py) creates **two** fresh owned
containers, each with one independently named/marked test database. Reusing the
reviewed Voting CI container implementation gives both clusters tmpfs data and
bootstrap-password storage, no persistent host volume, immutable image digest,
random loopback-only published ports, SCRAM and verified container ownership.
RA names start `ra_demo_test_ci_`; Voting names start `voting_demo_test_ci_`.
Each gets a distinct UUID database comment marker. Neither `ra_db` nor
`voting_db` is a permitted target. PostgreSQL maintenance connections are confined
to these newly owned containers.

Existing trusted RA/Voting provisioning and guarded Alembic environments are
reused unchanged. The actual 14-revision RA chain ends at `c84e13b9702d`, including
`7b2d91a6c840`. The actual Voting chain is
`643decaa90ab -> b5bd58a07ceb -> d8f27a4c610b`. No revision is stamped, skipped,
edited or applied to an operator database.

After provisioning, ownership is checked before migrations. Every fixture and
runtime connection verifies its generated database name, UUID marker, expected
database owner, session/current role and PostgreSQL 18 version. Existing factories
also repeat their disposable designation checks. Hosted-Linux checks reject local
execution, inherited PostgreSQL/Docker targets and inherited demo/Vite settings.
The coordinator accepts no database destination, password or key-file argument.

## Runtime composition and secrets

The production launchers retain their fixed ports/database names and all safety
checks. This CI harness uses existing explicit dependency injection instead:

- `create_credential_app(..., auth_connection_factory=..., catalogue=...)` with
  the real PostgreSQL authentication/session adapters and restricted issuance store.
- The unchanged `CredentialIssuanceService`, protected server recovery and
  `LocalCIRCLSigner`, invoking the built Go CIRCL runtime executable.
- `create_voting_app(BallotService(PostgreSQLBallotStore(...), pin))`.
- Real Uvicorn listeners on distinct random loopback ports, without proxy-header
  trust or access logging. The unchanged Vite config preserves Host/Origin and
  rejects identity headers/cookies on its anonymous proxy paths.

RA and Voting run in separate fresh Python interpreters. Each receives a strict
role-specific configuration through private stdin. Voting receives only its own
database target/password and the public authority pin: RA authentication data,
issuance credentials, signing key file/passphrase and signer handle are absent
from its process. There is no shared service address space or fixture connection.
The privileged parent coordinator remains trusted test infrastructure.

Auth, issuance, Voting and fixture logins have different generated passwords.
Owner/migrator connections remain only in the coordinator's fixture/migration
code. Runtime connections never switch to owner or migrator roles.

Each scenario has a fresh active synthetic voter, eligibility granted with the
existing trusted function (which creates `eligibility_id`), a fresh election and
two candidates named explicitly synthetic A/B. Both databases receive the same
canonical manifest, signature, config digest and opening/closing dates derived
from database time. Each election gets fresh RSA-3072 RA/Tally keys and an Ed25519
authority. The public authority pin is configured independently in RA, Voting and
Vite; the API does not supply that trust anchor.

The RA test key is written only as encrypted PKCS#8 in a private runner temp
directory (0600 file), loaded with its generated in-memory passphrase, and supplied
to the reviewed signer through its existing private pipe. That pipe carries the
original blinded message, not its hash. Tally private material is discarded after
fixture setup; no Tally component is implemented. No operator key/configuration
file is read. No RSA signing substitute, fake signature, mocked database, synthetic
HTTP service or alternate crypto implementation is used in this gate.

Browser login credentials and recovery passphrase use a private parent/child stdin
pipe, not argv, environment or files. Checkpoints use a bounded private stdout
protocol. The browser driver prints no arbitrary errors, DOM, request payloads,
tokens or tracebacks. The coordinator logs only fixed checkpoints/categories and
allowlisted SQLSTATEs. PostgreSQL error statement/parameter logging is suppressed
by the existing reviewed container configuration.

## Scenarios and database assertions

The [Chromium driver](../frontend/tests/real-voting.mjs) uses actual application
screens, real HTTP responses and browser crypto. Its `route.fetch()` fault
injection forwards the original request to the real backend; only the resulting
HTTP response is dropped with `route.abort()`. No `route.fulfill()` is used.
There is no fixture-control HTTP endpoint: privileged test actions occur only at
private coordinator checkpoints.

| Scenario | Browser/API checks | Independent committed database checks |
| --- | --- | --- |
| `accepted` | Login/Me, signed catalogue, two candidates, choose A, confirmation, browser encryption/Prepare/Blind, real issuance 201, Finalize/verification, anonymous acceptance 201 and matching receipt. | Before issuance: no reservation/issuance/ballot. After issuance: one reservation, issuance and issued audit event. After acceptance: exactly one ballot and matching receipt. |
| `response_loss` | Drop a real committed issuance response, retry exact request -> 200 and same blind signature. Drop a real committed voting response, retain uncertain state, recover -> 200 and same receipt. | Committed issuance/audit verified before dropping its response; no second authorization on replay. Ballot and receipt verified before dropping the vote response; recovery retains exactly one ballot. |
| `closed_first` | Obtain a real credential, close the disposable election before first submit, confirm Voting returns 409. | One RA issuance; zero accepted ballots throughout. |
| Negative/replay checks in both accepted scenarios | Original ballot -> 409; altered signature -> 422; altered envelope -> 422. | Still exactly one accepted ballot with the original receipt. |
| Closing after acceptance in both accepted scenarios | Close the actual database election; original proof/envelope receipt recovery still returns 200. | Original committed row and receipt preserved. |
| ACLs, all scenarios | Runtime direct SELECT/DELETE, internal non-NULL receipt-function EXECUTE and owner/migrator role switching must be denied. | Existing negative probes require SQLSTATE 42501. Effective Voting function inventory, owners, SECURITY DEFINER/search_path, worker/PUBLIC EXECUTE and table/column privileges checked; RA unauthorized EXECUTE grants checked. |

The real login must create a database session. Every browser checkpoint is
acknowledged only after a separate fixture connection checks committed state.
The returned receipt must match the actual SQL result, Python service comparison,
browser verification and driver calculation. No SQL rows or cryptographic payloads
are printed. Before issuance, IndexedDB is checked for encrypted state without
plaintext pending fields. Issuance retries must have identical request ID and
original blinded bytes.

Privacy assertions inspect actual browser requests. RA issuance has exactly
election ID, request ID and blinded message, with no selected candidate ID/name
or serial. Anonymous requests have only election/credential/envelope, no RA
request ID or voter ID, and no Authorization, identity headers or cookies. A
deliberately installed synthetic identity cookie must still be omitted. The real
Voting route independently enforces this boundary. The coordinator is trusted
test infrastructure and can correlate its fixtures; this is not proof of anonymity
against a compromised coordinator, browser, proxy, network or server.

## Execution commands (hosted CI only)

The workflow installs the existing locks without dependency/version changes:
Node 24.22.3, Go 1.25.14, Python 3.11.9, blindrsa-ts 0.4.6 and CIRCL v1.6.5.
It runs the complete backend/crypto suite, native Go tests/build, frontend build
and tests, both existing browser suites and the TypeScript recovery tests first.
The key real-service invocation is:

```bash
"$EVOTE_TEST_PYTHON" scripts/real_voting_e2e.py \
  --allow-ephemeral-ci-databases \
  --node "$(command -v node)" \
  --signer-binary "$RUNNER_TEMP/real-e2e-circl-signer"
```

The preceding native build command is:

```bash
go mod download
go mod verify
go test -count=1 ./...
go build -o "$RUNNER_TEMP/real-e2e-circl-signer" ./cmd/ra-credential-signer
```

Run that build in `crypto_interop/signer/`. All other provisioning, fixture
seeding, startup and shutdown happen inside the guarded coordinator, with no
interactive prompts or production launcher invocation.

The first human-approved push containing this workflow to
`feat/voter-voting-ui` starts the full **real-voting-e2e** job. It does not depend
on dispatch discovery or the workflow being on the default branch: GitHub
documents that [push also runs workflows not merged into the default branch](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#push).
The first run still must pass every regression/security step before reaching
the real-service scenarios.

Inspect the **Real browser RA CIRCL PostgreSQL voting** workflow and its
**real-voting-e2e** job after publication. Keep manual dispatch for later use;
do not rely on it for the first run, because its availability has
[default-branch/discovery requirements](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#workflow_dispatch).
When available, manual dispatch on the reviewed published branch is:

```bash
gh workflow run real-voting-e2e.yml --ref feat/voter-voting-ui
gh run list --workflow real-voting-e2e.yml --branch feat/voter-voting-ui
gh run view <run-id> --log-failed
```

These commands were not run during implementation.

## Cleanup and screenshots

For each scenario, real services and signer stop before deletion of only that
scenario's generated UUID fixtures. Fresh transactions verify committed cleanup
of both databases, including RA audit/session/reservation rows and Voting
candidates/ballots/configuration. Encrypted test-key temp directories are removed.
ExitStack/finally remove both exact owned containers after verifying their
name/label/image/loopback/tmpfs properties again. SIGTERM unwinds normal cleanup;
an abrupt host kill may prevent process-level cleanup, after which the fresh
hosted runner itself is disposable. There is no broad Docker prune or database
drop against external targets.

Only two PNG files are eligible for upload, after the entire job and cleanup
succeed: a public synthetic catalogue before choice entry and an accepted-heading
crop without receipt or private state. No tracing, videos, HAR, HTML dumps,
credential downloads, private keys, SQL dumps or logs are uploaded. The artifact
is `real-voting-public-previews` with three-day retention. The upload action is
pinned to the [official v7.0.2 commit](https://github.com/actions/upload-artifact/commit/cf430e030ddbb5b0abf93d22962f4752f3646cd9).

**No real-gate screenshots or real database/cleanup PASS evidence exist yet.**
They can only be produced by the first successful hosted run; old synthetic
screenshots are not substituted.

## Actual local validation and limits

- Complete database-free Python backend/crypto suite: **655 passed**, including
  34 new safety-boundary tests. These use test doubles solely to verify guard and
  private-protocol rejection behavior, not as real-gate evidence.
- Frontend unit/component/crypto tests: **78 passed**.
- Existing authentication browser suite: **7 passed**; existing synthetic voting
  browser suite: **3 passed**, both in local Edge. They remain separate evidence.
- Existing TypeScript recovery tests: **2 passed**.
- Frontend TypeScript checks/production build, JavaScript/Python/YAML/Bash syntax,
  Python dependency verification, changed-source secret scan and diff checks:
  **PASS** (all five new files scanned; six workflow Bash blocks checked). The
  standalone real browser driver also refused Windows with only a sanitized
  failure event, before launching a browser. The existing SJCL fallback
  externalization warning remains; browser WebCrypto regression passed.
- The new real gate, PostgreSQL migrations, native CIRCL execution and real-gate
  database assertions have **NOT RUN locally**. Go is not available on this
  session's PATH. The workflow installs the pinned toolchain on Ubuntu.

No existing workflow, applied migration, production launcher, frozen protocol,
dependency lock or application behavior changed. This gate does not supersede
the independent Gate 1, Gate 2, Commit #6 or synthetic browser gates. It adds
combined coverage; full 20-way concurrency and crash-boundary coverage remain
in those existing PostgreSQL gates. Multi-process restart recovery, other browser
engines, production key isolation, Tally validity, publication evidence and full
anonymity/coercion resistance are outside this gate's claims.

## Final pre-publication corrections

Two confirmed workflow issues were corrected:

1. Removed the PR trigger. Only the existing exact feature-branch push and manual
   dispatch triggers remain; there is no job condition/dependency that skips
   the first push.
2. Removed the unsupported job-level `runner.temp` expression for the Python
   executable. The installation step now uses the runner's `RUNNER_TEMP`, writes
   the public executable path to `GITHUB_ENV` for subsequent steps, and uses its
   local shell variable within the installation step itself. `runner.temp`
   remains only in the artifact step's supported `with` context. See GitHub's
   [context availability table](https://docs.github.com/en/actions/reference/workflows-and-actions/contexts#context-availability).

Two added regression tests enforce the exact trigger set and Python-path setup
ordering/context. This review changed the workflow, safety tests and this report.
The coordinator and browser driver were inspected and remain byte-for-byte
unchanged from the five-file implementation presented for review.

Publication inventory:

- [Workflow](../.github/workflows/real-voting-e2e.yml)
- [Coordinator](../scripts/real_voting_e2e.py)
- [Browser driver](../frontend/tests/real-voting.mjs)
- [Safety tests](../tests/test_real_voting_e2e_safety.py)
- This report.

Safety review found no additional confirmed defect in the target files. The
hosted-runner, owned-container, independent database designation, separate
credentials/processes, native signer, sanitized logging, fail-closed assertions,
bounded cleanup and successful-cleanup-only public PNG upload controls remain.
These are source/guard-test findings, not a claim that real hosted E2E execution
or teardown has passed. The first full Ubuntu run remains required.
