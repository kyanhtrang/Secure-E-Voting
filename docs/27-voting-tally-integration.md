# Real Admin to Voter to Tally integration review

Branch `test/voting-tally-integration`, base `main` at `f53bc10`.
The combined real-service gate is implemented for human review. **It has not run
on GitHub Actions.** Prior component gates and the local results below do not
establish a combined E2E PASS.

## Architecture and key ownership

```text
Trusted hosted coordinator -> Admin HTTP -> voting_admin_login -> Voting PG18
                                        -> ra_election_publisher_login -> RA PG18
Chromium A/B -> separate Vite origins -> real RA HTTP -> ra_auth_login / ra_issuance_login
                                                    -> native Go CIRCL signer
Chromium A/B -> anonymous Voting HTTP -> voting_ballot_login -> Voting PG18
Separate operator -> Tally HTTP -> voting_tally_login -> committed snapshot/report
                               -> encrypted matching Tally RSA key + private evidence
```

The coordinator creates one RSA-3072 RA key and one RSA-3072 Tally key, both
e=65537, before Admin finalization. Their public SPKIs, fingerprints and key IDs
form an approved public keyset. A separate Ed25519 authority signs the manifest;
a distinct Ed25519 snapshot/report authority is independently pinned. All private
keys are encrypted PKCS8 files in a fresh private runner-temp directory, outside
the checkout, with generated unlock secrets sent only through private pipes.
The key signed into the manifest is retained and used unchanged to decrypt the
browser ballots. No replacement key is generated after voting.

Only Admin receives the manifest authority key. Only RA receives the credential
RSA key and native signer. Only the Tally child receives the Tally RSA key and
snapshot/report key. Voting and the browser receive public verification material.
The trusted provisioning coordinator necessarily creates all test keys; these
process boundaries are not OS-user sandboxing or production key isolation.

The default app, production launchers, frozen cryptography and all existing
migrations remain unchanged. The production RA demo composition intentionally
accepts one fixed subject. A hosted-only adapter composes the same real routers,
authentication/session stores, limiter, local-origin and no-store middleware,
catalogue and issuance services for exactly the two trusted synthetic subjects.
It uses restricted, guarded connection factories. It provides no mocked HTTP,
database result or signature. Each voter has its own RA process and Vite origin;
both use the same election and credential signing key. Their browser contexts
remain alive until tally completion, retaining their own recovery proofs.

## Disposable migration and ACL review

The workflow accepts no database targets, credentials, key inputs or repository
secrets. It requires GitHub-hosted Ubuntu 24.04. Existing guards reject local
platforms, inherited PostgreSQL/Docker endpoints and service configuration.
The production databases cannot be selected by a command-line argument.

Two independently owned PostgreSQL 18 containers use the existing digest-pinned
image, tmpfs data/password storage, SCRAM, random loopback-only ports and no host
volumes. Names are fresh `ra_demo_test_ci_*` and `voting_demo_test_ci_*`.
Every runtime/fixture factory verifies the container ID/name/image/marker label,
tmpfs and mapped loopback port before connecting, then checks the actual database
name, independent UUID comment marker, owner, session/current role and PG18
version. Bootstrap and migration helpers retain their reviewed disposable guards.

| Database | Existing revisions applied, in order | Result |
|---|---|---|
| RA | baseline through `c84e13b9702d`, then Admin `bf932d0f8702` | 15 revisions |
| Voting | `643decaa90ab`, `b5bd58a07ceb`, `d8f27a4c610b`, Admin `af821c9e7601`, Tally `e6a90c72b541` | 5 revisions |

No new migrations or grants are added to application deployment. Trusted setup
provisions baseline roles and separate `voting_admin_login`,
`ra_election_publisher_login` and `voting_tally_login` inside the owned clusters.
Migrator/owner capabilities remain in the trusted fixture process. Runtime
receives only its restricted credentials: Admin and publisher RPCs, RA auth and
issuance RPCs, anonymous ballot RPCs, and the ten existing Tally RPCs respectively.

The Tally migration's fail-closed preflight and the existing ACL harness remain
intact: NOINHERIT, no memberships/elevated flags/schema CREATE, no table DML,
no baseline/Admin EXECUTE, `voting_owner` SECURITY DEFINER ownership, fixed
`pg_catalog,...,pg_temp` search paths and no PUBLIC EXECUTE. The combined gate
additionally denies Tally ballot UPDATE/INSERT and Admin access to Tally RPCs.
Forbidden operations must produce actual SQLSTATE 42501 through the reviewed
denial helper. No assertion or privilege is weakened.

Initial privileged fixtures are active Admin/Tally principals, two active voters,
generated keys and eligibility via `ra.set_voter_eligibility`. Drafts, candidates,
signed configuration, RA publication, lifecycle changes and accepted ballots are
created through actual services. No accepted ballots are seeded in the combined
journey. Immutable rows are retained until their owned containers are destroyed.

## HTTP scenarios and committed assertions

| Step | Real operation and required evidence |
|---|---|
| Admin | Login; create draft; add candidates A/B; configure window; select public keyset; finalize. Independently verify the manifest and matching RA/Voting bytes, hashes and signatures. Late window/roster edits return 409. |
| Interrupted OPEN | Temporarily revoke only the original publisher reconcile EXECUTE grant inside the disposable RA DB. Admin OPEN returns 503; readiness remains false. Restore exactly that grant, retry OPEN, require matching enabled RA policy and readiness. |
| Tally authorization | Separate operator login/me. Actual Admin and both actual voter tokens receive 401 from Tally. Voter tokens also fail Admin access. |
| OPEN enforcement | Authenticated Tally run returns 409 `CONFLICT` for the OPEN election. |
| Voter A | Real Chromium login/catalogue; choose A; browser AES-256-GCM and RSA-OAEP encryption; frozen v2 Prepare/Blind; actual original blinded bytes go through real issuance to native CIRCL; Finalize and verify; anonymous POST receives 201. |
| Voter B | Independent eligible voter/context repeats the real workflow for B, receiving a distinct receipt and second committed ballot. |
| Privacy/security | Each browser requires the exact blinded RA request shape, with no serial/candidate; anonymous requests contain no RA/Admin authorization, identity cookies, voter/request IDs or usernames. A cookie canary must remain omitted. Duplicate submission returns 409; altered signature/envelope returns 422. The actual Voting upstream also observes forbidden identity headers. |
| Durable acceptance | After each browser acceptance, assert one reservation, one completed issuance and one issuance audit event for that voter/election; verify the exact committed receipt set of size one, then two. Browser independently computes the receipt digest. |
| Interrupted CLOSE | Real Admin CLOSE under the same bounded publisher permission fault returns 503. Voting is CLOSED but `ra_ready=false`; RA remains enabled pending reconciliation. Tally must return 409 `CONFLICT`; no job may exist. Restore grant and retry CLOSE; require CLOSED/readiness and disabled RA issuance. |
| Real Tally | Actual operator POST `/api/v1/tally/elections/{id}/run` returns 200 only after commit. The existing restricted service verifies the frozen configuration and committed signed snapshot, decrypts with the retained matching RSA key and counts the browser ciphertexts. |
| Exact counts | A=1, B=1, accepted=2, valid=2, counted=2, invalid=0; accepted=valid+invalid. Candidate IDs/roster and configuration digest must match the independently verified manifest. |
| Evidence | Independently verify Ed25519 aggregate signature/context, canonical bytes and digest. Require TALLIED in both Voting and Admin control state; exactly one snapshot, job and report; two snapshot/tallied audit events; snapshot signature, private immutable evidence file and complete committed receipt set agree. HTTP response fields must be aggregate-only. |
| Idempotency | Repeat run and read report; require byte-equivalent JSON evidence and still exactly one job, snapshot and report, with unchanged counts. |
| Wrong authority | A separate Tally verifier with a different public manifest pin must reject report verification with 503 `INTEGRITY`. The correctly configured service must still return the original committed report. No stored configuration or ballot is mutated. |
| Receipt recovery | Only after successful Tally, release both waiting browser contexts. Each posts its original proof with `credentials: omit`, gets the same receipt, and still gets 409 on duplicate acceptance. Recheck exactly two ballots and original receipts. |
| Audit/ACL/logout | Require one Admin OPEN/CLOSE and one TALLY_OPERATOR TALLIED event with the proper distinct principals; enforce baseline/Admin/Tally effective ACL and 42501 denials; logout and reject the revoked Tally session. |
| Cleanup | Close browsers, Vite/HTTP services and native signers; remove private runner-temp key/evidence files and both owned containers. Explicitly verify directory and container IDs are absent before the final checkpoint. Exceptions cause nonzero exit and context-manager cleanup. |

The existing [Tally PostgreSQL harness](../scripts/tally_postgres_ci.py) also runs
as a separate regression step first, retaining real invalid-ballot classification,
rollback/recovery, concurrency, wrong-key/configuration, fencing and ACL assertions.
Those fixtures are in a separate owned disposable container and do not substitute
for either Chromium-produced ballot in the combined election.

## Workflow and commands

[The dedicated workflow](../.github/workflows/voting-tally-integration.yml) triggers
on pushes only to `test/voting-tally-integration`, with input-free manual dispatch
retained. Repository permissions are `contents: read`; checkout credentials and
tool caches are disabled. There are no artifact uploads, traces, screenshots or
secret-bearing environment values. Required failures are never ignored.

Tools reuse the reviewed pins: Node 24.22.3, Go 1.25.14, Python 3.11.9; dependencies
use the unchanged Python/npm locks and Go sums (`-mod=readonly`, `GOWORK=off`,
`GOTOOLCHAIN=local`). Ubuntu runs, in order:

```bash
python -m venv "$RUNNER_TEMP/admin-voter-python"
gate_python="$RUNNER_TEMP/admin-voter-python/bin/python"
"$gate_python" -m pip install --no-deps -r backend/voting/requirements.lock.txt
"$gate_python" -m pip check
"$gate_python" scripts/voting_postgres_ci.py --verify-dependencies
npm --prefix frontend ci --ignore-scripts
npm --prefix crypto_interop ci --ignore-scripts
npm --prefix crypto_interop run build
# In crypto_interop/signer:
go mod download
go mod verify
go test -count=1 ./...
go build -o "$RUNNER_TEMP/admin-voter-circl-signer" ./cmd/ra-credential-signer
# At the repository root:
EVOTE_TEST_NODE="$(command -v node)" "$gate_python" -m pytest tests/ crypto_interop/ -q
node --test crypto_interop/dist/pending_state.test.js
# In frontend (EVOTE_TEST_PYTHON is exported by the workflow):
npm run check
npm run build
npm test
npx --no-install playwright install --with-deps chromium
npm run test:browser
npm run test:voting-browser
npm run test:admin-browser
npm run test:tally-browser
# At the repository root, hosted runner only:
"$gate_python" scripts/tally_postgres_ci.py --allow-ephemeral-ci-database
"$gate_python" scripts/voting_tally_e2e.py --allow-ephemeral-ci-databases \
  --node "$(command -v node)" \
  --signer-binary "$RUNNER_TEMP/admin-voter-circl-signer"
git diff --exit-code
git diff --check
```

Do not run these disposable provisioning commands against a local installation.
The coordinator refuses that environment and accepts no user database target.
After human-approved publication, inspect the workflow named **Real
Admin-to-Voter-to-Tally integration**, job `voting-tally-integration`, for that
exact commit. No commit or push was performed while preparing this change.

Expected combined checkpoints, not actual execution evidence:

```text
PASS: voting_tally_e2e checkpoint=migrations
PASS: admin_voter_e2e checkpoint=admin_draft scenario=accepted
PASS: admin_voter_e2e checkpoint=admin_finalize scenario=accepted
PASS: voting_tally_e2e checkpoint=open_tally_denied
PASS: voting_tally_e2e checkpoint=accepted_first
PASS: voting_tally_e2e checkpoint=accepted_second
PASS: voting_tally_e2e checkpoint=close_interrupted
PASS: voting_tally_e2e checkpoint=close_reconciled
PASS: voting_tally_e2e checkpoint=tally
PASS: voting_tally_e2e checkpoint=evidence
PASS: voting_tally_e2e checkpoint=idempotency
PASS: voting_tally_e2e checkpoint=configuration_rejected
PASS: voting_tally_e2e checkpoint=receipts
PASS: voting_tally_e2e checkpoint=acl
PASS: voting_tally_e2e checkpoint=cleanup
```

Failures expose only fixed stage/category, well-formed SQLSTATE and allowlisted
HTTP status. Browser failures expose only one of preflight, catalogue, prepare,
issue, submit, security or recovery. No exception text, SQL/body/parameters,
tokens, private keys, DOM or individual selections are printed. A missing child
readiness/event, timeout, nonzero exit or cleanup failure fails the gate.

## Local validation and review inventory

Executed on this combined checkout, not added counts from older branches:

| Check | Actual result |
|---|---|
| Complete backend/crypto `pytest tests/ crypto_interop/ -q` | 839 passed (805 existing + 34 new coordinator tests) |
| Frontend Vitest | 87 passed, 8 files |
| Existing authentication browser suite | 7 passed |
| Existing voting browser suite | 7 passed |
| Existing Admin browser suite | 2 passed |
| Existing Tally browser suite | 2 passed |
| TypeScript credential recovery | 2 passed |
| Frontend TypeScript check and production build | PASS |
| Crypto TypeScript build; new driver Node syntax | PASS |
| Python dependency integrity/version verification; locked npm installs/tree | PASS; locks unchanged |
| Python/JSON/YAML parsing, workflow Bash syntax | PASS |
| Changed-source secret/payload and whitespace review; `git diff --check` | PASS |
| New combined real PostgreSQL/CIRCL/Chromium journey | NOT RUN; pending Ubuntu Actions |
| Native Go build/test locally | NOT RUN; Go is not available on the local PATH; required in Actions |

Local browsers used installed Edge via the existing Windows Playwright settings;
Actions installs pinned Playwright Chromium. Local Python used the project venv,
`PSYCOPG_IMPL=python` and installed libpq18 for database-free imports because
Windows Application Control blocks the bundled psycopg DLL. This opens no database
connection and changes no security policy. The initial frontend attempt used
system Python and failed a missing dependency/import; the corrected full run
above used the project venv. The unchanged Vite build emits its existing blindrsa
Node `crypto` externalization notice; browser crypto regressions passed.

All changed files are new:

- [Dedicated workflow](../.github/workflows/voting-tally-integration.yml).
- [Hosted coordinator and isolated adapters](../scripts/voting_tally_e2e.py).
- [Real browser driver](../frontend/tests/real-voting-tally.mjs).
- [Database-free safety regressions](../tests/test_voting_tally_e2e_safety.py).
- [This review report](./27-voting-tally-integration.md).

No application source, dependency lock, existing workflow, applied migration,
production launcher, stash or previous test assertion is changed.

## Limitations and human approval gate

The new wiring, actual migration execution, browser ciphertext decryption, exact
committed counts, real ACL denials and owned-resource cleanup remain unverified
until this workflow runs successfully on Ubuntu. Database-free unit doubles are
used only to test guard refusal, private control, error handling and coordination;
they are not E2E substitutes.

This is a trusted single hosted-runner test, with process/service credential
separation but a common OS user. It does not demonstrate HSM isolation, protection
from a malicious runner/coordinator, independent external auditing, full anonymity,
coercion resistance or complete E2E verifiability. Timing and a two-voter aggregate
can disclose information; no production privacy claim follows from this fixture.
Python/JavaScript cannot guarantee immediate secret zeroization.

The gate tests Admin and Tally via their real HTTP APIs; it does not test the Admin
or Tally UI against live databases. Existing synthetic component/browser suites
remain separately labeled. Public results and Bulletin Board publication remain
unimplemented by this change. Review the five files, then approve a branch push
and inspect actual Actions evidence before treating this combined gate as passed.
