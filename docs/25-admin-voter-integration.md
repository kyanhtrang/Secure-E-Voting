# Real Admin to Voter integration gate

Branch `test/admin-voter-integration`, base `main` at `ea23a27`. This separate
gate connects the reviewed Admin, RA, native CIRCL, voter browser and Voting
components. **The new combined gate has not executed.** Local regression results
below support source review; they are not real PostgreSQL/CIRCL E2E evidence.

## Services and trust boundaries

```text
Coordinator -> real Admin HTTP API -> voting_admin_login -> Voting PostgreSQL 18
                                   -> ra_election_publisher_login -> RA PostgreSQL 18
                         |
                  signed public manifest
                         |
Chromium -> Vite -> RA API -> ra_auth_login / ra_issuance_login -> RA PostgreSQL 18
                         -> LocalCIRCLSigner -> native Go CIRCL BlindSign
Chromium -> Vite -> Voting API -> voting_ballot_login -> Voting PostgreSQL 18
```

Admin, RA and Voting run in separate Python processes with distinct loopback
origins, role-specific credentials and strict private-pipe configuration schemas.
Vite receives only public origins and the independently generated authority pin.
The voter browser receives no Admin token, Admin password, database credential or
private key. There is no shared authenticated request interceptor on Voting.

Only the Admin process receives the encrypted Ed25519 authority key and its
passphrase. Only RA receives the encrypted RSA-3072 credential key, its passphrase
and native signer path. Tally public keys are generated from separate ephemeral
RSA-3072 keys; Tally private keys are discarded and never sent to Admin, Voting or
the browser. Public keysets are approved by trusted test configuration, not
accepted from an untrusted browser. The authority public pin is supplied to all
verifiers independently of the Admin API. Frozen manifest, RSABSSA v2, envelope
and receipt formats are unchanged. BlindSign receives the original blinded bytes
through the reviewed issuance service and CIRCL adapter.

The Admin journey uses real HTTP APIs rather than the Admin browser UI. The voter
journey uses the existing real-services Chromium driver. No runtime service,
database response or cryptographic signature is mocked. The database-free safety
tests use doubles solely to test refusal, cleanup and callback behavior.

## Disposable provisioning and migrations

[The workflow](../.github/workflows/admin-voter-integration.yml) runs only on
GitHub-hosted Ubuntu 24.04, with automatic pushes restricted to this branch and
optional manual dispatch without inputs. Permissions remain `contents: read`.
Actions are pinned by commit; tools are Node 24.22.3, Go 1.25.14 and Python 3.11.9.
Python/npm locks and Go module sums are reused unchanged. All regressions run
before the new gate. Existing workflows are untouched.

[The coordinator](../scripts/admin_voter_e2e.py) reuses the owned-container
implementation and bootstrap/migration helpers from the existing PostgreSQL gates.
It creates two separate digest-pinned PostgreSQL 18 containers with tmpfs data and
bootstrap-password storage, no persistent host volumes, SCRAM authentication and
random loopback-only published ports. Database names are fresh
`ra_demo_test_ci_*` and `voting_demo_test_ci_*`; independent UUID database comment
markers are mandatory. `ra_db`, `voting_db`, remote Docker endpoints, inherited PG
connection settings and inherited service configuration are refused.

Every new runtime and fixture factory verifies the owned container ID, name,
marker label, pinned image, tmpfs mounts and loopback port before connecting.
It then checks database name, database owner, session/current role, independent
database comment and PostgreSQL major version. Trusted baseline bootstrap and
guarded Alembic helpers retain their existing identity/marker checks; they run
only against the newly owned targets. Runtime never receives bootstrap or
migrator credentials. Only fixture connections SET ROLE to the appropriate owner.

| Database | Existing chain | Admin extension | Total revisions |
|---|---|---|---:|
| RA | reviewed baseline through `c84e13b9702d`, including `7b2d91a6c840` | `bf932d0f8702` | 15 |
| Voting | `643decaa90ab` -> `b5bd58a07ceb` -> `d8f27a4c610b` | `af821c9e7601` | 4 |

No migration source or production deployment setting changes. New runtime roles
are provisioned only inside the owned clusters using the reviewed Admin CI setup.
Admin logins remain NOINHERIT with no memberships or elevated role flags. Existing
SECURITY DEFINER ownership, fixed search paths, narrow EXECUTE grants, PUBLIC
revocations and table-DML restrictions remain intact.

Initial privileged data consists of one active synthetic Admin principal, one
active synthetic voter, ephemeral key material and eligibility through
`ra.set_voter_eligibility`. The coordinator does **not** insert or update finalized
Voting elections/configuration/candidates or RA signing-key/policy rows.
Admin HTTP calls create and publish those records.

## Exact scenarios

Each scenario creates a distinct election and keyset for the same synthetic voter.

1. Admin logs in, verifies `/auth/me`, creates a draft, adds candidates A and B,
   updates the voting window, reads the approved public keyset, and finalizes.
   The coordinator independently verifies the returned signature and canonical
   manifest. Voting and staged RA publication bytes, signatures and hashes must
   match. Attempts to edit the signed window or roster must return 409.
2. An actual EXECUTE denial interrupts OPEN at the second database boundary.
   Voting must be OPEN with `ra_ready=false`; RA must have no enabled policy and
   its real authenticated catalogue must return 503. Restoring the original grant
   and retrying the same Admin `/open` call must publish the matching enabled RA
   policy and reconcile readiness.
3. The real RA login token is rejected by Admin; the Admin token is rejected by
   RA. An unauthenticated Admin request is also rejected. Neither token is passed
   to the anonymous Voting client.
4. Chromium logs in, fetches the Admin-published catalogue, verifies its manifest,
   selects A, encrypts the ballot, prepares/blinds the frozen credential, obtains
   a native CIRCL blind signature, finalizes/verifies locally, and submits.
5. The scenario-specific checks below execute against actual services and DBs.
6. Admin audit events must contain the expected lifecycle categories and the
   synthetic Admin actor. Sessions are logged out, privilege assertions run, and
   final database counts are checked before owned-resource destruction.

| Scenario | Required real observations |
|---|---|
| `accepted` | HTTP 201, one committed ballot, locally verified receipt, duplicate 409, altered signature/envelope 422 |
| `response_loss` | Committed issuance response dropped; exact retry recovers the same signature. Committed ballot response dropped; receipt recovery returns the same receipt without another ballot |
| `closed_first` | Credential is genuinely issued before Admin closes; a subsequent new ballot returns 409 and no ballot row is created |

CLOSE is deliberately interrupted in all three scenarios. Voting must commit
CLOSED first, while RA temporarily remains enabled and readiness remains false.
The browser then proves either that the committed receipt is still recoverable
or that a new ballot is rejected **during this incomplete reconciliation**.
Only after that checkpoint does the coordinator retry Admin `/close`, verify
disabled RA issuance and the retained closed tombstone, and reject reopening.

Expected final rows: three CLOSED managed elections, three durable issuance
reservations, three completed issuances and two accepted ballots. Every existing
browser checkpoint retains its separate-transaction DB count/receipt assertions.
The browser continues to check exact RA blinded-request fields, absence of serial
or candidate data at RA, original-request replay, credential/envelope binding,
anonymous requests without authorization/cookies/identity fields, duplicate
rejection and recovery. A passive observer at the actual Voting ASGI boundary
records only request counts and a Boolean if identity headers arrive, including
Admin-specific headers; any observed leak fails service shutdown and the gate.

## Failure injection and cross-database semantics

Failure injection removes only EXECUTE on
`ra_admin.reconcile(uuid,bytea,boolean,uuid)` from
`ra_election_publisher_login`, using the verified RA owner fixture. The helper
first requires the original grant to exist. It commits the revocation, calls the
real Admin API and observes the real PostgreSQL permission failure. A `finally`
block restores precisely the original grant. No PUBLIC or additional role grant
is added; no service is replaced. This injection exists only in the disposable
coordinator, not production code or migrations.

The test does not assume cross-database atomicity. OPEN can commit in Voting
before RA publication, and CLOSE can commit before RA issuance is disabled.
Readiness is conservative and retries reconcile the immutable same manifest.
During an initial incomplete OPEN, no RA policy/credential can be obtained for
the election. This does not promise that Voting rejects every previously valid
credential during all possible partial states; existing acceptance semantics
are preserved. During incomplete CLOSE, Voting already rejects new acceptance
and permits recovery of previously committed receipts.

ACL checks reuse the real Voting and RA probes and add checks for Admin role
flags/memberships, no PUBLIC execution, denied direct ballot/voter table access,
denied owner role switching, and denial of Admin functions to auth, issuance and
ballot runtime identities. They require exactly seven Admin RPCs for
`voting_admin_login` and exactly two publisher RPCs for
`ra_election_publisher_login`, with no schema CREATE. Assertions use actual privilege functions and actual
42501 denials. No privileged fixture credential is installed in a runtime service.

## Diagnostics and cleanup

Expected output includes these fixed checkpoints, without IDs or payloads:

```text
PASS: admin_voter_e2e checkpoint=admin_login
PASS: admin_voter_e2e checkpoint=admin_draft scenario=accepted
PASS: admin_voter_e2e checkpoint=admin_finalize scenario=accepted
PASS: admin_voter_e2e checkpoint=open_interrupted scenario=accepted
PASS: admin_voter_e2e checkpoint=open_reconciled scenario=accepted
PASS: real_voting_e2e checkpoint=catalogue
PASS: real_voting_e2e checkpoint=prepared
PASS: real_voting_e2e checkpoint=issued
PASS: real_voting_e2e checkpoint=accepted
PASS: admin_voter_e2e checkpoint=close_interrupted scenario=accepted
PASS: admin_voter_e2e checkpoint=close_reconciled scenario=accepted
PASS: admin_voter_e2e checkpoint=admin_audit scenario=accepted
...
PASS: admin_voter_e2e checkpoint=acl
PASS: admin_voter_e2e checkpoint=database_assertions
PASS: admin_voter_e2e checkpoint=cleanup
PASS: admin_voter_e2e scenarios=3 real_services=true owned_containers=removed
```

Failures contain only allowlisted stage/category, SQLSTATE and optional allowlisted
HTTP status, for example:
`FAIL: admin_voter_e2e stage=admin_finalize category=assertion_error sqlstate=unavailable http_status=503`.
There are no arbitrary error messages, tracebacks, SQL parameters, connection
URLs, token/credential payloads, ballot envelopes or private keys in CI output.

All secrets use generated memory values, private pipes or encrypted mode-0600
test-key files under a private runner-temp directory. HTTP requests omit ambient
cookies/proxies and refuse redirects. No generated secrets are passed in argv.
The existing driver's synthetic public screenshots stay in the private temporary
directory and are deleted; the new workflow uploads no artifacts.

Fixture rows, immutable audit records and tombstones remain intact until their
owned containers are destroyed. This avoids deleting reviewed retention evidence
or needing a fixture reset that bypasses lifecycle rules. ExitStack closes the
HTTP processes/native signer, removes the private directory and removes only
verified owned containers. The final assertion verifies that both container IDs
are absent and the directory is gone. SIGTERM unwinds this cleanup; forced runner
termination is ultimately bounded by destruction of the ephemeral hosted VM.
The workflow removes its exact generated native binary in an `always()` step.

## Execution and review inventory

After human approval, the first push to the dedicated branch triggers the full
job, including the pinned native signer build. Its final integration command is:

```bash
"$EVOTE_TEST_PYTHON" scripts/admin_voter_e2e.py \
  --allow-ephemeral-ci-databases \
  --node "$(command -v node)" \
  --signer-binary "$RUNNER_TEMP/admin-voter-circl-signer"
```

There are no database, credential, production key or endpoint arguments. Local
execution is refused before file, process, Docker or database operations.

| Changed file | Purpose |
|---|---|
| [New workflow](../.github/workflows/admin-voter-integration.yml) | Separate hosted gate, locked setup, all regressions first, no artifacts |
| [New coordinator](../scripts/admin_voter_e2e.py) | Owned provisioning, isolated services, real Admin HTTP lifecycle, reconciliation and ACL assertions |
| [Existing browser coordinator](../scripts/real_voting_e2e.py) | Optional close/checkpoint callbacks; original default behavior/checkpoints preserved |
| [Safety tests](../tests/test_admin_voter_e2e_safety.py) | Refusal/identity/credential isolation, fault-grant restoration, privacy observation, callback and workflow regressions |
| [This review report](./25-admin-voter-integration.md) | Architecture, scenarios, trust/ACL review and validation status |

Actual local results on this combined checkout:

| Executed validation | Result |
|---|---|
| Complete Python backend/crypto regression | **781 passed**, including 44 new safety cases |
| Frontend component/API/crypto tests | **84 passed** |
| TypeScript production build | **PASS** |
| Authentication browser suite | **7 passed** |
| Voting browser suite | **7 passed** |
| Admin browser suite | **2 passed** |
| TypeScript credential recovery tests | **2 passed** |
| Locked npm installs and Python dependency checks | **PASS**, locks unchanged |
| Python syntax, workflow YAML and seven Bash blocks | **PASS** |
| Changed-source secret/whitespace scan and `git diff --check` | **PASS** |
| Migration dependency graphs without execution | **PASS**, RA 15 / Voting 4 |

Python 3.11.9/Node 24.22.3 were used locally. Windows psycopg uses its supported
Python implementation with the already-installed PostgreSQL client library;
this imports a client library and does not connect to a database. Browser
regressions use Edge on Windows and their existing synthetic fixtures. The new
hosted gate uses Chromium. The existing blindrsa-ts browser externalization
notice remains; cryptographic browser tests pass.
Go is not on the local PATH; native Go tests/build are configured in the hosted
workflow and were not executed locally. No execution-policy bypass was attempted.

The new real migrations, actual permission-fault scenarios, native Linux signer,
cross-service browser journey and owned-resource teardown are **pending GitHub
Actions execution**. The earlier verified component gates do not establish a
PASS for this new composition. No local PostgreSQL instance, production private
key, commit, push, merge, worktree removal or stash removal was used.

CI process separation verifies credential routing and accidental boundary leaks;
it is not production OS/HSM key isolation or protection against a compromised
host/Docker administrator. Tally candidate-choice validation, vote counting and
results publication remain deferred. No full anonymity, coercion resistance or
complete end-to-end verifiability is claimed.
