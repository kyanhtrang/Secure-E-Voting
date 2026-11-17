# Commit 8: local Admin election management

Status: implementation for human review. **The new migrations and real Admin
PostgreSQL gate have not been executed.** Existing voting E2E evidence does not
validate this new administration path. No user databases were accessed.

## Architecture and authorization

The explicitly enabled [launcher](../backend/admin/launcher.py) serves a separate
loopback application on port 8002. It is absent from `backend.main.app`.
Host/Origin/peer checks reuse the reviewed local middleware; proxy trust, CORS,
API docs and access logs are disabled. Every response is `no-store`. Exceptions
are sanitized and neither request input nor database diagnostics are returned.

An explicit verifier maps one local username to an independently provisioned
`voting_admin.principals` UUID. Password verification reuses scrypt
N=16384/r=8/p=1, salt at least 16 bytes, digest 32 bytes. Five failed attempts in
60 seconds trigger the existing shared, process-local limiter. This is local
demo authentication, not an organization identity provider or MFA.

Admin sessions use `adm1.` plus 32 random bytes in canonical base64url. The DB
stores SHA256(`EVOTE-ADMIN-SESSION-v1\0` || ASCII token). Database timestamps
control a fixed 15-minute TTL. Every operation checks active principal,
`ELECTION_ADMIN` role, session expiry and revocation. A voter bearer fails token
validation before database access. The UI uses a separate in-memory token
closure, omitted cookies, no local/session storage and no token getter.

The two runtime credentials are capabilities of the trusted Admin server:

| Login | Database | Allowed boundary |
|---|---|---|
| `voting_admin_login` | Voting | seven Admin RPCs, session and lifecycle operations |
| `ra_election_publisher_login` | RA | two public-configuration publication RPCs |

Both must be LOGIN, NOINHERIT, NOSUPERUSER, NOCREATEDB, NOCREATEROLE,
NOREPLICATION, NOBYPASSRLS, with no memberships. Neither has table/column DML,
baseline RA/Voting function execution or schema CREATE. Their database passwords
are prompted without echo; getpass fallback is fatal. No automatic credential
file discovery occurs. Runtime never uses owner/migrator/superuser credentials.

**Trust assumption:** possession of the Admin database login can mint sessions
for active Admin principals. The database does not independently verify a human
password. The publisher similarly trusts the server-supplied audit actor UUID;
there is no cross-database principal FK. Isolation and protection of these
service credentials and the Admin process are required. A voter session cannot
obtain either capability through an API.

## Immutable signing and database boundaries

The server loads an encrypted Ed25519 manifest-authority private key, checks it
against an independently supplied raw 32-byte public pin, and signs only the
existing canonical manifest/context using cryptography. No protocol changes,
RSA private key or ballot data are needed in Admin. The public key catalogue
contains approved RSA-3072/e=65537 RA and Tally public SPKIs, IDs and SHA256
fingerprints; the opaque RA private-key reference stays server-side. Distinct
per-election RA public keys and distinct RA/Tally keys are required. An assigned
keyset cannot be assigned to another managed election.

1. Draft elections reuse Voting elections/candidates. Each update checks an
   optimistic revision; stale/concurrent operations fail with 409.
2. Finalization snapshots the exact roster/window/keyset into a durable
   `FINALIZING` reservation and commits **before** invoking Ed25519 signing.
   All subsequent edits are refused, including after a crash. Exact retries
   sign the same canonical bytes and freeze the existing Voting config table.
3. RA preparation inserts a STAGED key and a new public publication record.
   It does **not** insert a disabled credential policy: the existing RA guard
   correctly forbids false-to-true policy activation. Existing unmanaged keys,
   policies and issuance authorizations are never overwritten.
4. Opening verifies the bundle and matching RA hash, commits Voting OPEN within
   the DB-controlled window, then commits the first enabled RA policy, then
   acknowledges reconciliation in Voting. RA existing policy guards remain
   intact. The signed hash/parameters are identical in both databases.
5. Closing commits Voting CLOSED first, then disables RA issuance and records a
   retained closed publication tombstone, then acknowledges reconciliation.
   Reopening is forbidden. A late opening retry cannot undo the tombstone.

There is no cross-database atomic transaction. A 503 can occur after any commit.
Read status and retry the **same** finalize/open/close operation. `ra_ready`
means the last lifecycle transition was reconciled; CLOSED plus true does not
mean credentials are enabled. Voting can be OPEN while RA reconciliation is
pending. Previously obtained valid credentials can still be accepted during
that interval; no new policy is claimed enabled until RA commits. If an RA
commit succeeds and its response is lost, the recorded flag may conservatively
remain false. On closure, Voting acceptance stops even if RA is unreachable;
RA may still issue unusable credentials until reconciliation. Availability and
strict simultaneous state changes are not promised.

The coordinator holds one session advisory lock per election across the short
Voting RPC commits. Each mutation also takes the same transaction advisory lock
so direct RPC callers cannot race the coordinator. Dedicated connection closure
releases it on success/failure/session expiry. Relative Voting lock order is
principal/session, advisory lock, election FOR UPDATE, control row, candidates
or config. Ballot acceptance and Admin close serialize on the existing election
row; the original uniqueness and ballot transaction rules are unchanged. RA
uses its per-election advisory lock, signing key, policy, publication; it never
locks voters/eligibility, preserving issuance's relative key-before-policy order.
No SQL transaction is held across remote DB calls or signing.

Voting lifecycle audit events and revision changes commit with the mutation.
Existing event categories are reused (`ELECTION_CREATED` with `DRAFT_UPDATED`
reason for edits, `CONFIG_FROZEN` with stage-specific reasons). RA publication
events retain actor UUID, action, config hash and database time. Runtime has no
audit UPDATE/DELETE privileges. Owner/superuser compromise is outside this model.
Admin audit queries expose lifecycle metadata and no ballot plaintext/serials or
voter/issuance records. Event timing remains a metadata privacy consideration.

## Real API inventory

All routes are under `/api/v1/admin`; all mutation bodies are strict JSON with
exact fields. Dates are UTC second precision `YYYY-MM-DDTHH:mm:ssZ`; UUIDs are
canonical lowercase strings. Query parameters and unknown fields are rejected.

| Method/path | Request fields | Response |
|---|---|---|
| POST `/auth/login` | username, password | access_token, token_type=bearer |
| GET `/auth/me` | bearer | admin_id, role=ELECTION_ADMIN |
| POST `/auth/logout` | `{}` + bearer | 204 after DB commit |
| GET `/keysets` | bearer | keysets with public keys only |
| GET `/elections` | bearer | elections (managed only, maximum 200) |
| POST `/elections` | title, opens_at, closes_at | 201 election |
| GET `/elections/{id}` | bearer | election |
| PUT `/elections/{id}` | revision, title, opens_at, closes_at | updated election |
| POST `/elections/{id}/candidates` | revision, candidate_name | election; server chooses candidate UUID |
| PUT `/elections/{id}/candidates/{cid}` | revision, candidate_name | election (UUID upsert before signing) |
| DELETE `/elections/{id}/candidates/{cid}` | revision | election |
| POST `/elections/{id}/finalize` | revision, keyset_id | signed election; exact retry supported |
| POST `/elections/{id}/open` | `{}` | reconciled election |
| POST `/elections/{id}/close` | `{}` | reconciled election |
| GET `/elections/{id}/audit` | bearer | latest 100 events |

Election fields: election_id, title, status, phase, revision, opens_at,
closes_at, candidates, keyset_id, config_hash, ra_ready, bundle (null until signed).
Raw reservation bytes and private-key references are not HTTP fields.
Errors: generic 401, 403, 404, 409 conflict, sanitized 422, 429 login limit,
503 unavailable. No error body is trusted/displayed by the client. Requests have
timeouts and no automatic write retry. A lost create/add response requires
refresh and inspection before another creation; these operations do not have
idempotency keys. Election deletion, reopening, Tally and publication are absent.

## Forward migrations and ACL review

The existing applied histories are unchanged. New versions live in separate
directories so established baseline CI head checks remain reproducible:

| Database | New revision | Parent | Opt-in Alembic config |
|---|---|---|---|
| Voting | af821c9e7601 | d8f27a4c610b | [alembic_admin_voting.ini](../alembic_admin_voting.ini) |
| RA | bf932d0f8702 | c84e13b9702d | [alembic_admin_ra.ini](../alembic_admin_ra.ini) |

Migrations require the new roles to exist with safe effective privileges and
fail instead of creating/repairing roles. They SET LOCAL ROLE to the existing
database owner, create only the new Admin schemas/tables/functions, reuse
existing election/config/key/policy tables, revoke PUBLIC access, and grant
specific RPC EXECUTE plus schema USAGE. All functions are SECURITY DEFINER,
owner-owned, with pg_catalog first, trusted schemas only and pg_temp last.
Internal helpers have no runtime EXECUTE. Postflight checks reject unexpected
function/table ACLs, including inherited owner default ACL changes. Relation
privilege checks use CASE guards for mixed pg_class types. Missing config hashes
use IS DISTINCT FROM and cannot bypass readiness through SQL NULL semantics.
Downgrades intentionally refuse automatic destructive removal of audit/tombstones.

Voting SQL contracts: `login_session(uuid,bytea)->jsonb`, `session(bytea)->jsonb`,
`logout(bytea)->void`, `operation(bytea,uuid,boolean)->boolean`,
`read_elections(bytea,uuid)->jsonb`, `audit(bytea,uuid)->jsonb`,
`mutate(bytea,uuid,text,jsonb)->jsonb`. Internal `_actor(bytea)->uuid`,
`_lock(uuid)->void` are owner-only.
RA contracts: `prepare(uuid,bytea,bytea,bytea,text,uuid)->jsonb` returns config_hash;
`reconcile(uuid,bytea,boolean,uuid)->jsonb` returns config_hash, enabled, closed.
Internal `_role()->void` is owner-only. SQL uses static, qualified statements;
adapters bind all values rather than interpolating requests into SQL.

## Explicit local setup (after human approval and disposable CI)

No commands in this section were executed against user databases. Provision the
two new restricted logins via the trusted operator process; use interactive
password setting rather than password literals or shell environment values.
Grant only CONNECT on their respective database. Do not give membership in owner,
migrator, RA service or ballot worker roles. Apply the two opt-in migration heads
only after reviewing and validating them in disposable CI. The opt-in INIs reuse
the existing interactive migrator environments; runtime never uses these logins.

As a separately authorized operator, enroll the chosen Admin UUID in
`voting_admin.principals` with `role='ELECTION_ADMIN', is_active=true`. There is
no bootstrap principal, password, demo voter or session in a migration.
Maintain a private configuration directory outside the checkout with restrictive
OS permissions (including Windows ACLs). Supply an explicit verifier JSON with
exact fields: enabled=true, environment="local-demo", admin_id (UUID), username,
salt (canonical base64url random >=16 bytes), digest (canonical base64url
scrypt(password,salt,N=16384,r=8,p=1,dklen=32)). Never store plaintext passwords.

Supply a key catalogue JSON object keyed by keyset ID; each value has exactly
`ra_key`, `tally_key`, `private_key_reference`. Public key objects have exactly
key_id, spki (canonical base64url DER), fingerprint (lowercase SHA256 hex).
Provision fresh per-election RA RSA-3072 keys through the reviewed issuer key
handling. Keep the corresponding Tally RSA private key offline; only its public
key is needed here. The reference is an opaque operator label, not key material.
The Ed25519 private key must be encrypted PKCS8 PEM and match the independently
distributed raw 32-byte manifest public pin already trusted by RA/Voting/Voter UI.
No authority-key or verifier-generation endpoint is exposed by Admin.

From the repository root (replace only file paths with reviewed local paths):

```powershell
python -m backend.admin.launcher --enable-local-admin `
  --verifier C:/private-config/admin-verifier.json `
  --key-catalogue C:/private-config/public-keysets.json `
  --authority-key C:/private-config/manifest-authority-encrypted.pem `
  --authority-pin C:/private-config/manifest-authority-public.bin
```

The command prompts for both runtime DB passwords and the authority key passphrase;
no password argument/environment variable is supported. It uses fixed local
127.0.0.1:5432 database targets and port 8002. Do not run it during source review.

Frontend (Node 24.22.3, no dependency changes):

```powershell
cd frontend
npm.cmd ci --ignore-scripts
$env:VITE_ENABLE_ADMIN='true'
npm.cmd run dev:local
```

Open `http://127.0.0.1:5173/admin`. Without both local-demo mode and the explicit
flag, Admin remains the existing read-only foundation. The Vite Admin proxy
preserves Host/Origin and is restricted to a separate loopback origin, default
127.0.0.1:8002. Existing RA and anonymous Voting proxies are unchanged.

Continue using the reviewed [RA credential launcher](../backend/ra/credential_launcher.py)
on 8000 and [Voting launcher](../backend/voting/local_launcher.py) on 8001 with the
same authority pin. The RA launcher accepts one signing key and an explicit
`--publish-election` list: restart/reconfigure it for each newly approved election
and matching key. Trusted eligibility enrollment is still a separate existing RA
operator operation. Admin does not register voters or grant voter eligibility.

## Disposable CI and remaining limitations

[admin-management.yml](../.github/workflows/admin-management.yml) is a separate
push-to-feature-branch/manual Ubuntu 24.04 gate with contents:read, pinned actions,
locked Python/npm dependencies, no repository secrets and no uploaded artifacts.
The [coordinator](../scripts/admin_postgres_ci.py) has no selectable DB targets or
password arguments. It owns two digest-pinned PostgreSQL 18 tmpfs containers with
random loopback ports and generated credentials; it creates RA/Voting test-prefixed
databases and verifies independent UUID comments, ownership and identities on
every connection. Existing real baseline chains run first, followed by the two
Admin revisions through guarded migration environments. Owner fixture access and
runtime logins remain separate. ExitStack tears down both owned containers even
on failure. Log output is fixed stage/category/SQLSTATE only, never exception
messages, SQL parameters, keys or connection URLs.

Pending real scenarios: SQL compilation/ACL postflight, active principal/session
TTL, 2-way stale-revision update race (one success), transaction rollback, real
manifest freeze and RA hash equality, interrupted OPEN/CLOSE reconciliation,
closed tombstones, audit actors, denied direct tables/PUBLIC/unrelated-role RPCs,
revocation/expiry, and owned-container cleanup. Run only on the GitHub-hosted
runner with `python scripts/admin_postgres_ci.py --allow-ephemeral-ci-databases`.
The script refuses local execution before any container/database call.

Synthetic Admin browser checks cover sign-in, draft creation, logout, disabled
opening and mobile/desktop fit. Unit fault injection proves service ordering and
exact manifest retry semantics, not real PostgreSQL concurrency. No combined
Admin browser -> PostgreSQL -> voter issuance -> ballot gate has run. Existing
real-voting workflows and frozen cryptography were preserved.

Limitations requiring explicit review: local HTTP/single-process authentication,
in-process signing-key protection (no HSM or remote approval), no MFA or durable
distributed login limiter, bounded list/audit responses without pagination,
retained sessions/audits without automated purge, one-way finalization/closure,
no signing-key rotation or incident recovery UI, and manual issuer/catalogue/
eligibility deployment. `ra_ready` proves matching published database policy, not
that the native signer or Tally service is online or correctly provisioned.
No full anonymity, coercion resistance, ballot counting or results publication
is claimed. These limitations do not permit relaxing existing verification or ACLs.

## Actual local validation and review inventory

Validated on branch `feat/admin-election-management`, base `e870de1`, Windows,
Python 3.11.9 and Node 24.22.3. All changes remain uncommitted. Original test
assertions, applied migrations, dependency locks and frozen crypto are unchanged.

| Executed check | Result |
|---|---|
| `python -m pytest tests/ crypto_interop/ -q` | **700 passed**, including 29 new Admin cases |
| Frontend `npm test` | **82 passed**, 7 files |
| Frontend `npm run build` | TypeScript and Vite production build pass |
| Original `npm run test:browser` | **7 passed**, Edge on Windows |
| Existing voting browser scenarios | **3 passed**, temporary equivalent port substitutions |
| `npm run test:admin-browser` | **2 passed**, 390px/1440px, including navigation/session retention |
| `node --test crypto_interop/dist/pending_state.test.js` | **2 passed** |
| `npm ci --ignore-scripts`, frontend and crypto_interop | Pass, lockfiles unchanged |
| `python -m pip check` | No broken requirements |
| Existing Voting dependency verifier | All eight exact dependency pins match |
| Changed-source Python/JSON/YAML/Bash parsing | Pass; 10 Python, 2 JSON, 1 workflow, 4 Bash blocks |
| Changed-source secret/whitespace review | Pass; no embedded keys, credentials or token material |
| `git diff --check`, unresolved conflict check | Pass; no conflicts |
| New Admin migrations / real PostgreSQL gate | **NOT RUN**; human review and hosted CI required |

The initial frontend run selected system Python without rfc8785. Rerunning with
`EVOTE_TEST_PYTHON` pointing to the verified project venv passed without changing
tests or dependencies. Existing voting browser ports 5178/8003/8004 were occupied
by another process. That process was preserved; temporary copies used
5188/8013/8014, including the cookie-canary origin substitution. All three original
assertion sets passed and the temporary files were removed. Authentication and
Admin suites used their normal configurations. These are synthetic browser
fixtures, not evidence of real Admin PostgreSQL or combined voter E2E success.
Vite retains the existing blindrsa-ts Node crypto externalization notice; browser
cryptography regression still passes. Native Go and existing real database gates
were not rerun locally.

26 changed/new files:

| Area | Files |
|---|---|
| Admin backend | [package](../backend/admin/__init__.py), [auth](../backend/admin/auth.py), [router](../backend/admin/router.py), [service](../backend/admin/service.py), [store](../backend/admin/store.py), [launcher](../backend/admin/launcher.py) |
| Migration extensions | [RA revision](../migrations/admin_ra/versions/bf932d0f8702_admin_publication.py), [Voting revision](../migrations/admin_voting/versions/af821c9e7601_admin_elections.py), [RA config](../alembic_admin_ra.ini), [Voting config](../alembic_admin_voting.ini) |
| UI | [Admin client](../frontend/src/admin/client.ts), [workspace](../frontend/src/admin/workspace.tsx), [routes](../frontend/src/app.tsx), [shell](../frontend/src/components/shell.tsx), [flags](../frontend/src/config.ts), [styles](../frontend/src/styles.css), [Vite proxy](../frontend/vite.config.ts) |
| Tests/build configuration | [backend tests](../tests/test_admin_management.py), [Admin unit/component tests](../frontend/src/admin/admin.test.tsx), [Admin browser scenarios](../frontend/tests/admin-browser/admin.spec.ts), [browser config](../frontend/playwright.admin.config.ts), [scripts](../frontend/package.json), [TypeScript config](../frontend/tsconfig.json) |
| Disposable CI | [workflow](../.github/workflows/admin-management.yml), [provisioning/integration coordinator](../scripts/admin_postgres_ci.py) |
| Review/startup guide | [this report](./22-admin-election-management.md) |

Review the new SQL and service capability assumptions before publishing. After
human approval, pushing this feature branch will trigger the separate Admin gate;
inspect its `admin-management` job for actual migration, race, rollback, ACL and
cleanup results. A green database-free run alone is insufficient to approve a
deployment. No local database connection or migration, commit, push, merge or
stash removal was performed.
