# Gate 2: local RA issuance and recovery

Implementation awaiting human review and PostgreSQL execution. Gate 1 at
commit `4491cef` passed on GitHub Actions according to the project handoff;
this document does not claim a new native Go or PostgreSQL PASS.
The [frozen v2 protocol](13-credential-protocol-v2.md), existing authentication,
all existing tests, and applied migrations remain unchanged. Voting and Tally
are outside this gate.

## Components and trust boundaries

- [Issuance service](../backend/ra/credential_service.py) verifies the independently
  signed manifest, obtains durable authorization, and orchestrates recovery.
- [PostgreSQL adapter](../backend/ra/postgres_credential_store.py) invokes only
  four restricted functions in a new `ra_credential` schema. It never accepts a
  client voter ID. PostgreSQL resolves identity from an active session.
- [Recovery encryption](../backend/ra/credential_recovery.py) protects only the
  384-byte blind signature using AES-256-GCM with a persistent external key.
- [Local signer adapter](../backend/ra/credential_signer.py) starts the new
  [CIRCL helper](../crypto_interop/signer/cmd/ra-credential-signer/main.go).
  The frozen Gate 1 test signer is unchanged and is not used for runtime keys.
- [Client pending state](../crypto_interop/src/pending_state.ts) uses the same
  pinned `@cloudflare/blindrsa-ts` 0.4.6. `preparePending` verifies the manifest,
  prepares/blinds locally, and persists protected state before returning an RA
  request. `loadPending` reconstructs that exact request after a restart;
  `finalizePending` revalidates the manifest and unblinds/verifies locally.
- [Separate launcher](../backend/ra/credential_launcher.py) explicitly composes
  the existing demo authentication with issuance. The default app has no
  issuance route and keeps login disabled.

RA receives election ID, request ID, and the original blinded representative.
SHA256(blinded_msg) is an equality identifier only. Only the **original 384
bytes** reach CIRCL `BlindSign`; no private RSA exponentiation or ordinary
RSA signing replacement is implemented. The signer never sees serial, ballot
choice, envelope, final credential, voter ID, or session token.

```mermaid
sequenceDiagram
    participant C as Client (protected state)
    participant R as Local RA
    participant D as RA PostgreSQL
    participant S as Local CIRCL process
    C->>C: Verify pinned manifest; Prepare/Blind; persist encrypted pending state
    C->>R: Bearer session + election_id/request_id/blinded_msg
    R->>D: policy_for_session(session digest, election)
    D-->>R: Signed public policy (no private key reference)
    R->>R: Verify independent manifest signature and frozen profile
    R->>D: Transaction 1: reserve_request(session digest, request hash, policy hash)
    D-->>R: COMMIT durable unique authorization
    R->>D: Transaction 2: lock_request, revalidate session/eligibility/policy
    alt Completed exact request
        D-->>R: Protected stored response
        R->>R: AEAD decrypt with request/election context
    else Reserved exact request
        R->>S: Original blinded_msg, configured key ID
        S-->>R: CIRCL blind signature
        R->>R: AES-256-GCM encrypt blind signature
        R->>D: complete_request; reuse protected existing issuance function
        D-->>R: Protected stored response
        R->>R: AEAD authenticate/decrypt persisted response
    end
    R->>D: COMMIT transaction 2
    R-->>C: Blind signature only after successful commit
    C->>C: Unblind/verify using persisted state
```

## Database changes and transaction semantics

The forward-only [revision 7b2d91a6c840](../migrations/ra/versions/7b2d91a6c840_ra_credential_reservations.py)
extends RA head `f3c2a1d4e6b8`. It does not touch Voting objects or rewrite history.
Downgrade refuses to remove authorization tombstones.

Two tables supplement the existing schema:

| Structure | Purpose |
| --- | --- |
| `ra.credential_policies` | Immutable signed public manifest, Ed25519 signature, SHA256 config hash, existing key ID/fingerprint, opening/closing times, one-way issuance disable switch |
| `ra.credential_reservations` | UUID, voter/election FK, original request UUID and blinded hash, key/config binding, database reservation timestamp and recovery deadline; UNIQUE(voter_id,election_id) |

Completed credentials continue to use existing `ra.blind_issuances`, its unique
voter/election authorization, encrypted recovery columns, and protected
`ra.issue_blind_credential` function. No duplicate completion table is added.
Legacy completed issuances without a Gate 2 reservation cause 409, preserving
the record without assuming compatibility with its previous recovery AAD.

The shared lock order is voter (UPDATE), session (SHARE), eligibility (UPDATE),
reservation (UPDATE), completed issuance (UPDATE), signing key (SHARE), policy
(SHARE). The original completion function reacquires already held locks in its
existing compatible order. Policy lookup also serializes on voter/session.
Authenticated issuance never locks a key before its voter/eligibility rows.
Owner enrollment/retirement should be scheduled outside concurrent issuance.
Deadlocks, statement timeouts, and connection failures return sanitized 503;
the client retries the same state. The production connection factory uses
5-second statement and 2-second lock timeouts; signer RPC timeout is 3 seconds.

Transaction 1 must commit successfully before any signer invocation. Transaction
2 holds the authorization locks through signing, encrypted completion, and commit.
A second request waits and then either replays the completion or conflicts with
the durable reservation. UNIQUE is the database backstop, independent of Python
locks. Different voters may use the same client-supplied request UUID; ownership
is always the authenticated voter/election pair.

Reservation fields cannot be updated. The existing trusted eligibility function
permits eligibility changes before completion but rejects changes after a
completed issuance. Revoking eligibility after reservation cannot release its
slot. Voter deactivation remains possible through existing trusted administration;
every retry rechecks eligibility and active status. Foreign keys prevent deleting eligibility/key/policy rows
out from under a retained reservation. Enrolled key material and manifest fields
cannot be replaced. Policy creation verifies key metadata consistency;
cryptographic manifest verification occurs in the service against its external
pin, not inside PostgreSQL. Policy key fingerprints are unique across elections.

New reservations require an eligible active voter, live session, ACTIVE signing
key, enabled policy, and database time in `[opens_at, closes_at)`. Exact reserved
requests may finish after closing, until the recovery deadline, provided the key
is ACTIVE and issuance is enabled. This only recovers an authorization already
spent during the opening period; it does not extend any future voting deadline.
Completed exact replays do not require the signer or an ACTIVE key, but do still
require live authentication, eligibility, and recovery retention.

## Recovery contract

The database sets the deadline to immutable `closes_at + 24 hours`. It controls
reservation and completion timestamps. At/after the deadline, an exact retry is
410. A different request remains 409 forever. Reservations and completed
authorization records are retained as tombstones; there is no reset/reissue API,
reservation cancellation, cleanup job, or admin override in this implementation.
The baseline permits a PURGED recovery state, but the applied migration chain
does not define a protected purge function. Gate 2 introduces no purge operation
or runtime table access. Any future separately reviewed purge must erase only
expired recovery data while retaining completed issuance and reservation tombstones.

| Failure point | Exact retry | Different request |
| --- | --- | --- |
| Before reservation commit | May establish original authorization | May establish authorization if no commit occurred |
| After reservation commit, before signing | Sign original bytes | 409 |
| Signer failure or lost signing response | Sign original bytes again; same RSA operation/result | 409 |
| After signing, before completion commit | Re-sign same bytes, persist under a new AES nonce | 409 |
| Completion commit succeeded, HTTP response lost | Decrypt/replay stored response (200) | 409 |
| Commit outcome unknown | 503; exact retry distinguishes durable state | 409 if reservation committed |
| Recovery deadline elapsed or client state lost | No new credential; authorization stays consumed | 409 |

RA stores only ciphertext (400 bytes including GCM tag), random 12-byte nonce,
external storage-key ID, and required reservation/issuance metadata. Its AEAD AAD
is a versioned domain plus JCS reservation/voter/election/request IDs,
blinded/config hashes, signing/storage key IDs, and normalized UTC recovery
deadline. Copying ciphertext between voters, requests, elections, or keys fails
authentication. Plaintext blind signatures exist transiently in process memory
and in the authorized HTTP response only.

Client recovery uses AES-256-GCM, random salt/nonce, and scrypt
N=65536/r=8/p=1 to derive the key from a private recovery passphrase of at least
12 characters. The ciphertext includes all contextual fields, prepared message,
serial, inverse and original blinded bytes. File publication is exclusive and
atomic on a filesystem supporting hard links; file contents are flushed before
publication. Existing pending state is never overwritten. This protects process
restart recovery, not guaranteed power-loss durability on every filesystem.
Use a private directory, restrictive OS ACLs (especially on Windows), a strong
passphrase and an encrypted backup. Keep the pending file until the finalized
credential has been safely protected by its caller. Never transmit the pending
state to RA. Losing the passphrase/state or recovery master key cannot reset
voter authorization.

## HTTP contract

`POST /api/v1/ra/credentials/issue` requires one canonical Bearer token from the
existing demo login. The explicit SHA256(token ASCII) session digest is reused;
the generic session service's decoded-token digest behavior is unchanged.

Request has exactly:

```json
{"election_id":"canonical-lowercase-UUID","request_id":"canonical-lowercase-UUID","blinded_msg":"canonical-unpadded-base64url-of-384-bytes"}
```

This example uses descriptive placeholders, not valid wire values. Bodies are
limited to 4096 bytes; duplicate JSON fields and unknown fields are rejected.
No voter ID, serial, envelope, finalized credential, ballot, or voting receipt is
accepted. The RSA representative must be greater than zero and below the pinned
modulus, before authorization is reserved.

New completion: 201; exact committed replay: 200.

```json
{"status":"issued","ra_key_id":"configured-key-id","profile":"RSABSSA-SHA384-PSS-Randomized","blind_sig":"canonical-unpadded-base64url-of-384-bytes"}
```

Replay uses `status: replayed`. Invalid authentication is generic 401 with
WWW-Authenticate: Bearer; inactive voters also get 401. Ineligible/disabled/not
open issuance: 403. Conflicting request or old completed issuance: 409. Recovery
deadline/purge: 410. Invalid body/encoding/representative: sanitized 422 (413 for
oversized bodies). Database/signer/configuration/decryption/commit failures: 503.
All credential responses use Cache-Control: no-store, including 404/405 and
local-origin rejection. No exception details or rejected secret inputs are
returned. Login/Me/Logout contracts and login rate limiting are reused unchanged.

## Roles, provisioning and deployment

[Existing provisioning definitions](09-ra-demo-provisioning.md) define the
restricted authentication login and explain the incomplete legacy-role creation
inventory. A deployment administrator must separately provision
`ra_issuance_login` as LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE
NOREPLICATION NOBYPASSRLS, without memberships to or from it, with CONNECT on the
RA database and a separately managed password/connection limit. Do not make it
a member of owner/migrator/service roles or grant general RA access. No role is
created or changed by this migration, launcher or test harness.

The migration fails before creating objects if required roles are missing:
ra_owner, ra_auth_login, ra_issuance_login, ra_service, ra_service_login,
ra_recovery_worker, ra_audit_reader. Owner must be a restricted NOLOGIN role.
Auth/issuance effective schema, table, column, sequence and general function ACLs
and both directions of role membership are checked. PUBLIC EXECUTE and composite
type usage are revoked; unexpected function/table default grants abort migration.

| Runtime principal | New access |
| --- | --- |
| `ra_issuance_login` | USAGE on ra_credential schema/context type; EXECUTE only policy_for_session, reserve_request, lock_request, complete_request |
| `ra_auth_login` | None; its existing four demo wrappers remain unchanged |
| PUBLIC and other existing runtime roles | None |
| `ra_owner` | Owns new tables/schema/type/SECURITY DEFINER functions; fixture/deployment only |

The `_voter` and `_request` helpers and trigger functions have no runtime
EXECUTE grant. Every new function has fixed `search_path=pg_catalog,ra,pg_temp`
and qualified application objects. SQL arguments are bound parameters.
General RA function/table privileges are never granted to a runtime caller.

### Defined service audit identity

The applied [issuance function](../migrations/ra/versions/1dcfbb1dd9a4_ra_issue_blind_credential_protected.py)
takes ten arguments ending in `p_actor_principal_id uuid`. This argument is
required and recorded with `actor_type=SERVICE`; it does not authorize the call.
The applied [baseline](../migrations/ra/versions/e52b0a9227ef_create_ra_schema_baseline.py)
defines an opaque non-null actor UUID with no actor registry or actor foreign key.
EXECUTE privileges and the wrapper's session/eligibility checks provide authorization.

Gate 2 assigns UUID `00000000-0000-4000-8000-000000000002` to the **local RA
credential-issuance service**, whose runtime boundary is ra_issuance_login. The
unapplied migration now declares it as `service_actor_id CONSTANT uuid` and
publishes the mapping in COMMENT ON FUNCTION complete_request. All local
instances of this service share this audit identity; it does not identify a
specific host, operator, voter or session. It is public audit metadata, contains
no PII, and must not be reused to label another service. No new principal table,
role membership, or EXECUTE grant is necessary under the existing audit contract.

Clients cannot choose this actor ID: the HTTP model and exported function
signatures have no actor parameter. The migration is the trusted source of this
mapping. Owner access remains trusted; the UUID itself confers no privileges.
Fixture operations use a separate random per-run SERVICE actor through the
existing owner-only eligibility/disablement functions.

First completion and its BLIND_ISSUANCE_ISSUED/SUCCESS event commit atomically
through the existing function. If audit insertion fails, completion rolls back
and the HTTP request fails; the earlier durable reservation remains consumed.
The old function also has a BLIND_ISSUANCE_REPLAYED branch when directly called
with its matching completed request. Gate 2's cached HTTP recovery reads the
already protected response instead of calling that function again, so HTTP 200
replays do not generate that event. No per-replay audit coverage or cryptographic
audit tamper evidence is claimed.

After separate human-approved provisioning and migration, an owner enrolls an
independently signed public manifest and matching ACTIVE metadata. Verify the
manifest with the offline Ed25519 authority, pin its public key independently
on both client and RA, and check canonical bytes, key ID, SPKI, fingerprint,
times and config hash before inserting the policy with issuance enabled. Do not
expose the authority private key to RA or reuse one RA signing key across elections.
The implementation exposes no HTTP enrollment/key-generation/policy-write API.

The launcher is explicitly activated as follows, using operator-provided paths:

```powershell
python -m backend.ra.credential_launcher --enable-local-demo --load-local-verifier --enable-credential-issuance --signer-binary C:/trusted/ra-credential-signer.exe --encrypted-signing-key C:/private/encrypted-ra-key.pem --manifest-authority-pin C:/trusted/manifest-public-pin.bin --key-id reviewed-ra-key-id --recovery-key-id reviewed-recovery-key-id
```

Only launch after review. Paths and key IDs are public configuration; no secret
belongs on the command line. The launcher explicitly reads the existing fixed
local verifier and prompts without echo for auth/issuance DB passwords, persistent
32-byte AES key (canonical base64url), and encrypted PKCS8 unlock passphrase.
It never discovers dotenv, plaintext keys, or database URLs. The authority file
contains only raw 32-byte Ed25519 public data. Use restrictive OS file ACLs and
reviewed binaries. Startup failures are sanitized.

Runtime connects only to 127.0.0.1:5432/ra_db with ra_auth_login for auth and
ra_issuance_login for issuance, and checks connection identity. It binds HTTP
only to 127.0.0.1:8000, with one worker, no proxy-header trust, no unrestricted
CORS, strict local Host/Origin/peer validation and access logging disabled.
Signing key DER is passed to the helper only through a private process pipe,
never argv, environment, HTTP or a plaintext file. Helper stderr is discarded;
invalid/late RPC responses close the helper and cause 503. Restart the service
with the same encrypted signing key, recovery key and pin after such a failure.

The recovery library supports an external keyring; keep old decryption keys
until all relevant deadlines and backup retention have elapsed. The simple
launcher accepts one key, so live rotation with several retained keys needs
explicit composition using CredentialRecovery's keyring, not key replacement
under an existing ID. Changing election signing material after enrollment is
forbidden; retirement/disable may stop unfinished requests permanently.

## Validation and later human-approved commands

The [disposable integration harness](../scripts/ra_credential_disposable_integration.py)
does not run during pytest. It requires both a `ra_demo_test_*` database name and
an independently installed database comment `secure-evoting-disposable:<UUID>`.
Every runtime, fixture and cleanup connection rechecks that designation.
It refuses ra_db before requesting passwords. Fixture-only
ra_migrator_login SET LOCAL ROLE ra_owner is separate from runtime
ra_issuance_login; the helper performs no migration, role, grant or database
creation. Fixture voters explicitly have is_active=true, unique random identities,
and UUID-scoped cleanup. The existing demo voter is never selected or modified.
Eligibility is created by the existing owner-only
`ra.set_voter_eligibility(uuid,uuid,boolean,uuid)`, which generates the required
eligibility_id and writes its audit event. No applied migration gives that
primary key a default. The harness checks the generated UUID and eligible flag
before issuing the fixture session, and also uses trusted functions for
revocation/disablement. These operations are never granted to runtime callers.

After human review, on an approved Ubuntu/native-Go host, prepare dependencies
and compile/run tests (all versions remain pinned):

```bash
python3.11 -m venv /tmp/evote-gate2-python
/tmp/evote-gate2-python/bin/python -m pip --isolated install --no-deps -r backend/ra/credential-requirements.lock.txt
/tmp/evote-gate2-python/bin/python -m pip check
npm --prefix crypto_interop ci --ignore-scripts
npm --prefix crypto_interop run build
EVOTE_TEST_NODE="$(command -v node)" /tmp/evote-gate2-python/bin/python -m pytest tests/ crypto_interop/ -q
node --test crypto_interop/dist/pending_state.test.js
(cd crypto_interop/signer && GOTOOLCHAIN=local GOFLAGS=-mod=readonly GOWORK=off go test -count=1 ./...)
(cd crypto_interop/signer && GOTOOLCHAIN=local GOFLAGS=-mod=readonly GOWORK=off go build -o /tmp/ra-credential-signer ./cmd/ra-credential-signer)
```

Use Node 24.22.3, Go 1.25.14 and Python 3.11; retain Gate 1's full-vector gate.
Then, **only after separately approving and applying the reviewed migration to
an independently designated disposable PostgreSQL 18 database**, run:

```bash
/tmp/evote-gate2-python/bin/python scripts/ra_credential_disposable_integration.py --disposable-fixture-writes --database ra_demo_test_gate2 --disposable-marker REPLACE_WITH_DATABASE_COMMENT_UUID --signer-binary /tmp/ra-credential-signer --node "$(command -v node)"
```

Passwords are entered through getpass, not shell commands or repository files.
No Alembic execution command is supplied as an implicit approval. Required live
checks include migration SQL/trigger compilation, role/ACL assertions,
two-connection concurrent different/identical requests, correct identity isolation,
reservation/signing/commit fault recovery, encrypted storage, disabled/expired/
revoked sessions, ineligible voters, expiry tombstones, immutable key/policy,
and a real TS -> HTTP -> PostgreSQL -> CIRCL -> TS -> Python round trip.
Process/response loss uses fault injection at actual transaction boundaries;
this is not evidence of a PostgreSQL-server crash or power-loss durability test.

Actual local validation (Python 3.11.9, Node 24.22.3, Go 1.25.14):

| Check | Result |
| --- | --- |
| Complete database-free Python/TypeScript pytest suite | 394 passed in 18.84s (279 previous application tests + 40 previous crypto tests + 75 new tests) |
| TypeScript compiler | PASS |
| Node protected pending-state tests | 2 passed, including real randomized Prepare/Blind |
| New runtime CIRCL helper build | PASS; binary produced in OS temp outside Git |
| Native Go tests | Prior execution BLOCKED by Windows Application Control; final-review test-binary compilation with default vet also BLOCKED at vet.exe. Runtime go build passes; no native execution PASS claimed |
| Combined Python dependency locks, dry run and pip check | Already satisfied; no broken requirements |
| git diff --check and checks of untracked additions | PASS (checked separately because additions are not staged) |
| Secret review of new files | No private-key blocks, credential-bearing PostgreSQL URLs or common access-key/token patterns; prompts and test-only fixtures inspected |
| Existing tracked application files, tests, applied migrations and crypto protocol | Unchanged against HEAD; only the existing CI workflow is modified |
| PostgreSQL migration, concurrency and runtime signer integration | NOT RUN; awaiting human approval and permitted native execution |

No PostgreSQL connection, migration, role/grant change, existing local credential
or election private-key read, real-voter change, real credential consumption,
commit or push occurred. Launcher tests use only newly generated temporary TEST keys.
Native Go execution remains BLOCKED until tested on a permitted host. Existing
Gate 1 PASS is project-provided prior evidence, not a new full-gate execution.

## Change inventory

Gate 2 adds 23 new uncommitted files and modifies only the existing CI workflow.
The final-review correction pass changes seven paths, listed below.

- Runtime: [credential_service.py](../backend/ra/credential_service.py),
  [postgres_credential_store.py](../backend/ra/postgres_credential_store.py),
  [credential_recovery.py](../backend/ra/credential_recovery.py),
  [credential_router.py](../backend/ra/credential_router.py),
  [credential_runtime.py](../backend/ra/credential_runtime.py),
  [credential_signer.py](../backend/ra/credential_signer.py),
  [credential_launcher.py](../backend/ra/credential_launcher.py),
  [credential-requirements.lock.txt](../backend/ra/credential-requirements.lock.txt).
- Signer: [main.go](../crypto_interop/signer/cmd/ra-credential-signer/main.go),
  [main_test.go](../crypto_interop/signer/cmd/ra-credential-signer/main_test.go).
- Client: [pending_state.ts](../crypto_interop/src/pending_state.ts),
  [pending_state.test.ts](../crypto_interop/src/pending_state.test.ts).
- Database: [new migration](../migrations/ra/versions/7b2d91a6c840_ra_credential_reservations.py),
  [disposable integration harness](../scripts/ra_credential_disposable_integration.py).
- Tests: [credential_helpers.py](../tests/credential_helpers.py),
  [service](../tests/test_ra_credential_service.py),
  [HTTP](../tests/test_ra_credential_http.py),
  [store](../tests/test_ra_credential_store.py),
  [runtime](../tests/test_ra_credential_runtime.py),
  [migration](../tests/test_ra_credential_migration.py),
  [disposable safety](../tests/test_ra_credential_disposable_safety.py),
  [CI coverage](../tests/test_ra_credential_ci.py).
- Existing CI workflow: [rsabssa-interop.yml](../.github/workflows/rsabssa-interop.yml).
- This document: [14-ra-credential-issuance-recovery.md](14-ra-credential-issuance-recovery.md).

## Final-review corrections and database contract review

This pass changes only the [disposable harness](../scripts/ra_credential_disposable_integration.py),
[unapplied migration](../migrations/ra/versions/7b2d91a6c840_ra_credential_reservations.py),
[migration contract tests](../tests/test_ra_credential_migration.py),
[fixture tests](../tests/test_ra_credential_disposable_safety.py),
[new CI coverage test](../tests/test_ra_credential_ci.py),
[existing workflow](../.github/workflows/rsabssa-interop.yml), and this document.
All previous implementation changes remain uncommitted.

The final applied schema was reconstructed by following all 12 repository
revisions from the baseline through f3c2a1d4e6b8, without importing or executing
migrations. No live schema or ACLs were queried; deployment drift remains a
separate PostgreSQL verification item.

| Contract reviewed | Repository evidence and correction/result |
| --- | --- |
| IDs, defaults and keys | Eligibility UUID has no default in the baseline or later applied revisions. Fixture setup now delegates UUID generation, eligibility mutation and audit to the trusted function and checks its result. Voter UUIDs remain explicit with is_active=true; completed issuance/audit UUIDs are generated by their existing functions. |
| Foreign keys and authorization uniqueness | Existing eligibility UNIQUE(voter_id,election_id), completed issuance UNIQUE(voter_id,election_id), key UNIQUE(election_id,ra_key_id), and recovery/session checks match the new reservation references and column types. |
| Function signatures and actor | Ten-argument issue_blind_credential and four-argument set_voter_eligibility are matched exactly. The runtime SERVICE actor is now named and documented in SQL/catalog comments; it remains fixed outside client control. The manual harness asserts the actual issuance audit actor. |
| Lock order | Voter precedes session/eligibility/reservation/completion/key/policy. Existing eligibility mutation serializes on voter then eligibility; existing completion reacquires voter/eligibility/completion/key in compatible order. New wrappers and previous ownership checks remain restricted. |
| Session checks | Existing find_active_session was hardened to VOLATILE. The new wrapper rechecks active voter and locks/revalidates nonrevoked, unexpired session using database clock time. Fixture session creation retains the existing 15-minute maximum. |
| Eligibility management | Trusted mutation rejects changes after completed issuance. Fixture grant/revocation and voter disablement now use the trusted functions rather than bypassing their auditing behavior. A reservation is never released by eligibility revocation. |
| Expiry and audit | Database-controlled issuance time and reservation deadline are passed to the existing completion function; invalid expiry or audit failure aborts completion. Reservation expiry/purged recovery never restores eligibility. Cached replay does not invoke the legacy replay-audit branch; this limitation is documented above. No protected purge function exists in the applied chain. |

Nine new database-free regression cases cover generated eligibility IDs and
fail-closed fixtures, the actual migration chain and completion signature/audit
mapping, lock/session/expiry contracts, and Linux workflow coverage. These are
offline checks, not evidence of PostgreSQL execution or lock scheduling.

The Ubuntu workflow now triggers on pushes to feat/ra-credential-issuance-recovery
as well as the original Gate 1 branch. Its existing `go test -count=1 -v ./...`
recursively executes the runtime helper's generated RSA-3072 test, including
original-byte signing, Finalize, and digest/key/reinitialization rejection. A new
step builds the runtime helper in RUNNER_TEMP. The required Ubuntu commands are:

```bash
go test -count=1 -v ./...
go build -o "$RUNNER_TEMP/ra-credential-signer" ./cmd/ra-credential-signer
```

Both run from the existing signer module with Go 1.25.14 and the unchanged CIRCL
lock. Pinned actions, contents: read, read-only module installs, default vet,
fail-on-error shell behavior, no credentials/databases and no artifact uploads
remain in place. Existing Gate 1 vector/interoperability coverage is preserved;
new runtime signer tests use only ephemeral generated test keys.

**GitHub Actions has not run these changes.** After human review, require the
Ubuntu run for the exact reviewed commit to pass. Then separately approve the
disposable PostgreSQL provisioning/migration and run the manual harness command
above. Migration status is ready for human review and disposable execution,
not a claim of SQL-engine, live ACL, concurrency or real-database integration PASS.

## Security limits

This is a local demo, not production key isolation: RA/Python and the signer run
under the same OS principal and both handle signing material in memory. Python
cannot reliably erase all immutable key/password copies, and process dumps,
swap, hostile same-user processes and filesystem permissions remain operator
risks. No HSM, signer-side database authorization attestation, or hardware
non-exportability is claimed. Anyone who compromises the RA process/key can
sign extra credentials outside database authorization. Anyone who steals a live
session can consume its voter's slot. Owner/migrator roles remain trusted.

The existing demo password/session issuer is not production voter authentication;
ra_auth_login can issue sessions for its fixed demo identity. A reserved but lost
client state intentionally sacrifices availability instead of issuing a second
independent credential. Key loss or retirement can make pending recovery fail.
Completed blind signatures cannot be revoked individually from an anonymous
credential through voter identity.

RA knows voter/election authorization and request timing; network metadata,
local browser/process state, client backups, reverse proxies, endpoint telemetry,
operator access and later submission timing can correlate users. Avoid request
body/token logging, use separate services and independently distributed trust
pins, and assess batching/transport privacy in later gates. Full anonymity,
coercion resistance and full end-to-end verifiability are not claimed.

RA cannot validate hidden serial, envelope binding or ballot choice. The client
and a future Voting verifier must enforce the frozen credential/config binding.
Encrypted candidate-choice validity is deferred to Tally in this local demo.
This gate has no Voting endpoint, spending transaction, election-close authority
integration, anonymous receipt or Tally. No real credential should be consumed
until the PostgreSQL approval gate and subsequent deployment review complete.
