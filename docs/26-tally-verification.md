# Commit 9 restricted Tally and verification

Branch `feat/tally-verification`, base `main` at `9cd8647`. The separate Tally
runtime verifies committed encrypted ballots, decrypts after closure and returns
authorized aggregate reports. **The new migration and real PostgreSQL Tally gate
have not executed.** Local regression evidence is recorded below; existing
component and Admin-to-Voter CI results do not establish a PASS for this subsystem.

## Architecture and authorization

```text
Tally operator UI -> loopback Tally API -> voting_tally_login
                                           |
                         restricted SECURITY DEFINER functions
                                           |
                    Voting snapshots, jobs, reports and audit
                                           |
                     private signed evidence outside the DB

Independent manifest pin -> frozen configuration verification
Independent snapshot pin -> private snapshot and aggregate signatures
Encrypted election-specific Tally RSA key -> verified ciphertext decryption
```

Admin, RA and anonymous Voting services receive no Tally private key or passphrase.
The default `backend.main.app` has no Tally routes. Only the explicit local
launcher activates Tally, binds 127.0.0.1:8005, disables proxy trust, access logs,
OpenAPI/docs and CORS, and retains the existing peer/Host/Origin checks. All Tally
responses are `no-store`; errors have fixed messages/codes and never echo inputs.
Blocking cryptographic/database work runs in a thread pool, with DB concurrency
control authoritative across processes.

Tally has independent operator principals, scrypt credentials and sessions.
Principals default inactive and require trusted enrollment as `TALLY_OPERATOR`.
Password verification reuses the reviewed scrypt parameters and the process-local
five-failures/60-second limiter. Tokens are canonical `tly1.` plus 32 random bytes;
the DB stores SHA256(`EVOTE-TALLY-SESSION-v1\0` || ASCII token), with a DB-controlled
15-minute TTL and revocation. Admin/voter bearer formats fail before DB access.
Every RPC checks the active operator/session and exact login identity.

The new `voting_tally_login` must be LOGIN, NOINHERIT, NOSUPERUSER, NOCREATEDB,
NOCREATEROLE, NOREPLICATION, NOBYPASSRLS, without memberships. It has no direct
table/column DML, sequence privileges, baseline Voting/Admin function execution
or schema CREATE. It receives schema USAGE and ten narrow Tally RPC EXECUTE grants.
The login is a capability of the trusted Tally process: it can mint sessions for
active operators, and the database does not verify the operator's human password.
Protecting that credential and the Tally process remains essential.

## Verification and classification policy

The signed election manifest is verified against the independently configured
Ed25519 pin. Its exact canonical bytes, configuration digest, authority fingerprint,
election ID, windows, RSA-3072/e=65537 key IDs/SPKIs/fingerprints and frozen roster
are checked. Snapshot signing uses a different, independently pinned Ed25519 key;
the launcher requires encrypted PKCS8 for this key too. It cannot reuse the
election-manifest authority pin. The Snapshot/RA/Tally cryptographic roles remain
distinct.

The implementation follows Document 09's snapshot object, receipt-sorted encrypted
record format, unsigned manifest fields and `EVOTE-SNAPSHOT-v1\0` signing context.
No public Board endpoint is implemented. The snapshot contains only encrypted
envelopes and credential verification metadata, including serials needed for AAD.
Those private input records are available only through authorized Tally DB RPCs
and private evidence files, never HTTP, UI, ordinary logs or uploaded artifacts.

Before loading the RSA private key, every record must pass the existing frozen
RSABSSA finalized-signature, canonical message, envelope, election/key/configuration
binding and original receipt verification. Serial/receipt duplicates are rejected.
The SQL snapshot check independently requires the exact committed record set,
envelope hashes and recomputed original receipts. It cannot omit, duplicate or
substitute a committed record and still pass normal finalization.

There are two distinct failure classes:

| Observation | Policy |
|---|---|
| Broken manifest/snapshot signature, receipt, stored envelope hash, credential proof, dataset binding or evidence | Abort the whole tally as `INTEGRITY`; keep CLOSED; no aggregate result |
| Missing key file, incorrect passphrase, wrong key ID/SPKI/fingerprint/profile | Abort as `KEY_UNAVAILABLE`; do not classify all ballots invalid |
| Authentic committed envelope fails RSA-OAEP or yields a non-32-byte AES key | One invalid ballot, reason `KEY_WRAP` |
| Authentic committed envelope fails AES-GCM authentication | One invalid ballot, reason `AEAD` |
| Decrypted JSON is noncanonical/malformed, has extra fields, wrong version/election or a candidate outside the signed roster | One invalid ballot, reason `PLAINTEXT` |

RSA wrapping uses OAEP SHA256/MGF1-SHA256 with the existing empty label. AES uses
256-bit GCM, the existing 12-byte nonce/tag format and exact JCS AAD
`{schema_version:1,election_id,serial}`. Plaintext has exactly schema_version,
election_id and candidate_id; it must name one signed candidate. Candidate counts
are sorted by canonical candidate UUID. Identical choices from distinct valid
credentials each count once. No plaintext individual classification is persisted.

Every accepted record receives exactly one valid/invalid classification. Mandatory
equalities are accepted=valid+invalid, counted=valid, sum(candidate counts)=valid
and sum(invalid reason counts)=invalid. No invalid ballot is silently dropped.
Candidate choices and AES plaintext buffers remain local to counting and leave
only aggregate counters. Python does not guarantee complete immediate memory
zeroization; this is a restricted local process, not HSM isolation.

## Transactions, idempotency and crash recovery

1. **Durable claim:** lock the election, require reconciled CLOSED state, enforce
   the local 1000-ballot bound, allocate a PREPARING baseline snapshot if needed,
   insert a RUNNING baseline tally job, increment the election fencing token and
   commit its five-minute DB lease and audit. One active job is allowed by the
   existing unique index. No private key is loaded here.
2. **Snapshot transaction:** lock election/job, verify active lease/fence/session,
   read committed inputs, verify public cryptography, construct deterministic JCS,
   sign/preserve private evidence, then atomically store snapshot bytes and mark
   the baseline snapshot FINALIZED. Commit before RSA key loading/decryption.
3. **Counting transaction:** lock the same election/job, verify finalized DB data
   against the independently configured pins and private evidence, load and match
   the encrypted RSA key, classify/count, sign and preserve the aggregate report,
   then insert the baseline report, mark the job SUCCEEDED and transition election
   and Admin control phase to TALLIED in one transaction. Recheck DB lease before
   final success. The receipt contract and accepted rows stay unchanged.
4. **Response:** reread and verify the committed signed aggregate report. A return
   is successful only after its database transaction committed.

All Tally operations use a transaction advisory lock, election row FOR UPDATE
NOWAIT, then job/snapshot locks. Concurrent requests fail with 409 or recover the
same completed report. Ballot acceptance, Admin closure and Tally share the
authoritative election-row lock. New accepted-row triggers also lock that row,
forbid inserts outside OPEN, and reject UPDATE/DELETE. Finalized snapshots,
snapshot bytes, reports and report signatures are immutable.

Caught failures roll back their current transaction and try to persist a separate
privacy-safe FAILED job/audit, leaving CLOSED state. A finalized snapshot is
retained after failed counting and reused. Crashes before failure recording leave
a durable RUNNING claim: after lease expiry, a new claim records recovery, marks
the old attempt failed and advances the fencing token. The old worker cannot
finalize. This local implementation has no lease extension/heartbeat; work must
finish inside five minutes and the 1000-ballot bound. It fails instead of counting
an arbitrary sample. Large-election streaming is future work.

After a lost COMMIT response, recovery reads the existing report before retrying.
Failure recording cannot overwrite SUCCEEDED. Repeated successful execution
returns the same signed report without decrypting again or creating another tally.

## Private evidence and verification boundary

Private mode-0600 snapshot/report evidence files live under an explicit private
directory, separate from the Voting database. Canonical bytes and Ed25519 signatures
are preserved with a flushed staging file and atomic no-overwrite hard link;
the directory is fsynced on POSIX. Existing evidence must match exactly. Report
signatures use the separate `EVOTE-TALLY-REPORT-v1\0` context over canonical
aggregate JSON. Database report/snapshot digests and signatures are verified
against this preserved evidence before returning aggregates.

Filesystem writes and database commits are not atomic. A crash can leave an
orphaned staging/evidence file. Deterministic retries reuse identical evidence;
they never overwrite conflicting bytes or replace a finalized snapshot. Lost or
corrupt authoritative evidence requires trusted backup restoration/operator review,
not silent regeneration. Protect the directory with restrictive Windows ACLs or
POSIX permissions; keep keys/evidence outside Git and web-served directories.

This separate storage detects database-only substitutions under the configured
pins. It is not an independently operated Auditor, hardware key custody or proof
that a malicious authorized worker counted honestly. SQL validates dataset/totals
and privileges, but cannot itself prove RSA decryption or Ed25519 signing without
trusting the restricted process. Independent public evidence, Board publication
and public results remain Commit 10 work. No complete end-to-end verifiability,
full anonymity or coercion resistance is claimed.

## API and Admin UI inventory

All routes are on the separately activated Tally service under `/api/v1/tally`.
Mutation JSON is exact; queries and identity-bearing extras are rejected.

| Method/path | Contract |
|---|---|
| POST `/auth/login` | username/password; returns access_token and token_type=`bearer` |
| GET `/auth/me` | operator_id and role=`TALLY_OPERATOR` |
| POST `/auth/logout` | `{}`; 204 only after successful DB revocation |
| GET `/elections` | bounded list of CLOSED/TALLIED managed elections with reconciliation status |
| POST `/elections/{id}/run` | `{}`; 200 signed aggregate evidence after commit or idempotent replay |
| GET `/elections/{id}/report` | verified committed aggregate report; 404 when unavailable |

Errors are sanitized: 401 authentication, 404 unavailable report/election, 409
state/lease conflict, 422 malformed request, 429 failed-login limit, 503
`KEY_UNAVAILABLE`, `INTEGRITY` or `UNAVAILABLE`. These distinctions expose no
individual ballot, serial, RA request ID or private key detail.

The response contains report, report_digest, signature, signing_key_id and public
candidate labels. Report fields are version/election/config/snapshot/algorithm
bindings, accepted/valid/invalid/counted totals, candidate_counts and aggregate
invalid_reasons. It contains no individual record or key material. Snapshot and
report signatures are verification evidence, not a claim of public publication.

`/admin/tally` uses an independent in-memory Tally client only when both local-demo
mode and `VITE_ENABLE_TALLY=true` are explicit. It requires a Tally operator login,
reconciled CLOSED selection and confirmation before running, and offers committed
report recovery after response loss. It shows authorized aggregates and invalid
reason totals. It does not accept key files/passphrases or reuse Admin/voter
bearers. Responses are verified by the Tally service; browser-side independent
aggregate-signature verification is not implemented. All Public Results and Board
screens remain unavailable. Existing Admin/Voter behavior remains unchanged by
default.

## Migration and permissions

New forward revision `e6a90c72b541` follows `af821c9e7601` in an opt-in Tally
version directory, configured by [alembic_tally.ini](../alembic_tally.ini). Existing
baseline/Admin configurations and applied histories remain unchanged. The Tally
graph is five Voting revisions: three baseline, Admin, then Tally. RA migrations
are not needed: the Tally runtime has no RA database credential or connection.

The migration reuses final_snapshots, tally_jobs, tally_reports, election fencing,
active-job FK, unique running/succeeded/finalized indexes and existing audit event
categories. It adds only private principals/sessions, snapshot bytes and report
signature tables, ten restricted RPCs and owner-only helpers. Admin control phase
is extended to TALLIED with a new forward CHECK. It adds the immutable-evidence
triggers described above; no old migration is edited.

Preflight requires the separately provisioned safe `voting_tally_login` and rejects
unsafe inherited/effective ACLs. It never creates roles. All functions are owned
by voting_owner, SECURITY DEFINER, with pg_catalog first, trusted schemas only,
pg_temp last and PUBLIC execution revoked. Only the new login receives the ten
RPCs; internal helpers are not executable by runtime. Table DML is not granted.
Postflight rejects unexpected owners, definer flags and function/table ACLs.
Relation privilege checks use CASE guards for mixed pg_class object kinds.

RPCs: login_session(uuid,bytea), session(bytea), logout(bytea), list_elections(bytea),
claim(bytea,uuid), work(bytea,uuid,uuid,bigint), seal(bytea,uuid,uuid,bigint,jsonb),
complete(bytea,uuid,uuid,bigint,bytea,bytea), fail(bytea,uuid,uuid,bigint,text), and
view_report(bytea,uuid). JSON is returned only by login/session/list/claim/work/view;
logout/seal/complete/fail return void. `work` is private runtime input, never HTTP.
The downgrade refuses destructive automatic removal of tally/audit evidence.

## Deployment after human approval

First require a passing disposable CI gate and review the new SQL. A trusted
operator must provision the restricted login, grant CONNECT only on Voting,
apply the opt-in migration, and enroll an active TALLY_OPERATOR UUID. None of
these operations were performed against user databases during implementation.

Create an explicit private verifier JSON with enabled=true, environment="local-demo",
operator_id, username, salt and digest. Salt/digest are canonical base64url;
derive a 32-byte scrypt digest with N=16384/r=8/p=1 and a random salt at least
16 bytes. Store no plaintext password. Use the existing election's matching
encrypted RSA-3072 Tally key; generating a replacement cannot decrypt its ballots.
Separately provision an encrypted Ed25519 snapshot key and its independently
preserved raw 32-byte public pin, distinct from the election authority pin.

From the repository root, after approved provisioning:

```powershell
python -m backend.tally.launcher --enable-local-tally `
  --verifier C:/private-config/tally-verifier.json `
  --authority-pin C:/private-config/election-authority-public.bin `
  --snapshot-key C:/private-config/snapshot-authority-encrypted.pem `
  --snapshot-pin C:/private-config/snapshot-public.bin `
  --snapshot-key-id snapshot-authority-01 `
  --encrypted-tally-key C:/private-config/election-tally-encrypted.pem `
  --tally-key-id matching-signed-election-key-id `
  --evidence-directory C:/private-evidence
```

The launcher prompts privately for the runtime DB password, snapshot-key
passphrase and Tally RSA passphrase; fallback to echoing input is fatal. It uses
only voting_tally_login against the fixed local Voting target. The RSA key loader
is delayed until verified finalized input. The single-key launcher may require
restart/reconfiguration for a different election's Tally key.

Frontend activation: set `VITE_ENABLE_TALLY=true`, run the existing
`npm run dev:local`, and open `/admin/tally`. The new loopback-only proxy defaults
to 127.0.0.1:8005 and must use a port separate from RA/Voting/Admin. No backend
CORS or proxy trust restriction is relaxed.

## Dedicated PostgreSQL CI and actual validation

[tally-verification.yml](../.github/workflows/tally-verification.yml) is a separate
push-to-feature-branch/manual Ubuntu 24.04 job with contents:read, pinned actions,
Python 3.11.9, Node 24.22.3, existing locked installs and no uploaded artifacts.
It runs backend/crypto/frontend/all browser regressions first, then:

```bash
"$EVOTE_TEST_PYTHON" scripts/tally_postgres_ci.py --allow-ephemeral-ci-database
```

The coordinator accepts no selectable database/credential arguments. It owns a
digest-pinned PostgreSQL 18 tmpfs container with a uniquely named/marked disposable
Voting database, generated credentials, verified owner/name/role/version/container
identity and loopback binding. It provisions baseline/Admin/Tally roles, applies
the real five-revision chain through the guarded Alembic environment, and never
targets ra_db or voting_db. Runtime and owner fixtures remain separate.

Pending real cases: CLOSED enforcement; genuine AEAD/OAEP encryption/decryption;
two same-choice ballots plus another candidate; explicit wrap/AEAD/plaintext
invalids; duplicate acceptance denial; four concurrent Tally requests with one
successful report; audit-trigger rollback and reuse of the finalized snapshot;
idempotent report recovery; wrong-key fingerprint and unsigned-config rejection;
expired-lease fencing; session revocation/expiry; direct table/owner/internal-helper
42501 denials; exact ten-function surface; PUBLIC revocations; and owned-container/
private-directory cleanup. Finalized evidence is retained until container teardown.

Fixtures use genuine finalized PSS verifier inputs from ephemeral TEST RA keys;
they do not replace or claim to exercise RFC BlindSign. Native RA/CIRCL issuance
remains in the preserved interoperability/Admin-to-Voter gates. The Tally CI
election and reconciliation flags are explicit trusted owner fixtures, not a
new execution of Admin/RA configuration publication. The existing combined gate
continues to cover that publication path. The Tally CI
coordinator and real HTTP app share a trusted test process; this tests DB
permissions and actual crypto, not production OS key isolation. A combined real
Admin/browser/RA/CIRCL/Voting/Tally gate is not yet implemented.

Actual local results on this checkout:

| Executed validation | Result |
|---|---|
| Full backend/crypto pytest | **805 passed**, including 24 new Tally/safety cases |
| Frontend unit/component/crypto tests | **87 passed** |
| TypeScript/Vite production build | **PASS** |
| Authentication / Voting / Admin / Tally browser suites | **7 / 7 / 2 / 2 passed** |
| TypeScript credential recovery | **2 passed** |
| Locked installs / Python dependency verification | **PASS**, no lock/dependency changes |
| Python/JSON/YAML/Bash syntax and secret/whitespace checks | **PASS** |
| Migration graph inspection and preserved old heads | **PASS**, no SQL executed |
| Real PostgreSQL Tally gate / migration | **NOT RUN**, hosted CI required |

Local Python 3.11.9 uses psycopg's supported Python wrapper with the installed
client library because the bundled DLL is blocked by Windows Application Control;
no security settings changed and no database connection occurred. Browser tests
use Edge on Windows and synthetic transport fixtures; hosted CI uses Chromium.
The new browser test initially used an exact label-text selector that included
native select option text. Selecting by the actual combobox role/name fixed that
test without changing authorization or confirmation behavior. Existing tests and
assertions remain intact. Vite retains its existing blindrsa-ts crypto externalization
notice; cryptographic regression passes.

Remaining limitations include single-key/operator local configuration, no MFA,
process-local login rate limiting, 1000 ballots/five-minute jobs without heartbeat,
bounded election listings, operator-managed evidence backup/orphan handling,
no independent Auditor/HSM, no public publication and no proof of honest counting
against a compromised authorized worker/host. Small aggregate cohorts can reveal
choices by inference; outputs remain restricted rather than being published.
No local migration, user DB access, production key access, commit, push, merge,
worktree removal or stash removal occurred.

## Changed files

| Area | Files |
|---|---|
| Tally backend | [verification](../backend/tally/verification.py), [runtime](../backend/tally/runtime.py), [HTTP](../backend/tally/http.py), [launcher](../backend/tally/launcher.py) |
| Migration | [forward revision](../migrations/tally/versions/e6a90c72b541_restricted_tally.py), [opt-in config](../alembic_tally.ini) |
| Admin Tally UI | [client](../frontend/src/tally/client.ts), [workspace](../frontend/src/tally/workspace.tsx), [routes](../frontend/src/app.tsx), [activation](../frontend/src/config.ts), [proxy](../frontend/vite.config.ts) |
| Backend tests | [fixtures](../tests/tally_helpers.py), [Tally tests](../tests/test_tally.py), [CI safety](../tests/test_tally_ci.py) |
| Frontend tests/configuration | [component tests](../frontend/src/tally/tally.test.tsx), [browser scenarios](../frontend/tests/tally-browser/tally.spec.ts), [browser config](../frontend/playwright.tally.config.ts), [scripts](../frontend/package.json), [TypeScript](../frontend/tsconfig.json) |
| CI | [workflow](../.github/workflows/tally-verification.yml), [coordinator](../scripts/tally_postgres_ci.py) |
| Review | [this report](./26-tally-verification.md) |
