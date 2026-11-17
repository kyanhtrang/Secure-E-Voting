# Commit #7: local voter voting UI

## Scope and baseline

The opt-in browser workflow uses the reviewed v2 blind credential, signed
manifest, encrypted envelope and receipt formats. Authentication remains disabled
in `backend.main.app`. Admin, Tally, publication and public verification remain
foundation screens. No database migration, role or frozen crypto source changed.

Unified review baseline: `feat/voter-voting-ui`, HEAD
`d962bf1bf37b5128313da3b80ca9f02a5edb3fb7`. The user fast-forwarded the branch
before this review; Commit #6 is included and is an ancestor. All 30 restored UI
files matched backup stash `d4d79769d4f68eb128615b79f153a7566cee262f` after newline
normalization at review start. There were no unmerged Git entries. The original
stash remains intact. All validation below ran in this combined checkout;
counts from the prior separate checkouts are not included.

## API inventory

| Endpoint | Use and authorization |
| --- | --- |
| `POST /api/v1/ra/auth/login` | Existing login contract; bearer token stays in a private in-memory closure. |
| `GET /api/v1/ra/auth/me` | Existing active RA session check. |
| `POST /api/v1/ra/auth/logout` | Existing session revocation. |
| `GET /api/v1/ra/elections` | New, explicitly enabled, authenticated read-only catalogue. |
| `POST /api/v1/ra/credentials/issue` | Existing Gate 2 issuance and exact-request recovery. |
| `POST /api/v1/vote/ballots` | Reviewed Commit #6 anonymous acceptance. |
| `POST /api/v1/vote/ballots/receipt` | Reviewed Commit #6 anonymous recovery using the complete original proof and envelope. |

The catalogue is the only new backend dependency. The operator explicitly lists
existing election UUIDs with repeated `--publish-election` flags. It reads each
real policy through the existing restricted session/policy function, verifies the
authority signature and database policy metadata, and returns:

```text
{elections: [{election_id, bundle: {manifest, signature},
              eligibility: "checked_on_issue",
              credential_availability: "checked_on_issue"}]}
```

It neither seeds elections nor reserves credentials. An empty configured list
returns an authenticated empty catalogue. Failures are sanitized and no-store.
It is installed only in the explicitly created credential app, not the default
application. No new table permissions are required. RA continues to use
`ra_auth_login` and `ra_issuance_login`; Voting uses `voting_ballot_login`.

Preflight eligibility, issued/reserved availability and live Voting status read
APIs do not exist. The UI labels these as checked on issue/submission. Signed
opening/closing dates describe the signed window, not the live database status;
the local clock only gates preparation/submission in the UI. RA and Voting still
enforce their authoritative database clock and state. Early closure may return
409. Election names are absent from the frozen manifest, so election UUIDs are
shown rather than invented names. Candidate names come only from verified data.

## Routes and operation order

`/voter/elections` lists verified policies, `/voter/elections/:electionId`
shows candidates and preparation, and `/voter/credentials` handles issuance and
recovery. `/vote` is outside the authenticated RA session provider. The voting
controller survives this navigation without exposing the RA bearer token.

1. Verify the Ed25519 manifest with an independently configured public key;
   validate exact fields, canonical UUID/base64url, RSA key sizes/fingerprints,
   dates and candidates. The API cannot supply or replace this trust anchor.
2. Generate a random 32-byte serial, AES-256 key and 12-byte nonce. Encrypt the
   canonical candidate plaintext with AES-GCM; use the frozen election/serial
   AAD. Wrap the AES key with the verified tally RSA-OAEP-SHA256 public key.
3. Canonicalize and hash the envelope. Build the exact domain-separated v2
   credential message, binding election, serial, envelope, config and RA key.
4. Use pinned `@cloudflare/blindrsa-ts` 0.4.6
   `RSABSSA.SHA384.PSS.Randomized()` to Prepare (32-byte prefix) and Blind.
   Commit encrypted recovery state to IndexedDB before allowing RA issuance.
5. Send only `{election_id, request_id, blinded_msg}` to RA. The original blinded
   bytes are used; the browser does not send a serial, envelope, finalized
   credential or candidate. The existing RA/CIRCL boundary is unchanged.
6. Finalize/unblind with the library and independently verify the prepared
   message signature using RSA-PSS/SHA384, MGF1-SHA384 and exactly 48-byte salt.
   Persist the finalized proof before allowing submission.
7. After confirmation, commit `submission_unknown` before sending the anonymous
   ballot. Verify the returned receipt against the local frozen receipt digest
   and persist `accepted` only after a match.

Anonymous requests reconstruct only `{election_id, credential, envelope}`;
the credential contains only `{message, prepared_msg, signature}`. They use a
separate fetch client, `credentials: omit`, no Authorization header, no referrer,
no-store caching and rejected redirects. The exact local Voting proxy paths
also reject accidental identity headers/cookies. RA and Voting proxy targets
must have different loopback ports, including when localhost aliases differ.
Host/Origin checks are preserved; CORS and proxy trust are not relaxed.

## Protected recovery and failures

This is a browser-local encrypted storage format, not a replacement for the
frozen wire protocol or the existing Node/scrypt recovery file. The browser uses
PBKDF2-SHA256 (600,000 iterations, random 16-byte salt) and AES-256-GCM (random
12-byte nonce, 128-bit tag). The passphrase must be 16-1,024 characters. AEAD AAD
binds `EVOTE-BROWSER-RECOVERY-v1`, election ID, request ID and config hash.
Only encrypted state and public routing/KDF context enter IndexedDB or exports.
Nonextractable derived keys and the passphrase are not persisted. Raw AES ballot
key bytes are cleared after encryption/wrapping; JavaScript cannot guarantee
complete memory erasure.

The encrypted plaintext includes the signed manifest, envelope, serial-bearing
message, prepared prefix, inverse, original blinded request and eventual proof.
It contains no RA bearer token or login password. Candidate plaintext and the
unwrapped ballot encryption key are not saved. Imports revalidate the manifest,
message/envelope bindings, prefix, proof and any accepted receipt before use.

IndexedDB `add` prevents replacing an existing election record; updates check
request/config equality in the same read/write transaction. HTTP work waits for
transaction completion. Blocked storage fails before issuance. The controller
also blocks concurrent button actions. Existing state must be restored rather
than silently replaced after a reload, signing error or network interruption.

Exact issuance retries preserve the request ID, blinded bytes and inverse.
The server's existing recovery deadline and retained authorization apply; losing
the passphrase/file does not release eligibility. Session expiry requires the
original account to authenticate again. After proof finalization, receipt
recovery needs no RA session and remains available after the election closes.
A failed receipt lookup does not prove an earlier request cannot still commit.
409, 422, 503, timeouts and malformed replies retain the original protected state;
the UI never automatically generates a new serial after an uncertain result.

Save the encrypted recovery file before relying on the browser profile. Keep
the passphrase separately. “Lock private state” drops the controller's plaintext
state and passphrase while retaining the encrypted record. Leaving the RA route
forgets the in-memory token; actual server revocation requires successful logout.
The minimal receipt export contains only election ID and receipt hash. Acceptance
does not prove counting, correct decryption or public bulletin-board inclusion.
The receipt digest is locally computable and unsigned; it is not an independent
server attestation. Acceptance feedback relies on the trusted local Voting service.

## Local startup (operator actions; not executed during implementation)

Use Node 24.22.3 and the existing locked Python environment. Use real, already
installed signed policies with the same independently verified authority key in
RA, Voting and the browser. An operator must have provisioned the reviewed
database migrations/configuration separately. This change does not perform that
setup or consume an election credential.

From the UI checkout, explicitly start RA with existing protected configuration:

```text
python -m backend.ra.credential_launcher --enable-local-demo --load-local-verifier --enable-credential-issuance --signer-binary <reviewed-executable> --encrypted-signing-key <operator-encrypted-key-file> --manifest-authority-pin <trusted-raw-32-byte-public-key-file> --key-id <configured-ra-key-id> --recovery-key-id <configured-recovery-key-id> --publish-election <existing-election-uuid>
```

The launcher loads the existing opt-in local verifier and prompts privately for
runtime DB passwords, the persistent server recovery key and encrypted signer
key passphrase. Never put these in Vite variables, shell arguments or source.
Use an approved environment that can execute the reviewed CIRCL signer; do not
change Windows Application Control to run it.

From this same combined checkout, start the separate Voting service:

```text
python -m backend.voting.local_launcher --enable-local-voting --manifest-authority-pin <same-trusted-public-key-file>
```

Both launchers bind loopback (RA 8000, Voting 8001). From `frontend/` in the UI
checkout, PowerShell:

```powershell
$env:VITE_ENABLE_VOTING='true'
$env:VITE_MANIFEST_AUTHORITY_PIN='<canonical-base64url-of-the-trusted-raw-32-byte-PUBLIC-key>'
$env:RA_DEMO_TARGET='http://127.0.0.1:8000'
$env:VOTING_DEMO_TARGET='http://127.0.0.1:8001'
npm.cmd ci --ignore-scripts
npm.cmd run dev:local
```

Open `http://127.0.0.1:5173`. The default dev/build keeps local authentication and
voting disabled. Voting additionally requires the explicit flag and valid
independent public pin. No credentials/private keys belong in any `VITE_` value.
Use a current WebCrypto-capable browser with Ed25519, RSA-PSS/OAEP, IndexedDB and
secure-context support (loopback HTTP qualifies in tested Edge). Other browser
engines require validation. The existing SJCL Node-crypto fallback triggers a
Vite externalization warning; actual Edge tests exercise the supported browser
WebCrypto path without adding a fallback or changing the crypto library.

## Validation and review limits

Executed locally on the combined source tree (Python 3.11.9, Node 24.22.3):

- Complete database-free backend/crypto pytest: **621 passed in 35.02s**;
  existing tests and assertions unchanged.
- Frontend TypeScript checks and production Vite build: **PASS**.
- Frontend unit/component/API/crypto tests: **78 passed**. Real generated
  RSA-3072 blind/unblind proof is verified independently by the unchanged Python
  verifier; AES-GCM/OAEP decryption, frozen serialization vectors, wrong salt,
  altered bindings, manifest rejection and encrypted recovery are covered.
- Original browser suite: **7 passed**; new voting browser suite: **3 passed**
  in desktop/mobile Edge. These exercise real browser crypto, separate synthetic
  RA/Voting HTTP services, encrypted storage, anonymous cookie/header omission,
  same-request signing recovery, session expiry and lost committed response.
- Existing Node TypeScript pending-state recovery tests: **2 passed**.
- Python dependency consistency, exact frontend dependency tree, Python/JSON/YAML
  and workflow Bash syntax, fixture JavaScript syntax, and `git diff --check`:
  **PASS**. Syntax checks covered 122 Python files, 7 JSON files, 3 YAML files
  and 24 workflow Bash blocks. `npm ci --ignore-scripts` succeeded for frontend
  and crypto interoperability packages (both reported zero vulnerabilities).
  Installed Python versions matched the application, RA, Voting and crypto
  locks; `pip check` and the Voting dependency-only verifier passed. Existing
  frontend lock entries are unchanged; only the pinned blind RSA/canonicalization
  libraries and their SJCL dependency were added. Crypto lock entries are unchanged.
- Targeted changed-source secret scan and app-bundle exclusion of synthetic
  fixture data: **PASS**. Frozen crypto, migrations and existing tests are
  unchanged. Desktop/mobile synthetic previews were inspected.

An additional database-free compatibility check generated a proof with the actual
TypeScript browser adapter (Prepare/Blind/Finalize), then submitted its exact
payload through the merged Python Voting app, router and service with the existing
in-memory test store. The real RA request model accepted its exact issuance
payload. The check passed acceptance (201), absent receipt (404), duplicate (409),
tampered envelope (422), forbidden identity headers/cookie (400), enforced local
client access (403), matching Python/TypeScript receipt and recovery after closure.
No private keys left the generating process or entered a file/log.

The browser fixture is explicitly synthetic, with ephemeral generated test keys
and in-memory service/database doubles. It uses the pinned library's BlindSign
for the test double; the native CIRCL signer and real PostgreSQL were not run in
this task. Previous CI gates remain upstream evidence, not newly executed tests.
The web workflow includes the frontend tests, build, original browser suite and
new voting browser suite, with locked installs, read-only permissions and no
continue-on-error. It triggers on relevant pushes to this UI branch and on pull
requests. Its Ubuntu run is pending. Existing backend/crypto and PostgreSQL
workflows were preserved byte-for-byte; their existing branch filters do not
automatically run them on this UI branch. This review did not execute them remotely.

The public trust anchor must be distributed independently. Shared JavaScript
execution, XSS, browser extensions, compromised API hosts, proxy infrastructure,
IP/timing correlation, and public recovery context can compromise privacy.
Passphrase encryption is vulnerable to offline guessing if users choose weak
phrases. Browser storage eviction and lost files remain availability risks.
There is no claim of full anonymity, coercion resistance or full end-to-end
verifiability. Tally must later decrypt and validate candidate choices.

Before release: review this browser adapter/storage design, run the updated
Ubuntu workflow, validate against explicitly approved
disposable RA/Voting services with real CIRCL and policies, and test additional
browser engines. No local PostgreSQL access, migration, production key access,
commit, push or merge was performed.

## Unified contract and privacy review

| Boundary | Verified compatibility |
| --- | --- |
| Login / Me / Logout | Existing username/password request, Bearer token response, active `voter_id` response and 204 logout match the scoped client. Error bodies are never surfaced; failed revocation is not reported as confirmed. |
| Catalogue | Authenticated, opt-in route returns the exact signed bundle and `checked_on_issue` fields the client validates. Empty/unavailable states do not fabricate data or eligibility. |
| Issuance / exact recovery | Exactly election ID, request ID and 384-byte blinded message; 201 issued / 200 replayed with exact profile/key/signature fields. 401/403/409/410/422/503 retain protected state and use sanitized feedback. |
| Frozen credential / encryption | Strict v2 fields, JCS UTF-8, canonical encodings, independent Ed25519 authority pin, distinct RSA-3072 keys, AES-256-GCM, OAEP-SHA256, 32-byte Prepare prefix and 48-byte PSS salt match reviewed verification. Original blinded bytes reach BlindSign, never their hash. |
| Anonymous acceptance | Exact election/credential/envelope fields; 201 accepted, 409 duplicate/closed, 422 invalid, 503 unavailable match the client. No RA request ID, voter ID, login name, bearer, identity cookie or authenticated interceptor enters the request. |
| Receipt recovery | Same original anonymous payload, 200 matching receipt / 404 unavailable receipt. Receipt construction matches the actual merged service. No new serial is generated for an uncertain commit; recovery is allowed after closure. |
| Protected imports | Context-bound AEAD, fixed KDF cost, canonical file encoding, signed configuration and proof checks precede use. Atomic IndexedDB transactions precede issuance/submission and block replacing a different pending request. |

No compatibility defect or failing product regression was found. The only file
changed during this unified review is this report: stale baseline/startup
instructions and separate-checkout counts were replaced with current evidence.
The complete Commit #7 diff still contains the same 30 files listed below.

Reproduction commands (run in this combined checkout; use the locked Python
environment and Node 24 on PATH):

```text
python -m pytest tests crypto_interop -q
python -m pip check
python scripts/voting_postgres_ci.py --verify-dependencies
npm.cmd --prefix frontend ci --ignore-scripts
npm.cmd --prefix frontend test
npm.cmd --prefix frontend run check
npm.cmd --prefix frontend run build
npm.cmd --prefix frontend run test:browser
npm.cmd --prefix frontend run test:voting-browser
npm.cmd --prefix crypto_interop ci --ignore-scripts
npm.cmd --prefix crypto_interop run check
npm.cmd --prefix crypto_interop run build
node --test crypto_interop/dist/pending_state.test.js
node --check frontend/tests/voting_fixture.mjs
git diff --check
```

`EVOTE_TEST_PYTHON` must name that environment's Python for the independent
frontend verifier and authentication fixture. `EVOTE_TEST_NODE` must name Node 24
for Python subprocess crypto tests. Generated test material stays ephemeral;
the dependency-only verifier returns before any Docker/PostgreSQL operation.

## Review file inventory (30 files)

| Area | Files |
| --- | --- |
| Opt-in backend dependency | `backend/ra/election_catalogue.py` (new), `backend/ra/credential_runtime.py`, `backend/ra/credential_launcher.py`, `tests/test_ra_election_catalogue.py` (new) |
| Frontend integration | `frontend/src/api/auth.ts`, `frontend/src/auth/session.tsx`, `frontend/src/app.tsx`, `frontend/src/config.ts`, `frontend/src/pages/voter.tsx`, `frontend/src/pages/voting.tsx` (new), `frontend/src/styles.css` |
| Browser voting components (all new) | `frontend/src/voting/crypto.ts`, `recovery.ts`, `workflow.ts`, `api.ts`, `context.tsx` |
| Unit tests/support (all new) | `frontend/src/voting/crypto.test.ts`, `workflow.test.ts`, `api.test.ts`, `material.test-support.ts`, `frontend/src/pages/voting.test.tsx` |
| Browser tests (all new) | `frontend/tests/voting_fixture.mjs`, `frontend/tests/voting-browser/voting.spec.ts`, `frontend/playwright.voting.config.ts` |
| Dependencies/configuration/CI | `frontend/package.json`, `frontend/package-lock.json`, `frontend/tsconfig.json`, `frontend/vite.config.ts`, `.github/workflows/web-ui.yml` |
| Documentation | This file (new). |
