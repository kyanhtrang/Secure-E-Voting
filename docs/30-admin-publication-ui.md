# Admin publication UI: human review

Branch `feat/admin-publish-ui`, base `8f67e56`. The existing `/admin/publication`
screen now invokes the reviewed Publisher service through an explicitly enabled
local proxy. Signing, enrollment and database authorization remain server-side.
**The new hosted UI-to-Publisher gate has not run.** Local synthetic browser tests
are not evidence of real PostgreSQL-backed UI publication.

## Architecture and exact API inventory

```text
Admin login -> existing Admin API -> memory-only AdminClient bearer closure
                                  -> exact local Publisher proxy -> Publisher
                                                                  -> restricted Voting RPCs
                                                                  -> publication key
Authoritative state refresh -> existing Admin detail/list/audit APIs
Public results link -> separate anonymous Board client -> independent public pins
```

No new application API, signing protocol, migration, role or grant. The existing
Publisher still requires both an active ELECTION_ADMIN session and explicit active
`voting_board.publishers` enrollment; a frontend flag cannot enroll an Admin.
Voter and Tally bearer formats cannot enter the publication client through Admin
login, and the proxy rejects those formats. Existing backend tests and the real
full-election gate retain server-side cross-role denial assertions.

| Call | Behavior |
|---|---|
| Existing `/api/v1/admin/auth/login`, `/me`, `/logout` | Unchanged login/session contract; bearer stays in one closure. |
| Existing Admin elections, keysets, detail and audit | Real managed-election selection and authoritative lifecycle/readiness refresh. |
| `POST /api/v1/publication/elections/{canonical UUID}/publish` | Body exactly `{}`; existing Admin bearer. No key, package, selection, voter identity or arbitrary URL supplied by UI. |
| `/public/results/{id}` | Existing independently verified public UI; no Admin session needed. |
| Existing Board GETs | Separate client, credentials omitted, no Admin token; pins configured independently of Board. |

The new client action uses POST only, `credentials: omit`, `cache: no-store`,
`redirect: error`, `referrerPolicy: no-referrer`, 30-second abort and an 8-KiB
streaming response cap. It checks no-store/JSON, canonical UTF-8/JCS, exact
acknowledgement fields, matching election, canonical signature encoding, digest
formats and count equations. This validates an acknowledgement **without claiming
its signature chain is independently verified**. Public verification remains the
existing full-bundle verifier. Raw error bodies are never read or rendered.

Publication requires local-demo mode, HTTP loopback, `VITE_ENABLE_ADMIN=true`,
`VITE_ENABLE_PUBLICATION=true`, and the compiled server activation flag. The Vite
server requires an explicit `PUBLICATION_DEMO_TARGET`; it is not a browser
environment variable or a form field. Startup rejects non-loopback HTTP origins,
URL credentials, paths/query/fragment and any RA/Voting/Admin/Tally/Board port
collision, including localhost/127.0.0.1 aliases. All other proxy targets are
unchanged. The new middleware blocks the publication namespace when disabled.

The proxy matches only the exact canonical publication endpoint and POST. It
rejects queries, other methods/routes, remote peers, duplicate Host/Origin/auth,
mismatched Origin, non-Admin bearer shape, cookies/identity headers, transfer
encoding, non-JSON and any body length other than the client's two-byte `{}`.
The real backend still parses the body and validates authorization; header shape
is not authentication. The proxy preserves Host and Origin, with changeOrigin,
xfwd and redirect following disabled; it does not strip credentials or manufacture
an Origin. Proxy/upstream timeouts are bounded. CORS remains false and Vite binds
127.0.0.1. No publication proxy points to an anonymous service.

## User flow, uncertainty and races

Sign in through the existing Admin form, open Publication, and select a managed
election. Entering/re-entering this route requires a fresh selection, preventing
an earlier route's stale detail from authorizing a new confirmation. The page
shows actual lifecycle, RA readiness, configuration hash and audit events.

Publish is enabled only for matching TALLIED status/phase, reconciliation ready,
a signed configuration hash and explicit activation. The user must separately
click **Confirm publish**. Cancel, election changes, route changes and logout
discard confirmation. A synchronous workspace lock and client in-flight guard
prevent duplicate clicks before React rendering catches up. Generation checks
discard stale refreshes and responses after logout/unmount; an old-route
publication cannot replace the current election. Existing draft/candidate/window/
finalize/open/close screens and their confirmation assertions remain intact.

TALLIED indicates a committed Tally by lifecycle, not independently checked
evidence. The screen explicitly states that Publisher must verify signed report,
snapshot and configuration before publication. PUBLISHED is shown only from a
fresh authoritative Admin response, followed by the existing public-results link.
The optional acknowledgement digest is labeled as such, not a cryptographic
verification badge. The UI displays no individual decrypted vote.

| Failure | UI handling |
|---|---|
| 401 | Forget Admin authorization, clear election/confirmation and return to sign-in. |
| 403 | Fixed explanation that this Admin is not enrolled as Publisher. |
| 409 | Election not ready/conflicting evidence; refresh actual state. |
| 422 | Fixed rejected-request feedback; no echoed input. |
| 503 / timeout / network loss / invalid acknowledgement | Outcome may be unknown; refresh authoritative state, never automatically retry POST. |

After any publication attempt, state is read again. If PUBLISHED is observed,
show committed confirmation even when the HTTP acknowledgement was lost. If a
refresh fails or a publication remains unconfirmed, Publish stays blocked until
an explicit state refresh. A TALLIED read does not prove the earlier request
cannot still commit. Any subsequent retry requires fresh confirmation and repeats
the same election plus `{}`; the server's reviewed locking/idempotency handles it.
The browser never invents a replacement publication package.

## Human-approved local startup

No database deployment is performed by this task. Use already reviewed/deployed
Admin, Tally and Board configuration with an authorized enrolled Publisher.
Original Tally evidence must be available read-only to Publisher; do not regenerate
or replace it. No new database provisioning is needed for this UI.

Start the existing Admin launcher using its existing external verifier, approved
key catalogue, encrypted authority key and public pin:

```bash
python -m backend.admin.launcher --enable-local-admin \
  --verifier /outside-repo/admin-verifier.json \
  --key-catalogue /outside-repo/approved-keysets.json \
  --authority-key /outside-repo/manifest-authority.encrypted.pem \
  --authority-pin /outside-repo/manifest-authority.pub
python -m backend.board.launcher --enable-local-demo --role publisher \
  --trust-config /outside-repo/public-trust.json \
  --evidence-directory /outside-repo/tally-evidence \
  --encrypted-publication-key /outside-repo/publication.encrypted.pem
python -m backend.board.launcher --enable-local-demo --role board \
  --trust-config /outside-repo/public-trust.json
```

These are template paths, not files read during implementation. Launchers prompt
privately for their own DB/key credentials. No password/passphrase belongs in npm
configuration, shell arguments or frontend environment. In the frontend terminal
(PowerShell example, **public pins only**, obtained independently):

```powershell
$env:VITE_ENABLE_ADMIN='true'
$env:ADMIN_DEMO_TARGET='http://127.0.0.1:8002'
$env:VITE_ENABLE_PUBLICATION='true'
$env:PUBLICATION_DEMO_TARGET='http://127.0.0.1:8007'
$env:VITE_ENABLE_BOARD='true'
$env:BOARD_DEMO_TARGET='http://127.0.0.1:8006'
$env:VITE_MANIFEST_AUTHORITY_PIN='<trusted base64url public pin>'
$env:VITE_EVIDENCE_PIN='<trusted base64url public pin>'
$env:VITE_EVIDENCE_KEY_ID='<existing evidence key id>'
$env:VITE_PUBLICATION_PIN='<trusted base64url public pin>'
$env:VITE_PUBLICATION_KEY_ID='<existing publication key id>'
npm --prefix frontend ci --ignore-scripts
npm --prefix frontend run dev:local
```

Open `http://127.0.0.1:5173/admin/publication`. If Board or pins are not configured,
the public page remains honestly unavailable/unverified. No keys are fetched from
the API to establish their own trust. A normal production build remains disabled.

## CI, actual validation and remaining evidence

The new [workflow](../.github/workflows/admin-publication-ui.yml) triggers only on
push to this feature branch plus input-free manual dispatch, with contents:read,
SHA-pinned Actions and Ubuntu 24.04. Existing workflows remain unchanged. It uses
Node 24.22.3, Go 1.25.14, Python 3.11.9 and existing dependency locks. No repository
secrets, continue-on-error, private artifacts, screenshots, video or traces.

It runs all regressions, native CIRCL/vector tests, standalone Tally and Board
gates, and the original complete real-election gate **before** a second isolated
complete election. The only change to the old coordinator is a default no-op hook
after publication rollback/before initial publication. In the new subclass only,
real Chromium uses the Admin UI for the first TALLIED -> PUBLISHED request. The
original gate still tests four competing initial publications; the second gate
tests four identical retries after UI publication, with all original signature,
count, receipt, immutability, audit, ACL and cleanup assertions retained.

Both elections use fresh owned PostgreSQL 18 containers, names/markers/ownership/
roles checked on every connection, real reviewed migrations and native CIRCL.
Both ballots come from the existing actual Chromium voter journeys, not seeded
accepted rows. The same generated RSA keys remain matched through decryption.
The UI gets only a synthetic Admin login and public IDs/receipts through a private
pipe; Vite receives only public origins/pins. Only the actual Publisher child
receives its publication private key. After publication, the browser logs out,
loads the real Board, verifies the full chain and A=1/B=1 aggregate, verifies both
receipts, checks unknown-receipt NOT_FOUND, and asserts no identity on Board.

Expected new checkpoint (not yet execution evidence):

```text
PASS: admin_publication_ui checkpoint=published_and_public_verified
PASS: admin_publication_ui checkpoint=cleanup
```

Failures show only fixed phase/category/SQLSTATE or allowlisted browser stage;
no arbitrary exceptions, bodies, SQL, tokens or key material. The coordinator
inherits owned-resource teardown; abrupt runner loss relies on hosted disposal.

Actual final local validation on this combined checkout:

| Check | Actual result |
|---|---|
| Complete backend/cryptography pytest | 1,019 passed (17 new hosted UI safety tests; all prior tests preserved). |
| Frontend unit/component/crypto | 167 passed in 12 files (59 new publication/proxy tests). |
| Existing authentication / voting / Admin / Tally / Board browsers | 7 / 7 / 4 / 2 / 3 passed, 23 total, including two new synthetic publication tests. |
| TypeScript checks + production frontend build | PASS. |
| Crypto TypeScript build + recovery tests | PASS, 2 recovery tests passed. |
| Dependency integrity | pip check, all reviewed Python version checks, both npm dependency trees PASS; locked npm installs reported zero vulnerabilities. No locks changed. |
| Syntax | 165 Python, 7 JSON, 11 YAML and 78 Bash bodies/scripts parsed; hosted driver JavaScript syntax PASS. |
| Migration graphs | Unchanged RA head bf932d0f8702 (15), Voting/Board head f8b31c2d970a (6); no migration executed. |
| Source/bundle secret scan and diff whitespace | PASS; no detected embedded credentials, test-secret/key material or runtime DB identity in the production bundle. |
| Native Go, PostgreSQL and real UI-to-Publisher gate locally | NOT RUN; Go unavailable on local PATH, hosted-only PostgreSQL safety guards retained. |

Two frontend attempts under concurrent CPU/browser load timed out in unchanged
five-second RSA workflow tests. Assertions and timeouts were not modified. Vitest
now bounds worker concurrency at two; the final isolated `npm test` passed all
167 tests. CI runs frontend unit tests before browser execution. This is a test
resource bound, not relaxed cryptography or a skipped regression. The existing
Vite blindrsa `crypto` externalization notice remains; builds and browser tests
above pass. Local browsers used existing Edge configuration; Ubuntu installs
Chromium. Python used the supported PSYCOPG_IMPL=python/libpq18 import path under
Windows Application Control, without changing security settings or connecting to
PostgreSQL. Only generated test cryptographic material was used.

Native Go, live PostgreSQL and
the new real UI-to-Publisher journey remain **NOT RUN locally** and require the
first human-approved Ubuntu push. Existing real CI evidence does not establish
this new UI path passed. The local browser publication tests explicitly use
synthetic HTTP services; original Board tests retain real signature verification
over generated synthetic evidence.

## Complete changed-file inventory

Modified:

- [Admin client](../frontend/src/admin/client.ts): memory-only publication action and bounded acknowledgement validation.
- [Admin workspace](../frontend/src/admin/workspace.tsx): publication selection, synchronous action lock and stale-result guards.
- [App route wiring](../frontend/src/app.tsx).
- [Explicit feature configuration](../frontend/src/config.ts).
- [Narrow local proxy](../frontend/vite.config.ts).
- [Vitest definitions and two-worker bound](../frontend/vitest.config.ts).
- [Admin browser local activation](../frontend/playwright.admin.config.ts).
- [Default no-op hosted composition hook](../scripts/full_election_e2e.py).

New:

- [Publication screen](../frontend/src/admin/publication.tsx).
- [Client/component regressions](../frontend/src/admin/publication.test.tsx).
- [Proxy regressions](../frontend/src/admin/publication-proxy.test.ts).
- [Synthetic mobile/desktop browser regressions](../frontend/tests/admin-browser/publication.spec.ts).
- [Real hosted browser driver](../frontend/tests/real-admin-publication.mjs).
- [Hosted coordinator](../scripts/admin_publication_ui_ci.py).
- [Hosted safety/contract regressions](../tests/test_admin_publication_ui_ci.py).
- [Dedicated workflow](../.github/workflows/admin-publication-ui.yml).
- [This report](./30-admin-publication-ui.md).

Total: 17 files. Production backend, default app authentication, launchers,
applied migrations, frozen cryptography, runtime grants, original test assertions
and all dependency locks are unchanged. No commit/push/merge or stash deletion.

## Security limitations

This is an explicitly enabled local demo. Trusted server configuration selects a
loopback Publisher; there is no TLS service attestation or OS-user isolation.
Same-origin XSS or a compromised local process can compromise a memory bearer;
the UI is not a replacement for database authorization. Network cancellation
cannot undo a committed publication. Public serials/envelopes/proofs retain the
already documented correlation and later-key-compromise risks. Independently
VERIFIED public evidence proves integrity/inclusion under configured authorities,
not individual decryption correctness, full anonymity, coercion resistance or
complete end-to-end tally correctness. No new public plaintext or key exposure
is introduced. Deployment and the first real UI gate remain human-review steps.
