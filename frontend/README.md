# Secure E-Voting web foundation

React + Vite + TypeScript, with separate Voter, Admin and Public workspaces.
Only the existing local RA Login / Me / Logout APIs are connected. No election,
ballot, publication or verification data is fabricated.

## Run locally

Use Node 24.22.3 (minimum 24.15) and npm. Versions are exact in
[package.json](package.json) and [package-lock.json](package-lock.json).
This is a separate package: the reviewed crypto package and its locks are unchanged.

From the checkout containing this frontend:

```powershell
cd frontend
npm ci --ignore-scripts
npm run dev
```

Open http://127.0.0.1:5173. Default development and production builds keep RA
sign-in disabled. Admin/public foundation screens remain available. Start the
explicit local-demo mode to enable auth:

```powershell
# Terminal 1, from the repository root, with existing approved RA auth setup.
python -m backend.ra.demo_launcher --enable-local-demo --load-local-verifier
# Enter the existing local DB password at the launcher's protected prompt.
# No password, token or signing key belongs in a command or frontend config.

# Terminal 2
cd frontend
npm run dev:local
```

The human-operated launcher uses the existing local verifier and restricted
ra_auth_login role, binds only 127.0.0.1:8000, and retains its own security checks.
The frontend does not read that verifier or database credentials. Provisioning
must already have been reviewed/completed; this change runs no migration.
The separate existing credential launcher also exposes the same auth contract,
but loading a signing key is unnecessary just to use this UI.
backend.main.app remains deliberately disabled for login.

### Configuration and origin boundary

| Setting | Behavior |
| --- | --- |
| Default mode, npm run dev / build | Auth disabled; no auth proxy |
| Explicit mode, npm run dev:local | Auth enabled only when the browser uses HTTP localhost/127.0.0.1 |
| RA_DEMO_TARGET | Server-side public origin; defaults to http://127.0.0.1:8000 |

Optional target override, with no secret:

```powershell
$env:RA_DEMO_TARGET = 'http://127.0.0.1:8000'
npm run dev:local
```

The target must be a loopback HTTP origin with no credentials, path, query or
fragment. No browser environment variable accepts database passwords, bearer
tokens or private keys. All Vite frontend configuration is public.

The only proxied paths are the three exact RA auth paths. changeOrigin=false
preserves Host and Origin together; xfwd and followRedirects are disabled.
This matches the existing LocalDemoMiddleware's exact origin/host check without
changing backend CORS or stripping the Origin header. The browser calls its own
origin; it never calls an arbitrary remote API. Frontend dev/preview servers bind
127.0.0.1 with strict ports, restricted host names and CORS disabled. Local server
responses deny framing and add nosniff, no-referrer and no-store headers.
An untrusted Origin is still rejected by the real backend (browser smoke tested).
Do not expose these development servers publicly.

## Architecture and routes

[main.tsx](src/main.tsx) mounts BrowserRouter and the generic error boundary.
[app.tsx](src/app.tsx) separates workspace trees. The RA SessionProvider exists
only within the Voter tree. Admin/public/anonymous screens cannot consume that
context and have no API adapters. [shell.tsx](src/components/shell.tsx) supplies
responsive navigation, workspace selection, skip navigation and route-heading
focus. [ui.tsx](src/components/ui.tsx), [tokens.css](src/tokens.css) and
[styles.css](src/styles.css) define reusable accessible feedback, panels, buttons,
publication gating and a consistent navy/green/ivory design system.

| Routes | Current functionality |
| --- | --- |
| /, /voter/login | Local sign-in; / redirects to the guarded Voter overview |
| /voter | Session-verified dashboard, refresh and logout |
| /voter/elections | Protected, honest catalogue-unavailable state |
| /voter/elections/:electionId | Protected detail-unavailable state; no invented record |
| /voter/credentials | Protected browser-integration placeholder; issuance disabled |
| /admin | Read-only management overview and planned lifecycle |
| /admin/elections, /candidates, /status, /tally, /publication, /audit | Foundation screens; all operation buttons disabled |
| /public | Public published-election feed unavailable; no account required |
| /public/results/:electionId | Publication-gated result layout with empty chart/evidence areas and unavailable totals |
| /public/board, /public/verify | Board and receipt-verification foundation; submission disabled |
| /vote | Separate anonymous-workspace placeholder; no RA context or API call |
| Any other path | Safe not-found screen, with no URL/input reflected |

The shorthand admin subpaths in the table all start with /admin. The current
PublicResults component always has unavailable publication status: no feed exists.
PublicationGate allows data rendering only for the exact PUBLISHED value, but
no route/query parameter can supply it. A future reviewed publication adapter
must validate the backend contract and its evidence before connecting a renderer.

## Real API contracts and missing services

Inspected source: [login_router.py](../backend/ra/login_router.py),
[session_router.py](../backend/ra/session_router.py),
[demo_launcher.py](../backend/ra/demo_launcher.py), and
[credential_router.py](../backend/ra/credential_router.py).

| Contract | Integration |
| --- | --- |
| POST /api/v1/ra/auth/login | Sends only username/password; expects 200 with access_token and token_type=Bearer |
| GET /api/v1/ra/auth/me | Sends RA bearer; expects 200 with voter_id only; required before showing authenticated UI |
| POST /api/v1/ra/auth/logout | Sends RA bearer; only 204 is confirmed revocation |
| POST /api/v1/ra/credentials/issue | Exists in the explicitly enabled credential app; intentionally not called by this foundation |
| Election list/detail/eligibility | No route/response contract exists; no speculative request is made |
| Admin identity and privileged APIs | No route/response contract exists; voter auth never grants admin authority |
| Published lists/status/results/board/receipt/evidence | No route/response contract exists; no speculative request or result is shown |

No expires_in, expires_at, voter name, admin role, election record, candidate count
or result field is invented from the existing response shapes. /health belongs
to the default app, not the auth launcher; the UI does not use it as a false
connection indicator. An actual empty catalogue cannot yet be distinguished
from no elections, so the UI explicitly says the catalogue is unavailable.

## Session and error security

[auth.ts](src/api/auth.ts) owns the bearer in a private closure, not React state
or a token getter. Only the three literal auth endpoints can receive it; login
does not receive Authorization. Requests omit cookies, reject redirects, use
no-store and no-referrer, and have a ten-second abort deadline through body reading.
Canonical token/UUID and exact current response fields are validated.

The session provider exposes verified identity/status, not the bearer. Reloading
or leaving the Voter tree aborts requests and forgets access locally. This does
not revoke the server session: it remains subject to its database TTL. Use the
logout button to request explicit revocation. Late login responses cannot
restore a forgotten token. No localStorage, sessionStorage, URL parameter,
service worker, analytics, console or persistent session cache stores tokens.

Foreground polling every 60 seconds and focus/visibility revalidation use /me.
A 401 clears access and returns to sign-in. A failed session check hides guarded
content and offers retry/logout. The API supplies no expiry time, so there is no
made-up countdown. The displayed last-check time is browser-local observation.
Password inputs are cleared immediately on submission. Error bodies/exceptions
are never displayed; user feedback comes from static messages for 401/422/429/
503 and network failures. Failed logout clears local memory but explicitly
reports that server revocation could not be confirmed.

Memory-only storage is not immunity to same-origin XSS, browser extensions,
DevTools or a compromised dependency. The HTML includes a CSP restricting
scripts/connections to the local origin (plus local HMR websocket connections),
no objects and self-only form action. Inline styles support the local tooling.
Deployment headers, TLS and production authentication need a separate review.
No frontend route guard substitutes for server-side authorization.

## Tests

```powershell
cd frontend
npm run build
npm test
```

Browser tests use the real FastAPI auth routes, verifier, session service,
no-store and local-origin middleware, with the existing in-memory database
double. They never read local credential files or connect to PostgreSQL.
The explicit [test fixture](tests/auth_fixture.py) binds only 127.0.0.1:8001;
the test Vite server uses 5174 and the built default preview uses 5176. Existing servers are never reused. All credentials
are synthetic test inputs. No election/ballot/result endpoint is mocked into
the application. One expiry response is deliberately intercepted by the test.

Use a Python environment with the existing combined RA dependencies installed:

```powershell
# From the repository root (use an existing suitable environment if available):
python -m venv .venv
.venv/Scripts/python.exe -m pip install --no-deps -r backend/ra/credential-requirements.lock.txt
$env:EVOTE_TEST_PYTHON = (Resolve-Path .venv/Scripts/python.exe).Path
cd frontend
npm run build
npm run test:browser
```

Windows tests use installed Microsoft Edge. On Linux, install Chromium first:
```bash
npx --no-install playwright install --with-deps chromium
EVOTE_TEST_PYTHON=/absolute/path/to/python npm run test:browser
```

Browser traces, video and automatic screenshots are disabled to avoid
credential-bearing diagnostics. Generated test results are ignored and never
uploaded by the [new frontend workflow](../.github/workflows/web-ui.yml).
That workflow uses pinned official actions, contents: read and no repository
secrets, database service, migration, or artifact upload. Its GitHub execution
is pending; local test evidence is recorded in the implementation report.

## Remaining integration work

Define and authorize real election/eligibility, admin and published-evidence APIs.
Review browser-compatible client blinding, independent trust pins, protected
recovery, anonymous submission and signature verification before enabling
credential/voting actions. Encrypted candidate-choice validity remains a Tally
responsibility in the local demo. Do not infer full anonymity, coercion resistance
or end-to-end verifiability from this visual foundation.
