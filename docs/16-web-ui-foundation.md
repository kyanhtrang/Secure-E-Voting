# Commit 5: web UI foundation review

Implemented on feat/web-ui-foundation from merge commit 6208210. At task start the original
main checkout reported an unfinished merge, so implementation was isolated
in a sibling feature worktree without finishing, quitting or modifying that
merge. No commit, push, merge, PostgreSQL connection or migration was performed.

## Delivered

The new [frontend](../frontend/README.md) is a separate locked React/Vite/
TypeScript package with React Router, semantic forms and navigation, reduced-
motion support, responsive desktop/mobile layouts, loading/error/success states,
and separate Voter/Admin/Public workspace routes. Screenshots are supplied as
external review artifacts; the authenticated dashboard screenshot uses only the
synthetic in-memory browser-test account, not an existing voter or election.

The [typed auth client](../frontend/src/api/auth.ts) uses the real Login/Me/Logout
schemas. The [session provider](../frontend/src/auth/session.tsx) checks identity
before allowing protected pages, revalidates session status, handles expiry and
ambiguous logout, aborts stale requests and discards memory-only access when
leaving the voter workspace. The [local Vite proxy](../frontend/vite.config.ts)
preserves Host/Origin and exposes only those three auth routes in explicit
local-demo mode. Default authentication remains disabled in backend.main.app.
No backend source, applied migration, frozen cryptography or previous test is changed.

Election catalogue/detail screens honestly report unavailable APIs. The existing
credential endpoint is documented but not wired without trusted client-side
preparation/recovery. Admin screens expose no privileged operation or claimed
admin login. Public results show no counts/candidates/evidence; a PUBLISHED gate
cannot be set through URL parameters or voter authentication. Receipt verification,
bulletin board and anonymous voting remain clearly disabled foundations.

## Validation

| Check | Actual local evidence |
| --- | --- |
| Frontend production build and TypeScript checks | PASS, Vite 8.3.8 / TypeScript 7.0.2 / Node 24.22.3 |
| Component and API contract tests | 48 passed |
| Browser tests, installed Microsoft Edge | 7 passed in 21.4s; real HTTP auth with in-memory DB, expiry/reload, public boundary, origin rejection, admin controls, default build auth disabled and 1440/390/320px keyboard/responsive checks |
| Existing database-free backend and crypto suite | 424 passed in 36.30s, unchanged |
| Frozen TypeScript crypto compilation | PASS; original locks unchanged |
| NPM dependency audit | 0 vulnerabilities reported at installation |
| Whitespace, workflow YAML, source parsing and secret-pattern review | PASS; no secret-pattern findings |
| Real user database/authentication | NOT RUN; browser server uses explicit synthetic fixture only |
| New frontend GitHub workflow | NOT RUN; publication requires human review |

Build outputs and dependencies are ignored. Screenshot artifacts do not contain
passwords, bearer tokens or real election results. No claim of live PostgreSQL
integration or a real vote follows from these frontend tests.

The change adds 28 new files and modifies only .gitignore among previously
tracked files. All implementation changes remain uncommitted in the feature
worktree. No operation was performed to conclude or discard the original merge.

## Changed files and architecture

- [Package](../frontend/package.json), [lockfile](../frontend/package-lock.json), [TypeScript configuration](../frontend/tsconfig.json),
  [Vite configuration](../frontend/vite.config.ts), [Vitest configuration](../frontend/vitest.config.ts),
  [Playwright configuration](../frontend/playwright.config.ts), [HTML entry](../frontend/index.html),
  [favicon](../frontend/public/favicon.svg).
- [Entry point](../frontend/src/main.tsx), [route tree](../frontend/src/app.tsx),
  [public configuration](../frontend/src/config.ts), [auth API](../frontend/src/api/auth.ts),
  [voter session](../frontend/src/auth/session.tsx).
- [Application shell](../frontend/src/components/shell.tsx), [reusable UI](../frontend/src/components/ui.tsx),
  [design tokens](../frontend/src/tokens.css), [responsive styles](../frontend/src/styles.css).
- [Voter screens](../frontend/src/pages/voter.tsx), [Admin screens](../frontend/src/pages/admin.tsx),
  [Public/anonymous screens](../frontend/src/pages/public.tsx).
- [API tests](../frontend/src/api/auth.test.ts), [component tests](../frontend/src/app.test.tsx),
  [test setup](../frontend/src/test/setup.ts), [browser tests](../frontend/tests/browser/smoke.spec.ts),
  [synthetic auth server](../frontend/tests/auth_fixture.py).
- [Installation/contract/security documentation](../frontend/README.md),
  [frontend CI](../.github/workflows/web-ui.yml), and [.gitignore](../.gitignore).

The frontend has no Axios/global bearer interceptor, shared auth state on public
routes, persistent token cache or new cryptographic primitive. UI capability
declarations describe unavailable services and do not invent backend DTOs.
Read-only navigation is not an authorization boundary for future admin operations;
the server must enforce all privileged permissions before any control is enabled.

The next milestone needs reviewed election/publication DTOs and authorization,
browser credential lifecycle integration, anonymous voting and real evidence
verification. Production deployment, accessibility audits with assistive
technologies, TLS, CSP response headers and full voting/tally acceptance remain.
Stop for human review.
