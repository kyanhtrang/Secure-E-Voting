# RA Demo Database Provisioning

## Scope

Local development only. NOT for production voter identification.

## Prerequisites

- PostgreSQL 18
- ra_db database and baseline RA migrations
- ra_owner database owner role
- ra_migrator_login permitted to SET ROLE ra_owner
- ra_owner has CREATE privilege on ra_db

## One-time administrator provisioning

Connect to ra_db as PostgreSQL administrator.

CREATE ROLE ra_auth_login
    LOGIN NOINHERIT NOSUPERUSER NOCREATEDB
    NOCREATEROLE NOREPLICATION NOBYPASSRLS
    CONNECTION LIMIT 5 PASSWORD NULL;

Use psql \password ra_auth_login to set its password.

GRANT CONNECT ON DATABASE ra_db TO ra_auth_login;

Do not grant ra_auth_login membership in ra_owner.

## Deployment

Run the RA Alembic migrations through revision a9c31d5e8b72.

Commit #3 additionally supplies revision f3c2a1d4e6b8, based on
a9c31d5e8b72. It must be reviewed and applied separately before using
the local HTTP demo. Implementation and database-free tests do not apply it.

Migration creates or reconciles:

- ra_demo schema
- ra_demo.issue_demo_session(text,uuid)
- Restricted EXECUTE permission for ra_auth_login

The additional revision creates only:

- ra_demo.find_active_demo_voter_id(text,text)
- ra_demo.find_active_demo_session(text)
- ra_demo.revoke_demo_session(text)

Each is owned by ra_owner, uses SECURITY DEFINER with a fixed search_path,
and grants EXECUTE only to ra_auth_login besides the owner. No general
RA schema/table/function access is granted. Revocation scopes ownership
and mutation in the same statement. Existing role provisioning is a
separate administrator responsibility; the launcher never provisions roles.

### Role and ACL preflight

The repository's role-separation design and earlier RA migrations require
ra_owner, ra_service, ra_service_login, ra_recovery_worker, and ra_audit_reader.
This document provides the separate ra_auth_login definition above. Complete
creation definitions for the legacy roles are not captured in this repository;
their live existence must not be assumed from the source alone.

Before creating functions, the new revision explicitly requires all six
roles. It rejects unsafe ra_auth_login flags, memberships to or from that role, and effective
general RA schema, table, sequence, or function access. Existing ra_demo USAGE
is required; CREATE must remain denied. It does not repair or broaden ACLs.
After creating/restricting the three functions, it rejects unexpected owner
default grants to any principal other than ra_owner and ra_auth_login.
PUBLIC EXECUTE remains revoked. Any failed preflight/postcondition aborts the
transactional migration without provisioning roles or changing general RA grants.

Existing demo voter identity must be registered separately:
demo-local / demo-voter-001.

## Security limitations

The demo session wrapper does NOT verify the password.
Anyone with ra_auth_login credentials can issue a session for
the one configured demo voter.

Do not expose the database port to untrusted clients.
Do not reuse this design for production elections.
Never store PostgreSQL passwords or access tokens in Git.

The demo credential configuration is stored outside the repository.

## Explicit local HTTP launcher

The launcher reads the existing verifier file only when both command-line
opt-ins below are supplied:

```text
%LOCALAPPDATA%\Secure-E-Voting\ra-demo-auth.local.json
```

Only these verifier fields are accepted from that file:

- RA_ENVIRONMENT=local
- RA_DEMO_AUTH_ENABLED=true
- RA_DEMO_USERNAME: the previously configured demo username
- RA_DEMO_PROVIDER=demo-local
- RA_DEMO_SUBJECT=demo-voter-001
- RA_DEMO_SALT_HEX and RA_DEMO_DIGEST_HEX: existing scrypt verifier material

The file must explicitly enable the demo and specify the local environment
and fixed demo identity. Missing, malformed, oversized, or invalid verifier
configuration fails before prompting for a password. Extra JSON fields,
including any stored database password or database target, are ignored.
No dotenv files or arbitrary credential paths are discovered.

No plaintext application password is part of the configuration. The user
enters it only in the login request. Do not put database/application
passwords in shell command arguments, repository files, logs, or screenshots.
After validating the verifier, the launcher prompts without echo for the
ra_auth_login database password. It rejects getpass's echoing-input fallback.
The password is held only in process memory; it is never taken from the JSON,
ambient password environment variable, or command-line argument, printed,
logged, or persisted. No real local verifier file is read by automated tests.

Database user, host, port, and database are fixed to ra_auth_login,
127.0.0.1, 5432, and ra_db. Missing/invalid configuration
fails without opening a database connection and without printing secrets.

With the project's existing Python environment active:

```text
python -m backend.ra.demo_launcher --enable-local-demo --load-local-verifier
```

Both flags and the file's enable/local settings are required. The server binds only
to 127.0.0.1:8000, with one worker, no proxy-header trust, and no access
logging. It rejects foreign Host/Origin headers and non-loopback peers.
Do not place this demo behind a forwarding proxy or expose its database
port. `uvicorn backend.main:app` retains disabled authentication regardless
of demo environment variables.

Use an HTTP client that keeps credentials and bearer tokens out of its
logs. POST username/password JSON to /api/v1/ra/auth/login; retain the
returned token only in memory. Send Authorization: Bearer with the token
to GET /api/v1/ra/auth/me and POST /api/v1/ra/auth/logout. After logout,
me returns 401. The full status and rate-limit policy is documented in
[the authorization boundary](08-ra-session-authorization-boundary.md).

## Verification

Run:
python scripts/test_ra_auth_login_permissions.py
python scripts/test_ra_demo_real_session_integration.py
python -m pytest tests/ -q

The real-session test removes only the session it creates.

### Commit #3 database-free verification

```text
python -m pytest tests/ -q
git diff --check
```

Use the explicit tests/ target. Legacy scripts/ tests are interactive
database tools, and must not be included in database-free test discovery.
The existing 127 test cases and assertions are retained unchanged.

### A. Existing-demo smoke test (session writes only)

After human approval and application of the reviewed migration to existing
ra_db, the existing active demo-local/demo-voter-001 identity may be reused:

```text
python scripts/test_ra_demo_existing_smoke.py --existing-demo-session-writes
```

The script never loads a verifier file: it creates synthetic HTTP credentials
in memory. It prompts separately for ra_auth_login (application runtime) and
ra_migrator_login (session inspection/cleanup only). It requires the existing
voter to be active and never inserts, updates, disables, or deletes a voter.

It verifies login/me/logout, SHA256(token ASCII) storage, the exact database
15-minute TTL, persisted revocation, and unchanged voter fields. It reserves
one fresh random token before issuance and refuses an existing digest. Cleanup
matches only that token digest AND the existing voter UUID, including when a
login response fails after persistence. Unrelated sessions are never removed.
This reservation supplies only randomness to the real issuer; HTTP, credential
verification, SQL functions, transactions, and database timestamp behavior are real.
No default/production configuration or plaintext HTTP password is reused.

An interrupted process can leave its own session until expiry; do not use
voter-wide cleanup. Concurrent legitimate voter changes can fail the unchanged
voter assertion after exact-session cleanup has committed.

### B. Verified disposable-database integration

Do not run comprehensive mutation tests against existing ra_db. The script
requires an explicitly named ra_demo_test_ database, a canonical UUID marker,
and a matching database comment installed independently by an administrator.
For example, ONLY after verifying that ra_demo_test_security is disposable:

```sql
COMMENT ON DATABASE ra_demo_test_security IS
    'secure-evoting-disposable:f83b1972-4d1c-4e4b-82ca-f67c317f88b8';
```

The separate database must already contain the reviewed RA schema/revision
and least-privilege roles, but no existing fixed demo identity. Provision it
through a separately reviewed process. The current Alembic environment targets
ra_db; these test flags do not retarget Alembic. Do not use an ordinary upgrade
command as a shortcut for provisioning the separately named test database.
The test creates no database, marker, role, grant, or migration.

After human approval, using the matching example target/marker:

```text
python scripts/test_ra_demo_auth_e2e_integration.py --disposable-fixture-writes --database ra_demo_test_security --disposable-marker f83b1972-4d1c-4e4b-82ca-f67c317f88b8
```

An optional --port selects a loopback test server. Before prompting, protected
database names such as ra_db are rejected. Every fixture/runtime connection
verifies the actual database identity and matching server-side marker. Missing
or mismatched marking fails before writes. The existing-voter refusal remains
mandatory even on marked databases; never delete an existing voter to bypass it.

Fixture voters explicitly use is_active=true. The comprehensive tests retain
expiry, voter disablement, concurrent revocation, other-voter isolation,
function metadata/ACLs, and denied general RA access/role switching. Runtime
connections use ra_auth_login only; separate owner fixture connections clean up
only generated voter UUIDs and their sessions. Abrupt termination can require
reviewed fixture cleanup before retrying. Marking is an administrator safety
designation, not proof against a privileged operator mislabeling a database.

Neither path prints passwords/tokens. PASS is evidence only after actual execution.

## Downgrade

Automated downgrade is intentionally disabled because the
ra_demo objects existed before they were captured in Alembic.
Review dependencies and data before any manual removal.
