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

Migration creates or reconciles:

- ra_demo schema
- ra_demo.issue_demo_session(text,uuid)
- Restricted EXECUTE permission for ra_auth_login

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

## Verification

Run:
python scripts/test_ra_auth_login_permissions.py
python scripts/test_ra_demo_real_session_integration.py
python -m pytest tests/ -q

The real-session test removes only the session it creates.

## Downgrade

Automated downgrade is intentionally disabled because the
ra_demo objects existed before they were captured in Alembic.
Review dependencies and data before any manual removal.
