"""Explicit, separately trusted setup only; runtime never imports this module.

No container creation/start or credential discovery. The already approved owned
container must be a fresh PG18 cluster. Existing demo databases are refused, not
updated. Credentials come from encrypted custody/private operator prompts.
"""
from uuid import UUID

from psycopg import sql
from pydantic import SecretStr

from deployment.local_demo_policy import ROLE_DATABASE, database_spec, fingerprint, require
from deployment.local_runtime_migrations import setup_identity

NOLOGIN = {
 'ra': ('ra_owner','ra_service','ra_recovery_worker','ra_audit_reader'),
 'voting': ('voting_owner','voting_admin_service','voting_ballot_service','voting_snapshot_worker',
    'voting_tally_worker','voting_publication_service','voting_board_reader','voting_audit_reader'),
}


def bootstrap(plan, approval, kind, maintenance_connection, credentials, *, boundary, confirmation):
    approval.check(plan)
    require(confirmation == 'BOOTSTRAP FRESH DEMO '+fingerprint(plan), 'APPROVAL_REQUIRED')
    spec = database_spec(plan,kind)
    expected = {r for r,k in ROLE_DATABASE.items() if k == kind}|{kind+'_migrator_login'}
    if kind == 'ra': expected.add('ra_service_login')
    require(set(credentials) == expected and all(isinstance(v,SecretStr) and len(v.get_secret_value()) >= 32 for v in credentials.values()), 'ROLE')
    require(len({v.get_secret_value() for v in credentials.values()}) == len(credentials), 'ROLE')
    boundary()
    with maintenance_connection() as conn:
        require(conn.autocommit is True, 'CONFIG')
        require(conn.execute('SELECT current_database(),session_user,current_user,current_setting(\'server_version_num\')::integer').fetchone()[:3]
            == ('postgres','postgres','postgres'), 'IDENTITY')
        require(180000 <= conn.execute("SELECT current_setting('server_version_num')::integer").fetchone()[0] < 190000, 'IDENTITY')
        require(conn.execute("SELECT datname FROM pg_database WHERE datname NOT IN ('postgres','template0','template1')").fetchall() == [], 'OWNERSHIP')
        require(conn.execute("SELECT 1 FROM pg_roles WHERE rolname=ANY(%s::text[])",(list(expected)+list(NOLOGIN[kind]),)).fetchall() == [], 'OWNERSHIP')
        require(conn.execute("SELECT count(*) FROM pg_hba_file_rules WHERE error IS NOT NULL OR (type LIKE 'host%' AND auth_method<>'scram-sha-256')").fetchone() == (0,), 'ROLE')
        for database in ('postgres','template0','template1'):
            conn.execute(sql.SQL('REVOKE ALL ON DATABASE {} FROM PUBLIC').format(sql.Identifier(database)))
        for role in NOLOGIN[kind]:
            conn.execute(sql.SQL('CREATE ROLE {} NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS').format(sql.Identifier(role)))
        for role,password in credentials.items():
            conn.execute(sql.SQL('CREATE ROLE {} LOGIN {} NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 40 PASSWORD {}').format(
                sql.Identifier(role),sql.SQL('INHERIT' if role == 'voting_ballot_login' else 'NOINHERIT'),sql.Literal(password.get_secret_value())))
        conn.execute(sql.SQL('GRANT {} TO {} WITH INHERIT FALSE, SET TRUE').format(sql.Identifier(spec['owner']),sql.Identifier(kind+'_migrator_login')))
        if kind == 'voting': conn.execute('GRANT voting_ballot_service TO voting_ballot_login WITH INHERIT TRUE, SET FALSE')
        conn.execute(sql.SQL('CREATE DATABASE {} OWNER {} TEMPLATE template0').format(sql.Identifier(spec['name']),sql.Identifier(spec['owner'])))
        conn.execute(sql.SQL('REVOKE ALL ON DATABASE {} FROM PUBLIC').format(sql.Identifier(spec['name'])))
        for role in expected-{'ra_service_login'}:
            conn.execute(sql.SQL('GRANT CONNECT ON DATABASE {} TO {}').format(sql.Identifier(spec['name']),sql.Identifier(role)))
        conn.execute(sql.SQL('COMMENT ON DATABASE {} IS {}').format(sql.Identifier(spec['name']),sql.Literal(spec['marker'])))
    # A failure partway is preserved for explicit operator review. No destructive
    # rollback of a partially initialized cluster, role or database is attempted.


def install_operators(plan, approval, setup, *, boundary, confirmation):
    approval.check(plan)
    require(confirmation == 'ENROLL SYNTHETIC ADMIN TALLY PUBLISHER '+fingerprint(plan), 'APPROVAL_REQUIRED')
    boundary()
    admin,tally = UUID(plan['identifiers']['admin']),UUID(plan['identifiers']['tally'])
    with setup() as conn:
        setup_identity(conn,plan,'voting')
        conn.execute('SET LOCAL ROLE voting_owner')
        require(conn.execute('SELECT version_num FROM voting.alembic_version').fetchall() == [('f8b31c2d970a',)], 'SOURCE')
        conn.execute('SELECT pg_advisory_xact_lock(71811002)')
        expected = [('voting_admin.principals','admin_id',admin,'ELECTION_ADMIN'),
                    ('voting_tally.principals','operator_id',tally,'TALLY_OPERATOR')]
        for table,column,identity,role in expected:
            rows = conn.execute('SELECT '+column+',role,is_active FROM '+table).fetchall()
            require(rows in ([],[(identity,role,True)]), 'IDENTITY')
            if not rows: conn.execute('INSERT INTO '+table+'('+column+',role,is_active) VALUES(%s,%s,true)',(identity,role))
        publishers = conn.execute('SELECT admin_id,is_active FROM voting_board.publishers').fetchall()
        require(publishers in ([],[(admin,True)]), 'IDENTITY')
        if not publishers: conn.execute('INSERT INTO voting_board.publishers(admin_id,is_active) VALUES(%s,true)',(admin,))
