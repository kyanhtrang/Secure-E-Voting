"""Separately approved local two-voter installer; never a migration or HTTP API.

Reuses the hosted gate's reviewed SQL, NOT its hosted installer or environment
guard. The schema name intentionally remains explicitly test-only. No existing
ra_demo function, voter, eligibility, reservation or session is replaced/deleted.
"""
from uuid import UUID

from deployment.local_demo_policy import database_spec, fingerprint, require, validate_plan
from deployment.local_runtime_database import IDENTITY_SQL
from scripts.voting_tally_auth import DDL, SIGNATURES, SUBJECTS, check_function_acl


def install(plan, approval, setup_connection, *, boundary, confirmation):
    approval.check(plan)
    require(confirmation == 'INSTALL TWO SYNTHETIC VOTERS '+fingerprint(plan), 'APPROVAL_REQUIRED')
    boundary()  # Actual owned VM/container identity BEFORE opening setup connection.
    spec = database_spec(plan,'ra')
    identities = {subject:UUID(plan['identifiers'][name]) for subject,name in zip(SUBJECTS,('voter_a','voter_b'))}
    require(len(set(identities.values())) == 2, 'IDENTITY')
    with setup_connection() as conn:
        row = conn.execute(IDENTITY_SQL).fetchone()
        require(row[:5] == (spec['name'],'ra_migrator_login','ra_migrator_login','ra_owner',spec['marker'])
            and type(row[5]) is int and 180000 <= row[5] < 190000, 'IDENTITY')
        conn.execute('SET LOCAL ROLE ra_owner')
        require(conn.execute('SELECT version_num FROM ra.alembic_version').fetchall() == [('bf932d0f8702',)], 'SOURCE')
        # One lock order, before schema/identity reads, including concurrent setup.
        conn.execute("SELECT pg_catalog.pg_advisory_xact_lock(71811001)")
        conn.execute('LOCK TABLE ra.voters IN SHARE ROW EXCLUSIVE MODE')
        existing = conn.execute("SELECT voter_id,auth_provider,auth_subject,is_active FROM ra.voters ORDER BY auth_subject").fetchall()
        expected = {(v,'demo-local',s,True) for s,v in identities.items()}
        schema = conn.execute("SELECT pg_catalog.to_regnamespace('ra_e2e_auth')").fetchone()
        if schema != (None,):
            # Restart is verification only. Losing recovery state never resets a
            # voter, sessions or the one-credential-per-election authorization.
            require(set(existing) == expected and len(existing) == 2, 'IDENTITY')
            rows = conn.execute('SELECT voter_id,provider,subject FROM ra_e2e_auth.voters').fetchall()
            require(set(rows) == {(v,'demo-local',s) for s,v in identities.items()} and len(rows) == 2, 'IDENTITY')
            check_function_acl(conn)
            return identities
        require(existing == [], 'OWNERSHIP')
        for subject in SUBJECTS:
            conn.execute("INSERT INTO ra.voters(voter_id,auth_provider,auth_subject,is_active) VALUES(%s,'demo-local',%s,true)",
                (identities[subject],subject))
        conn.execute(DDL)
        for subject in SUBJECTS:
            conn.execute("INSERT INTO ra_e2e_auth.voters(voter_id,provider,subject) VALUES(%s,'demo-local',%s)",
                (identities[subject],subject))
        for signature in SIGNATURES:
            conn.execute('GRANT EXECUTE ON FUNCTION ra_e2e_auth.'+signature+' TO ra_auth_login')
        check_function_acl(conn)  # Any default ACL drift rolls back ALL fixture DDL.
    return identities  # Commit has completed; setup credentials are not retained.
