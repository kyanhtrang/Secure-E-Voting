import getpass
import uuid

import psycopg

password = getpass.getpass("PostgreSQL password for ra_migrator_login: ")
settings = {
    "host": "127.0.0.1",
    "port": 5432,
    "dbname": "ra_db",
    "user": "ra_migrator_login",
    "password": password,
    "autocommit": True,
}
actor = uuid.uuid4()
cases = [
    (uuid.uuid4(), uuid.uuid4(), "concurrency-" + str(uuid.uuid4()))
    for _ in range(2)
]
hash_bytes = b"\xa1" * 32
signature = b"\xb2" * 32
nonce = b"\xc3" * 12


def connect():
    return psycopg.connect(**settings)


def begin_owned(conn):
    conn.execute("BEGIN")
    conn.execute("SET LOCAL ROLE ra_owner")


def issue_args(index):
    voter, election, key_id = cases[index]
    return (
        voter, election, uuid.uuid4(), hash_bytes, key_id,
        signature, nonce, "concurrency-test-storage", "1 day", actor,
    )


issue_sql = """
    SELECT ra.issue_blind_credential(
        %s, %s, %s, %s, %s, %s, %s, %s,
        pg_catalog.clock_timestamp() + (%s::interval), %s
    )
"""
revoke_sql = "SELECT ra.set_voter_eligibility(%s, %s, false, %s)"


def expect_sqlstate(conn, sql, params, expected, label, lock_timeout=False):
    begin_owned(conn)
    try:
        if lock_timeout:
            conn.execute("SET LOCAL lock_timeout = '500ms'")
        try:
            conn.execute(sql, params).fetchone()
        except psycopg.Error as exc:
            if exc.sqlstate != expected:
                raise AssertionError(
                    f"{label}: expected {expected}, got {exc.sqlstate}: {exc}"
                ) from exc
            print(f"PASS: {label} ({expected})")
        else:
            raise AssertionError(f"{label}: statement unexpectedly succeeded")
    finally:
        conn.execute("ROLLBACK")


seeded = False
a = None
b = None
try:
    with connect() as setup:
        begin_owned(setup)
        for voter, election, key_id in cases:
            setup.execute(
                "INSERT INTO ra.voters(voter_id, auth_provider, auth_subject) "
                "VALUES (%s, 'concurrency_test', %s)",
                (voter, str(voter)),
            )
            result = setup.execute(
                "SELECT ra.set_voter_eligibility(%s, %s, true, %s)",
                (voter, election, actor),
            ).fetchone()[0]
            assert result is True, "Could not grant test eligibility"
            setup.execute(
                """INSERT INTO ra.ra_signing_keys(
                    ra_key_id, election_id, public_key_spki_der,
                    public_key_fingerprint, private_key_reference,
                    key_state, activated_at
                ) VALUES (%s, %s, %s, %s, %s, 'ACTIVE', clock_timestamp())""",
                (key_id, election, b"\x30\x00", b"\xd4" * 32,
                 "test-only://concurrency"),
            )
        setup.execute("COMMIT")
        seeded = True
    print("PASS: Committed isolated test fixtures")

    a, b = connect(), connect()

    # Case A: the revoke transaction holds the voter lock first.
    voter, election, _ = cases[0]
    begin_owned(a)
    result = a.execute(revoke_sql, (voter, election, actor)).fetchone()[0]
    assert result is True, "Case A revoke did not succeed"
    expect_sqlstate(
        b, issue_sql, issue_args(0), "55P03",
        "Issuance blocked by pending revoke", lock_timeout=True,
    )
    a.execute("COMMIT")
    expect_sqlstate(
        b, issue_sql, issue_args(0), "23514",
        "Issuance rejected after revoke commits",
    )
    begin_owned(a)
    eligible = a.execute(
        "SELECT is_eligible FROM ra.voter_eligibility "
        "WHERE voter_id=%s AND election_id=%s", (voter, election)
    ).fetchone()[0]
    count = a.execute(
        "SELECT count(*) FROM ra.blind_issuances "
        "WHERE voter_id=%s AND election_id=%s", (voter, election)
    ).fetchone()[0]
    audit = a.execute(
        "SELECT count(*) FROM ra.ra_audit_events WHERE voter_id=%s "
        "AND election_id=%s AND event_type='ELIGIBILITY_REVOKED' "
        "AND outcome='SUCCESS'", (voter, election)
    ).fetchone()[0]
    assert eligible is False and count == 0 and audit == 1, "Case A state is inconsistent"
    a.execute("ROLLBACK")
    print("PASS: Revoke-first final state consistent")

    # Case B: the issuance transaction holds the voter lock first.
    voter, election, _ = cases[1]
    begin_owned(a)
    issuance_id = a.execute(issue_sql, issue_args(1)).fetchone()[0]
    assert issuance_id is not None, "Case B initial issuance failed"
    expect_sqlstate(
        b, revoke_sql, (voter, election, actor), "55P03",
        "Revoke blocked by pending issuance", lock_timeout=True,
    )
    a.execute("COMMIT")
    expect_sqlstate(
        b, revoke_sql, (voter, election, actor), "23514",
        "Revoke rejected after issuance commits",
    )
    begin_owned(a)
    eligible = a.execute(
        "SELECT is_eligible FROM ra.voter_eligibility "
        "WHERE voter_id=%s AND election_id=%s", (voter, election)
    ).fetchone()[0]
    count = a.execute(
        "SELECT count(*) FROM ra.blind_issuances "
        "WHERE voter_id=%s AND election_id=%s", (voter, election)
    ).fetchone()[0]
    issued_audit = a.execute(
        "SELECT count(*) FROM ra.ra_audit_events WHERE voter_id=%s "
        "AND election_id=%s AND event_type='BLIND_ISSUANCE_ISSUED' "
        "AND outcome='SUCCESS'", (voter, election)
    ).fetchone()[0]
    revoked_audit = a.execute(
        "SELECT count(*) FROM ra.ra_audit_events WHERE voter_id=%s "
        "AND election_id=%s AND event_type='ELIGIBILITY_REVOKED' "
        "AND outcome='SUCCESS'", (voter, election)
    ).fetchone()[0]
    assert (eligible is True and count == 1 and issued_audit == 1
            and revoked_audit == 0), "Case B state is inconsistent"
    a.execute("ROLLBACK")
    print("PASS: Issuance-first final state consistent")
finally:
    for conn in (a, b):
        if conn is not None:
            try:
                conn.execute("ROLLBACK")
            except psycopg.Error:
                pass
            conn.close()

    if seeded:
        with connect() as cleanup:
            begin_owned(cleanup)
            voters = (cases[0][0], cases[1][0])
            elections = (cases[0][1], cases[1][1])
            cleanup.execute(
                "DELETE FROM ra.ra_audit_events WHERE voter_id IN (%s, %s)",
                voters,
            )
            cleanup.execute(
                "DELETE FROM ra.blind_issuances WHERE voter_id IN (%s, %s)",
                voters,
            )
            cleanup.execute(
                "DELETE FROM ra.voter_eligibility WHERE voter_id IN (%s, %s)",
                voters,
            )
            cleanup.execute(
                "DELETE FROM ra.ra_signing_keys WHERE election_id IN (%s, %s)",
                elections,
            )
            cleanup.execute(
                "DELETE FROM ra.voters WHERE voter_id IN (%s, %s)",
                voters,
            )
            cleanup.execute("COMMIT")
        print("PASS: Test fixtures cleaned up")

print("RA two-session concurrency tests: PASS")
