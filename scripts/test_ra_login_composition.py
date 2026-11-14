import getpass
import sys
from pathlib import Path
from uuid import uuid4

import psycopg

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.ra.auth_service import (
    RAAuthenticationService,
    VerifiedIdentity,
    AuthenticationDenied,
    AuthenticationUnavailable,
)
from backend.ra.postgres_voter_account_reader import (
    PostgreSQLVoterAccountReader,
)


class FakeVerifier:
    def __init__(self, identity):
        self.identity = identity

    def verify_credentials(self, username, password):
        if username == "demo-user" and password == "demo-password":
            return self.identity
        return None


class FakeIssuer:
    def __init__(self, fail=False):
        self.issued = []
        self.fail = fail

    def issue_ra_session(self, voter_id):
        if self.fail:
            raise RuntimeError("Synthetic issuer failure")
        self.issued.append(voter_id)
        return "synthetic-token-not-for-production"


class ForbiddenReader:
    def find_active_voter_id(self, provider, subject):
        raise AssertionError(
            "Database lookup must not happen"
        )


class FailingReader:
    def find_active_voter_id(self, provider, subject):
        raise RuntimeError("Database unavailable")


def check(condition, label):
    if not condition:
        raise AssertionError(f"FAIL: {label}")
    print(f"PASS {label}")


def expect_denied(service, issuer):
    before = len(issuer.issued)
    try:
        service.login("demo-user", "demo-password")
    except AuthenticationDenied:
        pass
    else:
        raise AssertionError("Login unexpectedly accepted")
    assert len(issuer.issued) == before


def main():
    password = getpass.getpass(
        "PostgreSQL password for ra_migrator_login: "
    )

    def owner_connection():
        conn = psycopg.connect(
            host="127.0.0.1",
            port=5432,
            dbname="ra_db",
            user="ra_migrator_login",
            password=password,
            connect_timeout=5,
        )
        try:
            conn.execute("SET ROLE ra_owner")
            conn.commit()
            return conn
        except BaseException:
            conn.close()
            raise

    provider = "login_composition_test"
    active_id = uuid4()
    inactive_id = uuid4()
    fixture_created = False

    reader = PostgreSQLVoterAccountReader(owner_connection)

    def make_service(identity, account_reader=reader, fail_issuer=False):
        issuer = FakeIssuer(fail=fail_issuer)
        service = RAAuthenticationService(
            FakeVerifier(identity),
            account_reader,
            issuer,
        )
        return service, issuer

    try:
        with owner_connection() as conn:
            db, session_user, role = conn.execute(
                "SELECT current_database(), session_user, current_user"
            ).fetchone()

            check(
                (db, session_user, role)
                == ("ra_db", "ra_migrator_login", "ra_owner"),
                "1/9: Database identity verified",
            )

            conn.execute(
                """
                INSERT INTO ra.voters (
                    voter_id, auth_provider, auth_subject, is_active
                ) VALUES
                    (%s, %s, %s, true),
                    (%s, %s, %s, false)
                """,
                (
                    active_id, provider, str(active_id),
                    inactive_id, provider, str(inactive_id),
                ),
            )

        fixture_created = True

        active_identity = VerifiedIdentity(
            provider=provider,
            subject=str(active_id),
        )

        service, issuer = make_service(active_identity)
        token = service.login("demo-user", "demo-password")

        check(
            token == "synthetic-token-not-for-production"
            and issuer.issued == [active_id],
            "2/9: Verified identity receives mock session",
        )

        service, issuer = make_service(
            active_identity,
            ForbiddenReader(),
        )

        try:
            service.login("demo-user", "wrong-password")
        except AuthenticationDenied:
            pass
        else:
            raise AssertionError("Wrong password accepted")

        check(
            issuer.issued == [],
            "3/9: Invalid credentials denied before lookup",
        )

        service, issuer = make_service(
            VerifiedIdentity(provider, str(uuid4()))
        )
        expect_denied(service, issuer)
        check(True, "4/9: Unregistered identity denied")

        service, issuer = make_service(
            VerifiedIdentity("wrong_provider", str(active_id))
        )
        expect_denied(service, issuer)
        check(True, "5/9: Wrong provider denied")

        service, issuer = make_service(
            VerifiedIdentity(provider, str(inactive_id))
        )
        expect_denied(service, issuer)
        check(True, "6/9: Inactive voter denied")

        service, issuer = make_service(
            active_identity,
            fail_issuer=True,
        )

        try:
            service.login("demo-user", "demo-password")
        except AuthenticationUnavailable:
            pass
        else:
            raise AssertionError("Issuer failure accepted")

        check(
            issuer.issued == [],
            "7/9: Session issuer failure denied",
        )

        service, issuer = make_service(
            active_identity,
            FailingReader(),
        )

        try:
            service.login("demo-user", "demo-password")
        except AuthenticationUnavailable:
            pass
        else:
            raise AssertionError("Database failure accepted")

        check(
            issuer.issued == [],
            "8/9: Database failure denied",
        )

        with owner_connection() as conn:
            conn.execute(
                """
                UPDATE ra.voters
                SET is_active = false
                WHERE voter_id = %s
                """,
                (active_id,),
            )

        service, issuer = make_service(active_identity)
        expect_denied(service, issuer)

        check(
            issuer.issued == [],
            "9/9: Disabled voter denied on next login",
        )

    finally:
        if fixture_created:
            with owner_connection() as conn:
                conn.execute(
                    """
                    DELETE FROM ra.voters
                    WHERE voter_id IN (%s, %s)
                      AND auth_provider = %s
                    """,
                    (active_id, inactive_id, provider),
                )

            with owner_connection() as conn:
                remaining = conn.execute(
                    """
                    SELECT COUNT(*) FROM ra.voters
                    WHERE voter_id IN (%s, %s)
                    """,
                    (active_id, inactive_id),
                ).fetchone()[0]

            check(remaining == 0, "Fixture cleanup")

    print("RA login composition integration: PASS 9/9")


if __name__ == "__main__":
    main()