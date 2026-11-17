"""Explicit local-only Voting process. No RA routes, sessions or private keys."""

import argparse
import getpass
import warnings
from pathlib import Path

import psycopg
import uvicorn
from fastapi import FastAPI
from pydantic import SecretStr

from backend.ra.demo_launcher import LocalDemoMiddleware
from backend.voting.ballot_router import get_ballot_service, router
from backend.voting.ballot_service import BallotService, VotingUnavailable
from backend.voting.postgres_ballot_store import PostgreSQLBallotStore


def connection_factory(password):
    if not isinstance(password, SecretStr) or not password.get_secret_value():
        raise ValueError("Explicit local Voting configuration required")

    def connect():
        conn = None
        try:
            conn = psycopg.connect(host="127.0.0.1", port=5432, dbname="voting_db",
                user="voting_ballot_login", password=password.get_secret_value(), connect_timeout=5,
                options="-c statement_timeout=5000 -c lock_timeout=2000",
                application_name="secure-evoting-anonymous-voting")
            row = conn.execute("""SELECT current_database(), session_user, current_user,
                r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls,
                pg_has_role(current_user,'voting_owner','MEMBER'),
                has_schema_privilege(current_user,'voting','CREATE') OR has_schema_privilege(current_user,'public','CREATE'),
                EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
                  WHERE n.nspname='voting' AND c.relkind IN ('r','p','v','m','f') AND
                  (has_table_privilege(current_user,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
                   OR has_any_column_privilege(current_user,c.oid,'SELECT,INSERT,UPDATE,REFERENCES'))),
                EXISTS(SELECT 1 FROM pg_auth_members m JOIN pg_roles child ON child.oid=m.member
                  JOIN pg_roles parent ON parent.oid=m.roleid WHERE child.rolname=current_user
                  AND parent.rolname<>'voting_ballot_service'),
                EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
                  WHERE n.nspname='voting' AND p.proname NOT IN
                  ('ballot_policy','accept_anonymous_ballot','recover_ballot_receipt')
                  AND has_function_privilege(current_user,p.oid,'EXECUTE'))
                FROM pg_roles r WHERE r.rolname=current_user""").fetchone()
            if row != ("voting_db", "voting_ballot_login", "voting_ballot_login", False, False, False, False, False, False):
                raise VotingUnavailable()
            conn.commit()
            return conn
        except Exception:
            if conn is not None:
                conn.close()
            raise VotingUnavailable() from None
    return connect


def create_voting_app(service):
    app = FastAPI(title="Secure E-Voting Local Anonymous Voting", debug=False,
                  docs_url=None, redoc_url=None, openapi_url=None)
    app.include_router(router)
    app.dependency_overrides[get_ballot_service] = lambda: service
    app.add_middleware(LocalDemoMiddleware)
    return app


def main():
    parser = argparse.ArgumentParser(description="Explicit local anonymous Voting demo")
    parser.add_argument("--enable-local-voting", action="store_true", required=True)
    parser.add_argument("--manifest-authority-pin", type=Path, required=True,
                        help="Independently trusted raw Ed25519 PUBLIC key (32 bytes)")
    args = parser.parse_args()
    try:
        pin = args.manifest_authority_pin.read_bytes()
        if len(pin) != 32:
            raise ValueError()
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            password = SecretStr(getpass.getpass("PostgreSQL password for voting_ballot_login: "))
        service = BallotService(PostgreSQLBallotStore(connection_factory(password)), pin)
        uvicorn.run(create_voting_app(service), host="127.0.0.1", port=8001, proxy_headers=False,
                    forwarded_allow_ips="", access_log=False, workers=1, log_level="warning", server_header=False)
    except Exception:
        parser.exit(2, "Local Voting unavailable or invalid configuration\n")


if __name__ == "__main__":
    main()
