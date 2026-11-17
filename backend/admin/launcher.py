"""Opt-in loopback Admin launcher; no credential discovery or privileged login."""
import argparse
import getpass
import sys
import warnings
from pathlib import Path

import psycopg
import uvicorn
from cryptography.hazmat.primitives import serialization

from backend.admin.auth import AdminAuthentication
from backend.admin.router import create_admin_app, identifier
from backend.admin.service import AdminService, ManifestAuthority
from backend.admin.store import VotingAdminStore, RAPublisherStore
from backend.crypto.credential_protocol import strict_json, b64decode


def load_verifier(path):
    with Path(path).open("rb") as stream:
        raw = stream.read(16385)
    if len(raw) > 16384:
        raise ValueError("Invalid verifier size")
    data = strict_json(raw)
    if type(data) is not dict or set(data) != {"enabled", "environment", "admin_id", "username", "salt", "digest"} or data["enabled"] is not True or data["environment"] != "local-demo":
        raise ValueError("Explicit local Admin verifier required")
    identifier(data["admin_id"])
    return data


def prompt(label):
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        value = getpass.getpass(label)
    if not value:
        raise ValueError("Missing local configuration")
    return value


def connections(database, login, password):
    if (database, login) not in {("voting_db", "voting_admin_login"), ("ra_db", "ra_election_publisher_login")}:
        raise ValueError("Restricted local identity required")

    def connect():
        conn = psycopg.connect(host="127.0.0.1", port=5432, dbname=database, user=login,
                               password=password, connect_timeout=5, options="-c statement_timeout=10000 -c lock_timeout=3000")
        try:
            if conn.execute("SELECT current_database(),session_user,current_user").fetchone() != (database, login, login):
                raise ValueError("Runtime identity mismatch")
            owner = "voting_owner" if database == "voting_db" else "ra_owner"
            if conn.execute("SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname=current_database()").fetchone() != (owner,):
                raise ValueError("Unexpected database owner")
            if not conn.execute("SELECT NOT (rolsuper OR rolinherit OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls) FROM pg_roles WHERE rolname=current_user").fetchone()[0]:
                raise ValueError("Unsafe runtime identity")
            if conn.execute("SELECT EXISTS(SELECT 1 FROM pg_auth_members WHERE member=(SELECT oid FROM pg_roles WHERE rolname=current_user))").fetchone()[0]:
                raise ValueError("Unsafe membership")
            schema = "voting" if database == "voting_db" else "ra"
            if conn.execute("SELECT has_schema_privilege(current_user,%s,'CREATE') OR has_schema_privilege(current_user,'public','CREATE')", (schema,)).fetchone()[0]:
                raise ValueError("Unsafe schema privileges")
            if conn.execute("""SELECT EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
                WHERE n.nspname IN (%s,%s,%s) AND has_function_privilege(current_user,p.oid,'EXECUTE'))""",
                (schema, schema + "_credential", schema + "_demo")).fetchone()[0]:
                raise ValueError("Unsafe baseline function access")
            if conn.execute("""SELECT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
                WHERE n.nspname IN (%s,%s) AND CASE WHEN c.relkind IN ('r','p','v','m','f') THEN
                has_table_privilege(current_user,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
                OR has_any_column_privilege(current_user,c.oid,'SELECT,INSERT,UPDATE,REFERENCES') ELSE false END)""", (schema, schema + "_admin")).fetchone()[0]:
                raise ValueError("Unsafe direct table access")
            conn.commit()
            return conn
        except BaseException:
            conn.close()
            raise
    return connect


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--enable-local-admin", action="store_true", required=True)
    parser.add_argument("--verifier", type=Path, required=True)
    parser.add_argument("--key-catalogue", type=Path, required=True)
    parser.add_argument("--authority-key", type=Path, required=True)
    parser.add_argument("--authority-pin", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if not sys.stdin.isatty():
            raise ValueError("Interactive local configuration required")
        verifier = load_verifier(args.verifier)
        pin = args.authority_pin.read_bytes()
        voting = VotingAdminStore(connections("voting_db", "voting_admin_login", prompt("Voting admin DB password: ")))
        publisher = RAPublisherStore(connections("ra_db", "ra_election_publisher_login", prompt("RA publisher DB password: ")))
        key = serialization.load_pem_private_key(args.authority_key.read_bytes(), password=prompt("Encrypted manifest authority key passphrase: ").encode("utf8"))
        auth = AdminAuthentication(voting, verifier["admin_id"], verifier["username"], b64decode(verifier["salt"]), b64decode(verifier["digest"], 32))
        service = AdminService(auth, voting, publisher, ManifestAuthority(key, pin), strict_json(args.key_catalogue.read_bytes()))
        uvicorn.run(create_admin_app(service), host="127.0.0.1", port=8002, proxy_headers=False,
                    access_log=False, log_level="critical")
    except Exception:
        parser.exit(1, "Local Admin configuration or service unavailable\n")


if __name__ == "__main__":
    main()
