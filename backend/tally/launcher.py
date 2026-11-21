"""Explicit local Tally operator runtime. No automatic credential or key discovery."""
import argparse
from pathlib import Path
import sys

import psycopg
from pydantic import SecretStr
import uvicorn
from cryptography.hazmat.primitives import serialization

from backend.admin.launcher import prompt
from backend.crypto.credential_protocol import strict_json, b64decode, key_id
from backend.tally.http import create_tally_app
from backend.tally.runtime import TallyAuthentication, TallyService, TallyStore
from backend.tally.verification import EvidenceVault


def connection_factory(password):
    if not isinstance(password, SecretStr) or not password.get_secret_value(): raise ValueError("Explicit Tally credential required")
    def connect():
        conn = psycopg.connect(host="127.0.0.1", port=5432, dbname="voting_db", user="voting_tally_login",
            password=password.get_secret_value(), connect_timeout=5, options="-c statement_timeout=30000 -c lock_timeout=3000")
        try:
            row = conn.execute("""SELECT current_database(),session_user,current_user,pg_get_userbyid(d.datdba),
                r.rolsuper OR r.rolinherit OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls,
                EXISTS(SELECT 1 FROM pg_auth_members WHERE member=r.oid)
                FROM pg_roles r CROSS JOIN pg_database d WHERE r.rolname=current_user AND d.datname=current_database()""").fetchone()
            if row != ("voting_db", "voting_tally_login", "voting_tally_login", "voting_owner", False, False): raise ValueError("Unsafe Tally identity")
            if conn.execute("""SELECT EXISTS(SELECT 1 FROM pg_namespace n WHERE n.nspname IN ('voting','voting_admin','voting_tally','public') AND has_schema_privilege(current_user,n.oid,'CREATE'))
                OR EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname IN ('voting','voting_admin') AND has_function_privilege(current_user,p.oid,'EXECUTE'))
                OR EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname IN ('voting','voting_admin','voting_tally')
                 AND CASE WHEN c.relkind IN ('r','p','v','m','f') THEN has_table_privilege(current_user,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
                  OR has_any_column_privilege(current_user,c.oid,'SELECT,INSERT,UPDATE,REFERENCES')
                  WHEN c.relkind='S' THEN has_sequence_privilege(current_user,c.oid,'USAGE,SELECT,UPDATE') ELSE false END)""").fetchone() != (False,):
                raise ValueError("Unsafe Tally ACL")
            conn.commit(); return conn
        except BaseException:
            conn.close(); raise
    return connect


def verifier(path):
    with Path(path).open("rb") as stream: raw = stream.read(16385)
    if len(raw) > 16384: raise ValueError("Invalid local verifier")
    value = strict_json(raw)
    if type(value) is not dict or set(value) != {"enabled", "environment", "operator_id", "username", "salt", "digest"} or value["enabled"] is not True or value["environment"] != "local-demo":
        raise ValueError("Explicit local Tally verifier required")
    return value


class EncryptedTallyKey:
    def __init__(self, path, password, expected_id):
        key_id(expected_id)
        if not isinstance(password, SecretStr) or not password.get_secret_value(): raise ValueError("Explicit key unlock required")
        self.path, self.password, self.expected_id = Path(path), password, expected_id
    def __call__(self, metadata):
        if metadata["key_id"] != self.expected_id: raise ValueError("Tally key unavailable")
        return serialization.load_pem_private_key(self.path.read_bytes(), password=self.password.get_secret_value().encode())


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--enable-local-tally", action="store_true", required=True)
    for flag in ("verifier", "authority-pin", "snapshot-key", "snapshot-pin", "encrypted-tally-key", "evidence-directory"):
        parser.add_argument("--" + flag, type=Path, required=True)
    parser.add_argument("--snapshot-key-id", required=True)
    parser.add_argument("--tally-key-id", required=True)
    args = parser.parse_args(argv)
    try:
        if not sys.stdin.isatty(): raise ValueError("Interactive Tally activation required")
        settings = verifier(args.verifier)
        key_id(args.tally_key_id); key_id(args.snapshot_key_id)
        store = TallyStore(connection_factory(SecretStr(prompt("Restricted Tally DB password: "))))
        auth = TallyAuthentication(store, settings["operator_id"], settings["username"], b64decode(settings["salt"]), b64decode(settings["digest"], 32))
        snapshot = serialization.load_pem_private_key(args.snapshot_key.read_bytes(), password=prompt("Encrypted snapshot key passphrase: ").encode())
        vault = EvidenceVault(args.evidence_directory, snapshot, args.snapshot_pin.read_bytes(), args.snapshot_key_id)
        unlock = SecretStr(prompt("Encrypted Tally RSA key passphrase: "))
        load_key = EncryptedTallyKey(args.encrypted_tally_key, unlock, args.tally_key_id)
        service = TallyService(auth, store, args.authority_pin.read_bytes(), vault, load_key)
        uvicorn.run(create_tally_app(service), host="127.0.0.1", port=8005, proxy_headers=False,
            forwarded_allow_ips="", access_log=False, log_level="critical", server_header=False)
    except Exception: parser.exit(1, "Restricted Tally configuration or service unavailable\n")


if __name__ == "__main__": main()
