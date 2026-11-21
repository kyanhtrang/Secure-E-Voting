"""Explicit loopback-only Board/publication composition. Never imported by main."""
import argparse
from pathlib import Path
import sys

import psycopg
from pydantic import SecretStr
import uvicorn
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from backend.admin.launcher import prompt
from backend.crypto.credential_protocol import b64decode, strict_json
from backend.board.http import create_board_app, create_publication_app
from backend.board.service import Board, Publisher, Store
from backend.board.verification import BoardError, Trust


def load_trust(path):
    try:
        with Path(path).open("rb") as stream: raw=stream.read(8193)
        if len(raw)>8192: raise ValueError()
        value=strict_json(raw)
        if set(value)!={"authority","evidence","evidence_key_id","publication","publication_key_id"}: raise ValueError()
        trust=Trust(b64decode(value["authority"],32),b64decode(value["evidence"],32),value["evidence_key_id"],
            b64decode(value["publication"],32),value["publication_key_id"])
        trust.validate();return trust
    except Exception: raise BoardError(503,"UNVERIFIED") from None


class EncryptedPublicationSigner:
    def __init__(self,path,password,pin):self.path,self.password,self.pin=Path(path),password,pin
    def __call__(self,data):
        if not isinstance(self.password,SecretStr) or not self.password.get_secret_value() or self.path.is_symlink(): raise BoardError()
        with self.path.open("rb") as stream: raw=stream.read(16385)
        if len(raw)>16384 or not raw.startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----"): raise BoardError()
        private=serialization.load_pem_private_key(raw,password=self.password.get_secret_value().encode())
        if not isinstance(private,Ed25519PrivateKey) or private.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)!=self.pin:
            raise BoardError(503,"UNVERIFIED")
        return private.sign(data)


def connections(role,password):
    if role not in {"board","publisher"} or not isinstance(password,SecretStr) or not password.get_secret_value(): raise ValueError("Explicit restricted identity required")
    login="voting_board_login" if role=="board" else "voting_publication_login"
    def connect():
        conn=psycopg.connect(host="127.0.0.1",port=5432,dbname="voting_db",user=login,password=password.get_secret_value(),
            connect_timeout=5,options="-c statement_timeout=15000 -c lock_timeout=3000")
        try:
            if role=="board":conn.execute("SET TRANSACTION READ ONLY")
            identity=conn.execute("""SELECT current_database(),session_user,current_user,pg_get_userbyid(d.datdba),
                r.rolsuper OR r.rolinherit OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls,
                EXISTS(SELECT 1 FROM pg_auth_members WHERE member=r.oid OR roleid=r.oid)
                FROM pg_database d CROSS JOIN pg_roles r WHERE d.datname=current_database() AND r.rolname=current_user""").fetchone()
            if identity!=("voting_db",login,login,"voting_owner",False,False):raise ValueError("Unsafe runtime identity")
            funcs=conn.execute("""SELECT n.nspname,p.proname FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
                WHERE n.nspname IN ('voting','voting_admin','voting_tally','voting_board') AND has_function_privilege(current_user,p.oid,'EXECUTE')""").fetchall()
            allowed={"read_public","catalogue"} if role=="board" else {"publication_input","finish"}
            if set(funcs)!={("voting_board",name) for name in allowed}:raise ValueError("Unsafe runtime EXECUTE")
            if conn.execute("""SELECT EXISTS(SELECT 1 FROM pg_namespace n WHERE n.nspname IN ('public','voting','voting_admin','voting_tally','voting_board') AND has_schema_privilege(current_user,n.oid,'CREATE'))
                OR EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname IN ('voting','voting_admin','voting_tally','voting_board')
                AND CASE WHEN c.relkind IN ('r','p','v','m','f') THEN has_table_privilege(current_user,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
                OR has_any_column_privilege(current_user,c.oid,'SELECT,INSERT,UPDATE,REFERENCES') WHEN c.relkind='S' THEN has_sequence_privilege(current_user,c.oid,'USAGE,SELECT,UPDATE') ELSE false END)""").fetchone()!=(False,):raise ValueError("Unsafe runtime table access")
            return conn
        except BaseException:conn.close();raise
    return connect


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--enable-local-demo",action="store_true",required=True)
    parser.add_argument("--role",choices=("board","publisher"),required=True)
    parser.add_argument("--trust-config",type=Path,required=True)
    parser.add_argument("--evidence-directory",type=Path)
    parser.add_argument("--encrypted-publication-key",type=Path)
    args=parser.parse_args(argv)
    try:
        if not sys.stdin.isatty():raise ValueError()
        trust=load_trust(args.trust_config)
        if args.role=="board" and (args.evidence_directory or args.encrypted_publication_key):raise ValueError()
        if args.role=="publisher" and (args.evidence_directory is None or args.encrypted_publication_key is None):raise ValueError()
        store=Store(connections(args.role,SecretStr(prompt("Restricted Board/publication database password: "))))
        if args.role=="publisher":
            signer=EncryptedPublicationSigner(args.encrypted_publication_key,SecretStr(prompt("Encrypted publication signing key passphrase: ")),trust.publication)
            app=create_publication_app(Publisher(store,trust,signer,args.evidence_directory))
        else:app=create_board_app(Board(store,trust))
        uvicorn.run(app,host="127.0.0.1",port=8006 if args.role=="board" else 8007,proxy_headers=False,
            forwarded_allow_ips="",access_log=False,server_header=False,log_level="critical")
    except Exception:parser.exit(2,"Explicit publication configuration unavailable\n")


if __name__=="__main__":main()
