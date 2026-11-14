"""Hosted-Linux-only PostgreSQL gate. No operator credentials or target arguments.

Own a new, digest-pinned container and random loopback port, provision only a
new named/marked test database, then run the existing real integration harness.
Never import this module to launch work: all IO is behind explicit entrypoints.
"""
import argparse
from contextlib import contextmanager
from dataclasses import dataclass
import json
import logging
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import tempfile
import time
from uuid import uuid4

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))

import psycopg
from psycopg import sql
from pydantic import SecretStr
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine
from sqlalchemy.pool import NullPool

from scripts import ra_credential_disposable_integration as integration
from scripts.ra_demo_db_test_support import check,validate_disposable_designation,verify_disposable_database

ROOT=Path(__file__).resolve().parents[1]
# Official library/postgres OCI index resolved from Docker Registry on 2026-11-15.
POSTGRES_IMAGE="postgres:18-bookworm@sha256:ece55f7868da684e400f82f1030a050718adbdd65c23aa500c486f6e2950dc0f"
HEAD="c84e13b9702d"
TABLES=("voters","voter_eligibility","blind_issuances","ra_signing_keys","ra_audit_events",
        "ra_sessions","credential_policies","credential_reservations")
LOGINS=("ra_migrator_login","ra_auth_login","ra_issuance_login","ra_service_login")
NOLOGIN=("ra_owner","ra_service","ra_recovery_worker","ra_audit_reader")


def require_ci():
    check(sys.platform=="linux" and os.environ.get("GITHUB_ACTIONS")=="true"
          and os.environ.get("RUNNER_ENVIRONMENT")=="github-hosted"
          and os.environ.get("RUNNER_OS")=="Linux","GitHub-hosted Linux required")
    directory=Path(os.environ.get("RUNNER_TEMP",""))
    check(directory.is_absolute() and directory.is_dir(),"Private runner temp directory required")
    check(not any(name.startswith("PG") for name in os.environ),"Inherited PostgreSQL configuration refused")
    check(not any(name in os.environ for name in ("DOCKER_HOST","DOCKER_CONTEXT","DOCKER_TLS_VERIFY",
              "DOCKER_CERT_PATH","DOCKER_CONFIG")),"Inherited Docker endpoint/configuration refused")
    return directory.resolve()


def docker(*args,timeout=60):
    require_ci()
    result=subprocess.run(["docker","--host","unix:///var/run/docker.sock",*args],
                          capture_output=True,text=True,timeout=timeout,check=False)
    check(result.returncode==0,"Ephemeral Docker operation failed")
    return result.stdout.strip()


@dataclass(frozen=True)
class Target:
    database:str
    marker:str
    port:int

    def validate(self):
        validate_disposable_designation(self.database,self.marker)
        check(self.database.startswith("ra_demo_test_ci_") and len(self.database)<=63,"CI database name required")
        check(isinstance(self.port,int) and 1024<=self.port<=65535,"Ephemeral loopback port required")


def container_port(container_id,name,marker):
    check(bool(re.fullmatch(r"[0-9a-f]{64}",container_id)),"Invalid owned container ID")
    rows=json.loads(docker("inspect",container_id))
    check(len(rows)==1,"Unexpected container inspection")
    info=rows[0]
    check(info["Id"]==container_id and info["Name"]=="/"+name
          and info["Config"]["Labels"].get("secure-evoting-gate2")==marker
          and info["Config"]["Image"]==POSTGRES_IMAGE,"Container ownership or image mismatch")
    bindings=info["HostConfig"]["PortBindings"]
    check(set(bindings)=={"5432/tcp"},"Unexpected published ports")
    exposed=info["NetworkSettings"]["Ports"]["5432/tcp"]
    check(len(exposed)==1 and exposed[0]["HostIp"]=="127.0.0.1","Database is not loopback-only")
    return int(exposed[0]["HostPort"])


@contextmanager
def ephemeral_postgres():
    directory=require_ci()
    marker=str(uuid4())
    database="ra_demo_test_ci_"+uuid4().hex
    name="evote-gate2-"+uuid4().hex
    bootstrap=SecretStr(secrets.token_urlsafe(48))
    with tempfile.TemporaryDirectory(prefix="evote-gate2-ci-",dir=directory) as scratch:
        check(Path(scratch).resolve().is_relative_to(directory),"Unsafe private temp target")
        password_file=Path(scratch)/"bootstrap-password"
        with open(password_file,"x",opener=lambda path,flags:os.open(path,flags,0o600)) as stream:
            stream.write(bootstrap.get_secret_value())
        container_id=None
        try:
            docker("pull",POSTGRES_IMAGE,timeout=180)
            container_id=docker("run","--detach","--name",name,"--label","secure-evoting-gate2="+marker,
                "--publish","127.0.0.1::5432","--mount",
                "type=bind,src="+str(password_file)+",dst=/run/secrets/bootstrap-password,readonly",
                "--env","POSTGRES_PASSWORD_FILE=/run/secrets/bootstrap-password",
                "--env","POSTGRES_INITDB_ARGS=--auth-host=scram-sha-256 --auth-local=peer",
                POSTGRES_IMAGE,"-c","password_encryption=scram-sha-256","-c","log_statement=none",
                "-c","log_min_error_statement=panic","-c","log_parameter_max_length=0",
                "-c","log_parameter_max_length_on_error=0")
            port=container_port(container_id,name,marker)
            target=Target(database,marker,port)
            target.validate()
            yield target,bootstrap
        finally:
            # Only the exact container we created, after checking name/label/image
            # and loopback binding again. No broad prune or database drop command.
            if container_id is not None:
                container_port(container_id,name,marker)
                docker("rm","--force","--volumes",container_id)


def connect(target,login,password,*,database=None,autocommit=False):
    target.validate()
    check(login in (*LOGINS,"postgres"),"Unrecognized CI login")
    selected=database or target.database
    check(selected==target.database or (login=="postgres" and selected=="postgres"),"Unrecognized CI database")
    return psycopg.connect(host="127.0.0.1",port=target.port,dbname=selected,user=login,
        password=password.get_secret_value(),connect_timeout=2,sslmode="disable",autocommit=autocommit,
        options="-c statement_timeout=5000 -c lock_timeout=2000",application_name="gate2-disposable-ci")


def bootstrap_database(target,bootstrap,passwords):
    require_ci()
    target.validate()
    check(set(passwords)==set(LOGINS),"Missing generated CI login credentials")
    for attempt in range(60):
        try:
            admin=connect(target,"postgres",bootstrap,database="postgres",autocommit=True)
            break
        except psycopg.OperationalError:
            if attempt==59:
                raise RuntimeError("Ephemeral PostgreSQL startup failed") from None
            time.sleep(1)
    with admin:
        check(admin.execute("SELECT current_database(),session_user,current_user").fetchone()==
              ("postgres","postgres","postgres"),"Unexpected bootstrap identity")
        check(180000<=int(admin.execute("SHOW server_version_num").fetchone()[0])<190000,
              "PostgreSQL 18 required")
        check(admin.execute("SELECT 1 FROM pg_database WHERE datname='ra_db'").fetchone() is None,
              "Nonfresh PostgreSQL instance refused")
        for database in ("postgres","template0","template1"):
            admin.execute(sql.SQL("REVOKE ALL ON DATABASE {} FROM PUBLIC").format(sql.Identifier(database)))
        for role in NOLOGIN:
            admin.execute(sql.SQL("CREATE ROLE {} NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS").format(sql.Identifier(role)))
        for role in LOGINS:
            # SQL DDL requires a quoted literal, not a bind placeholder. Neither
            # this SQL nor database error statements are logged/printed.
            admin.execute(sql.SQL("CREATE ROLE {} LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 10 PASSWORD {}").format(
                sql.Identifier(role),sql.Literal(passwords[role].get_secret_value())))
        admin.execute("GRANT ra_owner TO ra_migrator_login WITH INHERIT FALSE, SET TRUE")
        admin.execute(sql.SQL("CREATE DATABASE {} OWNER ra_owner TEMPLATE template0").format(sql.Identifier(target.database)))
        admin.execute(sql.SQL("REVOKE ALL ON DATABASE {} FROM PUBLIC").format(sql.Identifier(target.database)))
        admin.execute(sql.SQL("GRANT CONNECT ON DATABASE {} TO ra_migrator_login,ra_auth_login,ra_issuance_login").format(sql.Identifier(target.database)))
        admin.execute(sql.SQL("COMMENT ON DATABASE {} IS {}").format(
            sql.Identifier(target.database),sql.Literal("secure-evoting-disposable:"+target.marker)))
    with connect(target,"postgres",bootstrap) as admin:
        verify_disposable_database(admin,target.database,target.marker)
        admin.execute("REVOKE ALL ON SCHEMA public FROM PUBLIC")
        admin.execute("CREATE SCHEMA ra AUTHORIZATION ra_owner")
        check(admin.execute("SELECT count(*) FROM pg_hba_file_rules WHERE error IS NOT NULL OR (type LIKE 'host%' AND auth_method<>'scram-sha-256')").fetchone()==(0,),
              "Host password authentication is not exclusively SCRAM")
    # Catch any accidental trust authentication before migrations or harness IO.
    try:
        wrong=connect(target,"ra_issuance_login",SecretStr(secrets.token_urlsafe(48)))
    except psycopg.OperationalError as error:
        check(error.sqlstate in (None,"28P01"),"Unexpected authentication probe failure")
    else:
        wrong.close()
        raise AssertionError("Incorrect CI password was accepted")
    with connect(target,"ra_issuance_login",passwords["ra_issuance_login"]) as runtime:
        check(runtime.execute("SELECT current_database(),session_user,current_user").fetchone()==
              (target.database,"ra_issuance_login","ra_issuance_login"),"Restricted login unavailable")
        verify_disposable_database(runtime,target.database,target.marker)


def migrate(target,password):
    require_ci()
    target.validate()
    config=Config()  # Never load the production ra_db environment or a secret URL.
    config.set_main_option("script_location",str(ROOT/"scripts/ci_ra_migrations"))
    config.set_main_option("version_locations",str(ROOT/"migrations/ra/versions"))
    config.set_main_option("path_separator","os")
    scripts=ScriptDirectory.from_config(config)
    check(scripts.get_heads()==[HEAD],"Unexpected RA migration heads")
    revisions=list(reversed(list(scripts.walk_revisions(base="base",head=HEAD))))
    check(len(revisions)==14 and revisions[0].revision=="e52b0a9227ef"
          and revisions[-2].revision=="7b2d91a6c840","Unexpected RA migration chain")
    engine=create_engine("postgresql+psycopg://",creator=lambda:connect(target,"ra_migrator_login",password),
                         poolclass=NullPool,echo=False,hide_parameters=True)

    def guard(connection):
        require_ci()
        check(connection.exec_driver_sql("SELECT current_database(),session_user,current_user,inet_server_port()").one()==
              (target.database,"ra_migrator_login","ra_migrator_login",5432),"Migration connection identity mismatch")
        # psycopg is the supplied SQLAlchemy connection's driver, not another URL.
        verify_disposable_database(connection.connection.driver_connection,target.database,target.marker)
        check(connection.exec_driver_sql("SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='ra'").scalar_one()==0,
              "Migration target is not empty")

    try:
        with engine.begin() as connection:
            config.attributes["connection"]=connection
            config.attributes["disposable_connection_guard"]=guard
            command.upgrade(config,HEAD)  # Actual reviewed revisions in Alembic order; no stamping.
    finally:
        engine.dispose()
    print("PASS: all 14 RA migrations committed; head c84e13b9702d (includes 7b2d91a6c840)")


def snapshot(conn):
    # All rows belong to this fresh CI database. Values stay in memory, never logs.
    return {table:conn.execute(sql.SQL("SELECT to_jsonb(t)::text FROM ra.{} t ORDER BY 1").format(
        sql.Identifier(table))).fetchall() for table in TABLES}


def run_harness(target,passwords,signer,node):
    require_ci()
    target.validate()
    fixture=integration.database_factory(passwords["ra_migrator_login"],database=target.database,
        port=target.port,fixture=True,disposable_marker=target.marker)
    sentinel=uuid4()
    with fixture() as conn:
        check(conn.execute("SELECT version_num FROM ra.alembic_version").fetchone()==(HEAD,),"Migration head not committed")
        check(all(not rows for rows in snapshot(conn).values()),"Fixture database is not fresh")
        conn.execute("INSERT INTO ra.voters(voter_id,auth_provider,auth_subject,is_active) VALUES(%s,%s,%s,true)",
                     (sentinel,"gate2-ci-sentinel",str(sentinel)))
        conn.execute("""WITH t AS (SELECT clock_timestamp() AS now)
            SELECT ra.create_session(%s,%s,t.now,t.now+interval '15 minutes') FROM t""",
            (integration.DemoSessionService._digest(secrets.token_urlsafe(32)),sentinel))
        before=snapshot(conn)
    collected=iter((passwords["ra_issuance_login"],passwords["ra_migrator_login"]))
    integration.main(argv=["--disposable-fixture-writes","--database",target.database,
        "--disposable-marker",target.marker,"--port",str(target.port),
        "--signer-binary",str(signer),"--node",str(node)],password_prompt=lambda _:next(collected))
    with fixture() as conn:
        check(snapshot(conn)==before,"Committed fixture cleanup or unrelated sentinel preservation failed")
        check(conn.execute("SELECT 1 FROM pg_database WHERE datname='ra_db'").fetchone() is None,
              "Unexpected ra_db creation")
    print("PASS: committed fixture cleanup and unrelated voter/session preservation")


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--allow-ephemeral-ci-database",action="store_true",required=True)
    parser.add_argument("--signer-binary",type=Path,required=True)
    parser.add_argument("--node",type=Path,required=True)
    args=parser.parse_args()
    require_ci()
    check(args.signer_binary.is_file() and args.node.is_file(),"Built test tools required")
    logging.disable(logging.CRITICAL)
    passwords={role:SecretStr(secrets.token_urlsafe(48)) for role in LOGINS}
    with ephemeral_postgres() as (target,bootstrap):
        bootstrap_database(target,bootstrap,passwords)
        print("PASS: isolated PostgreSQL 18, named/marked database, restricted roles and SCRAM")
        migrate(target,passwords["ra_migrator_login"])
        run_harness(target,passwords,args.signer_binary,args.node)
    print("PASS: Gate 2 disposable PostgreSQL integration and owned-container teardown")


def failure_message(error):
    state=getattr(error,"sqlstate",None) or getattr(getattr(error,"orig",None),"sqlstate",None)
    code=" (SQLSTATE "+state+")" if isinstance(state,str) and re.fullmatch(r"[0-9A-Z]{5}",state) else ""
    return "FAIL: Gate 2 disposable CI integration"+code+"; sensitive diagnostics withheld"


if __name__=="__main__":
    try:
        main()
    except Exception as error:
        raise SystemExit(failure_message(error)) from None
