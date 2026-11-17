"""Hosted Ubuntu Voting gate: own one tmpfs PostgreSQL, never target user DBs.

Imports do no I/O. Only the explicit CI entrypoint can create a container, roles
or databases. The dependency-verification entrypoint is entirely database-free.
"""

import argparse
import ast
from contextlib import contextmanager
from dataclasses import dataclass
from importlib.metadata import version
import hashlib
import json
import logging
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import time
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
import psycopg
from psycopg import sql
from pydantic import SecretStr
from sqlalchemy import create_engine, event
from sqlalchemy.pool import NullPool

from scripts import voting_disposable_integration as integration


# Same immutable official PostgreSQL 18 image already reviewed for Gate 2 CI.
POSTGRES_IMAGE = "postgres:18-bookworm@sha256:ece55f7868da684e400f82f1030a050718adbdd65c23aa500c486f6e2950dc0f"
HEAD = "d8f27a4c610b"
CHAIN = ("643decaa90ab", "b5bd58a07ceb", HEAD)
NOLOGIN = ("voting_owner", "voting_admin_service", "voting_ballot_service",
           "voting_snapshot_worker", "voting_tally_worker", "voting_publication_service",
           "voting_board_reader", "voting_audit_reader")
LOGINS = ("voting_migrator_login", "voting_ballot_login")
TABLES = ("elections", "candidates", "election_configs", "accepted_ballots", "final_snapshots",
          "tally_jobs", "tally_reports", "publications", "voting_audit_events")
EXPECTED = {"rfc8785": "0.1.4", "psycopg": "3.3.9", "psycopg-binary": "3.3.9",
            "cryptography": "50.0.2", "fastapi": "0.162.4", "alembic": "1.20.1",
            "SQLAlchemy": "2.1.8", "Mako": "1.4.3"}
check = integration.check


class MigrationDiagnostics:
    """Fixed labels only: never log SQL, bound values, messages, DETAIL or CONTEXT."""

    STAGES = {"connect", "marker", "identity", "empty_schema", "alembic", "commit"}
    ROUTINES = {"has_sequence_privilege_name_id", "has_sequence_privilege_id_id",
                "has_sequence_privilege_id", "ExecGrant_Relation", "CheckFunctionValidatorAccess"}

    def __init__(self, scripts):
        self.stage, self.revision, self.statement = "connect", None, "not_started"
        self._labels = {}
        for script in scripts.walk_revisions(base="base", head=HEAD):
            check(script.revision in CHAIN, "Unexpected diagnostic revision")
            tree = ast.parse(Path(script.path).read_text(encoding="utf-8-sig"))
            upgrade = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "upgrade")
            literal = 0
            for node in ast.walk(upgrade):
                if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Name) and node.func.value.id == "op"
                    and node.func.attr == "execute" and node.args
                    and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str)):
                    literal += 1
                    digest = hashlib.sha256(node.args[0].value.encode()).digest()
                    self._labels[digest] = (script.revision, "upgrade_sql_"+str(literal).zfill(2))

    def set_stage(self, stage):
        check(stage in self.STAGES, "Unexpected migration diagnostic stage")
        self.stage, self.statement = stage, "not_started"

    def before_execute(self, connection, clauseelement, multiparams, params, execution_options):
        # TextClause.text is the original Alembic op.execute literal, before
        # driver percent escaping. SQL/parameters are used only for classification.
        text = getattr(clauseelement, "text", None)
        label = self._labels.get(hashlib.sha256(text.encode()).digest()) if isinstance(text, str) else None
        if label is not None:
            self.revision, self.statement = label
        else:
            self.statement = "alembic_internal_or_nonliteral"

    def failure(self, error):
        root = getattr(error, "orig", None) or error
        state = getattr(root, "sqlstate", None)
        state = state if isinstance(state, str) and re.fullmatch(r"[0-9A-Z]{5}", state) else "unavailable"
        parts = ["FAIL: Voting migration", "stage="+self.stage,
                 "revision="+(self.revision or "not_started"), "check="+self.statement, "SQLSTATE="+state]
        diag = getattr(root, "diag", None)
        # Even syntactically valid identifiers can encode secrets. Exact allowlists
        # are required; arbitrary diagnostic strings and object names stay hidden.
        for field, allowed in (("schema_name", {"voting", "pg_catalog"}), ("table_name", set(TABLES)),
                               ("source_function", self.ROUTINES)):
            value = getattr(diag, field, None)
            if value:
                parts.append(field+"="+(value if value in allowed else "redacted"))
        return " ".join(parts)


def verify_dependencies():
    for package, expected in EXPECTED.items():
        check(version(package) == expected, "Voting dependency version mismatch: " + package)
    print("PASS: " + ", ".join(package + "==" + expected for package, expected in EXPECTED.items()))


def require_ci():
    check(sys.platform == "linux" and os.environ.get("GITHUB_ACTIONS") == "true"
          and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
          and os.environ.get("RUNNER_OS") == "Linux", "GitHub-hosted Linux required")
    directory = Path(os.environ.get("RUNNER_TEMP", ""))
    check(directory.is_absolute() and directory.is_dir(), "Runner temp directory required")
    check(not any(name.startswith("PG") for name in os.environ), "Inherited PostgreSQL configuration refused")
    check(not any(name in os.environ for name in ("DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS_VERIFY",
          "DOCKER_CERT_PATH", "DOCKER_CONFIG")), "Inherited Docker endpoint refused")


def docker(*args, input_text=None, timeout=60):
    require_ci()
    result = subprocess.run(["docker", "--host", "unix:///var/run/docker.sock", *args],
                            input=input_text, capture_output=True, text=True, timeout=timeout, check=False)
    check(result.returncode == 0, "Owned ephemeral Docker operation failed")
    return result.stdout.strip()


@dataclass(frozen=True)
class Target:
    database: str
    marker: str
    port: int

    def validate(self):
        integration.designation(self.database, self.marker)
        check(self.database.startswith("voting_demo_test_ci_") and len(self.database) <= 63,
              "Generated Voting CI database required")
        check(type(self.port) is int and 1024 <= self.port <= 65535, "Ephemeral loopback port required")


def owned_container(container_id, name, marker):
    check(re.fullmatch(r"[0-9a-f]{64}", container_id) is not None, "Invalid owned container ID")
    rows = json.loads(docker("inspect", container_id))
    check(len(rows) == 1, "Unexpected container inspection")
    info = rows[0]
    check(info["Id"] == container_id and info["Name"] == "/"+name
          and info["Config"]["Labels"].get("secure-evoting-voting-ci") == marker
          and info["Config"]["Image"] == POSTGRES_IMAGE, "Container ownership or image mismatch")
    bindings = info["HostConfig"]["PortBindings"]
    check(set(bindings) == {"5432/tcp"} and len(bindings["5432/tcp"]) == 1
          and bindings["5432/tcp"][0]["HostIp"] == "127.0.0.1", "Database must be loopback-only")
    check(not info["HostConfig"]["Privileged"] and info["HostConfig"]["NetworkMode"] != "host",
          "Unsafe container mode")
    check(set(info["HostConfig"]["Tmpfs"]) == {"/var/lib/postgresql", "/run/evote-secrets"}
          and all(mount["Type"] == "tmpfs" for mount in info["Mounts"]), "Persistent container mount refused")
    return info


@contextmanager
def ephemeral_postgres():
    require_ci()
    name, marker = "evote-voting-ci-"+uuid4().hex, str(uuid4())
    database = "voting_demo_test_ci_"+uuid4().hex
    bootstrap = SecretStr(secrets.token_urlsafe(48))
    container_id = None
    try:
        docker("pull", POSTGRES_IMAGE, timeout=180)
        # Wait for the secret's atomic rename inside tmpfs; no host file or secret argv/env.
        wait = ("while [ ! -s /run/evote-secrets/bootstrap-password ]; do sleep 0.05; done; "
                "exec /usr/local/bin/docker-entrypoint.sh \"$@\"")
        container_id = docker("run", "--detach", "--name", name,
            "--label", "secure-evoting-voting-ci="+marker, "--publish", "127.0.0.1::5432",
            "--tmpfs", "/var/lib/postgresql:rw,nosuid,nodev,mode=0755",
            "--tmpfs", "/run/evote-secrets:rw,noexec,nosuid,nodev,mode=0755",
            "--env", "POSTGRES_PASSWORD_FILE=/run/evote-secrets/bootstrap-password",
            "--env", "POSTGRES_INITDB_ARGS=--auth-host=scram-sha-256 --auth-local=peer",
            "--entrypoint", "/bin/sh", POSTGRES_IMAGE, "-ec", wait, "voting-ci", "postgres",
            "-c", "password_encryption=scram-sha-256", "-c", "log_statement=none",
            "-c", "log_min_error_statement=panic", "-c", "log_parameter_max_length=0",
            "-c", "log_parameter_max_length_on_error=0", "-c", "max_connections=80")
        info = owned_container(container_id, name, marker)
        ports = info["NetworkSettings"]["Ports"]["5432/tcp"]
        check(len(ports) == 1 and ports[0]["HostIp"] == "127.0.0.1", "Unsafe published address")
        target = Target(database, marker, int(ports[0]["HostPort"]))
        target.validate()
        write = ("umask 077; cat > /run/evote-secrets/bootstrap-password.tmp; "
                 "chown postgres:postgres /run/evote-secrets/bootstrap-password.tmp; "
                 "mv /run/evote-secrets/bootstrap-password.tmp /run/evote-secrets/bootstrap-password")
        docker("exec", "--interactive", container_id, "/bin/sh", "-ec", write,
               input_text=bootstrap.get_secret_value())
        yield target, bootstrap
    finally:
        if container_id is not None:
            owned_container(container_id, name, marker)  # No broad prune or unrelated cleanup.
            docker("rm", "--force", "--volumes", container_id)


def connect(target, login, password, *, maintenance=False, autocommit=False):
    require_ci()
    target.validate()
    check(login in (*LOGINS, "postgres") and (not maintenance or login == "postgres"), "CI login refused")
    conn = psycopg.connect(host="127.0.0.1", port=target.port,
        dbname="postgres" if maintenance else target.database, user=login,
        password=password.get_secret_value(), sslmode="disable", connect_timeout=2, autocommit=autocommit,
        options="-c statement_timeout=20000 -c lock_timeout=10000", application_name="voting-disposable-ci")
    try:
        if not maintenance:
            integration.verify_database(conn, target.database, target.marker)
        return conn
    except BaseException:
        conn.close()
        raise


def bootstrap_database(target, bootstrap, passwords):
    require_ci()
    target.validate()
    check(set(passwords) == set(LOGINS), "Generated CI login credentials required")
    for attempt in range(60):
        try:
            admin = connect(target, "postgres", bootstrap, maintenance=True, autocommit=True)
            break
        except psycopg.OperationalError:
            if attempt == 59:
                raise RuntimeError("Ephemeral PostgreSQL startup failed") from None
            time.sleep(1)
    with admin:
        check(admin.execute("SELECT current_database(),session_user,current_user").fetchone() ==
              ("postgres", "postgres", "postgres"), "Unexpected bootstrap identity")
        check(180000 <= int(admin.execute("SHOW server_version_num").fetchone()[0]) < 190000,
              "PostgreSQL 18 required")
        check(admin.execute("SELECT 1 FROM pg_database WHERE datname NOT IN ('postgres','template0','template1')").fetchone()
              is None, "Nonfresh PostgreSQL instance refused")
        for database in ("postgres", "template0", "template1"):
            admin.execute(sql.SQL("REVOKE ALL ON DATABASE {} FROM PUBLIC").format(sql.Identifier(database)))
        for role in NOLOGIN:
            admin.execute(sql.SQL("CREATE ROLE {} NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS").format(sql.Identifier(role)))
        for role in LOGINS:
            inheritance, limit = ("INHERIT", 40) if role == "voting_ballot_login" else ("NOINHERIT", 4)
            admin.execute(sql.SQL("CREATE ROLE {} LOGIN {} NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT {} PASSWORD {}").format(
                sql.Identifier(role), sql.SQL(inheritance), sql.Literal(limit), sql.Literal(passwords[role].get_secret_value())))
        admin.execute("GRANT voting_owner TO voting_migrator_login WITH INHERIT FALSE, SET TRUE")
        admin.execute("GRANT voting_ballot_service TO voting_ballot_login WITH INHERIT TRUE, SET FALSE")
        admin.execute(sql.SQL("CREATE DATABASE {} OWNER voting_owner TEMPLATE template0").format(sql.Identifier(target.database)))
        admin.execute(sql.SQL("REVOKE ALL ON DATABASE {} FROM PUBLIC").format(sql.Identifier(target.database)))
        admin.execute(sql.SQL("GRANT CONNECT ON DATABASE {} TO voting_migrator_login,voting_ballot_login").format(sql.Identifier(target.database)))
        admin.execute(sql.SQL("COMMENT ON DATABASE {} IS {}").format(
            sql.Identifier(target.database), sql.Literal("secure-evoting-disposable:"+target.marker)))
    with connect(target, "postgres", bootstrap) as setup:
        setup.execute("REVOKE ALL ON SCHEMA public FROM PUBLIC")
        setup.execute("CREATE SCHEMA voting AUTHORIZATION voting_owner")
        check(setup.execute("SELECT count(*) FROM pg_hba_file_rules WHERE error IS NOT NULL OR (type LIKE 'host%' AND auth_method<>'scram-sha-256')").fetchone() == (0,),
              "SCRAM host authentication required")
    try:
        wrong = connect(target, "voting_ballot_login", SecretStr(secrets.token_urlsafe(48)))
    except psycopg.OperationalError as error:
        check(error.sqlstate in (None, "28P01"), "Unexpected authentication probe failure")
    else:
        wrong.close()
        raise AssertionError("Incorrect CI password accepted")


def migrate(target, password):
    require_ci()
    target.validate()
    config = Config()  # No production INI, URL, environment or password discovery.
    config.set_main_option("script_location", str(ROOT / "scripts/ci_voting_migrations"))
    config.set_main_option("version_locations", str(ROOT / "migrations/voting/versions"))
    config.set_main_option("path_separator", "os")
    scripts = ScriptDirectory.from_config(config)
    check(scripts.get_heads() == [HEAD] and tuple(revision.revision for revision in reversed(
        list(scripts.walk_revisions(base="base", head=HEAD)))) == CHAIN, "Unexpected Voting migration chain")
    diagnostics = MigrationDiagnostics(scripts)
    engine = create_engine("postgresql+psycopg://", creator=lambda: connect(target, "voting_migrator_login", password),
                           poolclass=NullPool, echo=False, hide_parameters=True)
    try:
        with engine.begin() as connection:
            diagnostics.set_stage("marker")
            integration.verify_database(connection.connection.driver_connection, target.database, target.marker)
            diagnostics.set_stage("identity")
            check(connection.exec_driver_sql("SELECT current_database(),session_user,current_user,inet_server_port()").one()
                  == (target.database, "voting_migrator_login", "voting_migrator_login", 5432), "Migration identity mismatch")
            diagnostics.set_stage("empty_schema")
            check(connection.exec_driver_sql("SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='voting'").scalar_one() == 0,
                  "Migration schema is not empty")
            config.attributes.update(connection=connection, disposable_database=target.database, disposable_marker=target.marker)
            diagnostics.set_stage("alembic")
            event.listen(connection, "before_execute", diagnostics.before_execute)
            try:
                command.upgrade(config, HEAD)  # Actual migrations; diagnostics never rewrite or skip SQL.
            finally:
                event.remove(connection, "before_execute", diagnostics.before_execute)
            diagnostics.set_stage("commit")
    except Exception as error:
        print(diagnostics.failure(error))
        raise
    finally:
        engine.dispose()
    print("PASS: all three real Voting migrations committed; head " + HEAD)


def snapshot(conn):
    return {table: conn.execute(sql.SQL("SELECT to_jsonb(t)::text FROM voting.{} t ORDER BY 1").format(
        sql.Identifier(table))).fetchall() for table in TABLES}


def run_harness(target, passwords):
    require_ci()
    target.validate()
    fixture = integration.factory(target.database, target.marker, target.port, passwords["voting_migrator_login"], fixture=True)
    with fixture() as conn:
        check(conn.execute("SELECT version_num FROM voting.alembic_version").fetchone() == (HEAD,), "Uncommitted migration head")
        before = snapshot(conn)
        check(all(not rows for rows in before.values()), "Fixture database must be fresh")
    collected = iter(passwords[role] for role in LOGINS)
    integration.main(argv=["--allow-disposable-database", "--database", target.database,
        "--marker", target.marker, "--port", str(target.port)], password_prompt=lambda _: next(collected))
    with fixture() as conn:
        check(snapshot(conn) == before, "Committed Voting fixture cleanup failed")
    print("PASS: real Voting harness and committed fixture cleanup")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--allow-ephemeral-ci-database", action="store_true")
    mode.add_argument("--verify-dependencies", action="store_true")
    args = parser.parse_args()
    verify_dependencies()
    if args.verify_dependencies:
        return
    require_ci()  # Before generating secrets or contacting Docker/PostgreSQL.
    logging.disable(logging.CRITICAL)
    passwords = {role: SecretStr(secrets.token_urlsafe(48)) for role in LOGINS}
    with ephemeral_postgres() as (target, bootstrap):
        bootstrap_database(target, bootstrap, passwords)
        print("PASS: owned tmpfs PostgreSQL 18, SCRAM, named/marked database and least-privilege roles")
        migrate(target, passwords["voting_migrator_login"])
        run_harness(target, passwords)
    print("PASS: Voting PostgreSQL integration and owned-container teardown")


def failure_message(error):
    state = getattr(error, "sqlstate", None) or getattr(getattr(error, "orig", None), "sqlstate", None)
    code = " (SQLSTATE " + state + ")" if isinstance(state, str) and re.fullmatch(r"[0-9A-Z]{5}", state) else ""
    return "FAIL: Voting disposable CI integration"+code+"; sensitive diagnostics withheld"


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        raise SystemExit(failure_message(error)) from None
