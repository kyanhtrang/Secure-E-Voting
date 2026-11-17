"""Offline migration contracts, not a substitute for PostgreSQL execution."""

import ast
import importlib.util
from pathlib import Path

from alembic.config import Config
from alembic.script import ScriptDirectory


ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / "migrations/voting/versions/d8f27a4c610b_anonymous_ballot_acceptance.py"


def migration_sql(monkeypatch):
    spec = importlib.util.spec_from_file_location("voting_test_migration", PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    statements = []
    monkeypatch.setattr(module.op, "execute", statements.append)
    module.upgrade()  # Capture SQL only; no Alembic connection or PostgreSQL.
    return "\n".join(statements)


def test_actual_parent_chain_and_no_duplicate_ballot_tables():
    config = Config()
    config.set_main_option("script_location", str(ROOT / "migrations/voting"))
    directory = ScriptDirectory.from_config(config)
    assert directory.get_heads() == ["d8f27a4c610b"]
    chain = list(reversed(list(directory.walk_revisions())))
    assert [revision.revision for revision in chain] == ["643decaa90ab", "b5bd58a07ceb", "d8f27a4c610b"]
    baseline = Path(chain[0].path).read_text()
    source = PATH.read_text()
    ast.parse(source)
    assert "UNIQUE (election_id, serial)" in baseline
    assert "CREATE TABLE" not in source
    assert "CREATE ROLE" not in source and "ALTER ROLE" not in source
    assert "ra." not in source


def test_generated_sql_has_no_nul_and_reuses_exact_receipt_domain(monkeypatch):
    sql = migration_sql(monkeypatch)
    assert "\x00" not in sql
    assert "'EVOTE-RECEIPT-v1'" in sql and "pg_catalog.decode('00','hex')" in sql
    assert "E'\\n'" in sql  # PostgreSQL's base64 wrapping is stripped before hashing.
    assert '"election_id"' in sql and '"envelope_hash"' in sql and '"prepared_msg"' in sql


def test_definers_have_fixed_path_minimum_execute_and_explicit_owner(monkeypatch):
    sql = migration_sql(monkeypatch)
    assert sql.count("SECURITY DEFINER SET search_path=pg_catalog,voting,pg_temp") == 5
    assert sql.count("OWNER TO voting_owner") == 5
    assert sql.count("FROM PUBLIC, voting_admin_service") == 5
    assert sql.count("GRANT EXECUTE ON FUNCTION") == 3
    assert "GRANT SELECT" not in sql and "GRANT INSERT" not in sql
    assert "pg_catalog.aclexplode" in sql and "Unexpected Voting runtime memberships" in sql
    assert "Required Voting roles absent" in sql and "Existing Voting runtime ACLs require review" in sql


def test_lock_deadline_and_configuration_contract_match_baseline(monkeypatch):
    sql = migration_sql(monkeypatch)
    function = sql.split("CREATE FUNCTION voting.accept_anonymous_ballot(")[1].split("END $f$;")[0]
    assert function.index("FROM voting.elections") < function.index("FROM voting.election_configs") < function.index("FROM voting.accepted_ballots")
    assert function.index("FOR UPDATE") < function.index("decision := pg_catalog.clock_timestamp()")
    assert "decision>=e.closes_at" in function and "decision<e.opens_at" in function
    assert "e.election_config_digest IS DISTINCT FROM p_config" in function
    assert "pg_catalog.sha256(c.config_bytes) IS DISTINCT FROM p_config" in function
    assert "ON CONFLICT" not in function  # No duplicate insert can return a new success.
    assert "pg_catalog.gen_random_uuid()" in function
    assert "accepted_at" not in function  # Existing DB-controlled default remains authoritative.
    for column in ("ballot_id", "election_id", "serial", "envelope", "prepared_msg", "signature", "envelope_hash", "receipt_hash"):
        assert column in function
