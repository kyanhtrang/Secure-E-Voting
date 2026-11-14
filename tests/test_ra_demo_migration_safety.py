"""Inspect the unapplied revision without importing/running Alembic."""

import ast
from pathlib import Path


MIGRATION = Path(__file__).resolve().parents[1] / "migrations/ra/versions/f3c2a1d4e6b8_ra_demo_auth_e2e.py"


def sql_statements():
    tree = ast.parse(MIGRATION.read_text(encoding="utf-8"))
    upgrade = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "upgrade")
    return [node.value.args[0].value for node in upgrade.body
            if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call)
            and isinstance(node.value.args[0], ast.Constant)]


def test_role_preflight_precedes_role_switch_and_object_creation():
    statements = sql_statements()
    preflight = statements[0]
    assert "Required RA roles missing" in preflight
    for role in ("ra_owner", "ra_auth_login", "ra_service", "ra_service_login",
                 "ra_recovery_worker", "ra_audit_reader"):
        assert f"('{role}')" in preflight
    assert "pg_catalog.pg_roles" in preflight
    assert "pg_catalog.pg_auth_members" in preflight
    assert statements[1] == "SET LOCAL ROLE ra_owner"
    assert all("CREATE FUNCTION" not in statement for statement in statements[:3])


def test_effective_acl_guard_and_unexpected_default_grants_fail_closed():
    statements = sql_statements()
    before_creation = statements[2]
    for privilege in ("has_schema_privilege", "has_function_privilege", "has_table_privilege",
                      "has_sequence_privilege"):
        assert privilege in before_creation
    assert "RA authorization boundary is unsafe" in before_creation
    assert "aclexplode" in statements[-1]
    assert "Unexpected default grants on demo functions" in statements[-1]
    source = MIGRATION.read_text(encoding="utf-8")
    assert "FROM PUBLIC, ra_auth_login, ra_service, ra_service_login" in source
    assert "GRANT EXECUTE ON FUNCTION {signature} TO ra_auth_login" in source
    assert "GRANT USAGE ON SCHEMA ra " not in source
    assert "CREATE ROLE" not in source
    assert "ALTER ROLE" not in source
