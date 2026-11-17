"""Execute the actual CASE expressions against strict type-checking test probes.

SQLite is in-memory only. This checks branch evaluation and retained ACL detection,
not PostgreSQL's planner or catalog functions; real PostgreSQL CI remains required.
"""

import ast
from pathlib import Path
import re
import sqlite3

import pytest


MIGRATION = Path(__file__).resolve().parents[1]/"migrations/voting/versions/d8f27a4c610b_anonymous_ballot_acceptance.py"
KINDS = dict(enumerate(("r", "p", "v", "m", "f", "S", "i", "I", "c", "t"), 1))
TABLE_KINDS = set("rpvmf")
PRIVILEGES = {
    "table": "SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER",
    "column": "SELECT,INSERT,UPDATE,REFERENCES",
    "sequence": "USAGE,SELECT,UPDATE",
}


def expressions():
    tree = ast.parse(MIGRATION.read_text(encoding="utf8"))
    upgrade = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "upgrade")
    preflight = upgrade.body[0].value.args[0].value
    cases = re.findall(r"CASE WHEN c\.relkind.*?ELSE FALSE END", preflight, re.S)
    assert len(cases) == 2, "Both relation domains must be guarded inside CASE"
    assert "CASE WHEN c.relkind IN ('r','p','v','m','f')" in cases[0]
    assert "CASE WHEN c.relkind='S'" in cases[1]
    assert "Existing Voting runtime ACLs require review" in preflight
    return [case.replace("pg_catalog.", "") for case in cases]


def database(granted, calls):
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE pg_class(oid integer,relkind text)")
    conn.executemany("INSERT INTO pg_class VALUES(?,?)", KINDS.items())

    def probe(name, role, oid, privileges):
        allowed = {"S"} if name == "sequence" else TABLE_KINDS
        assert KINDS[oid] in allowed, "Wrong object type reached privilege probe"
        assert role == "restricted_runtime" and privileges == PRIVILEGES[name]
        calls.append((name, oid))
        return name == granted

    for name in PRIVILEGES:
        function = "has_"+("any_column" if name == "column" else name)+"_privilege"
        conn.create_function(function, 3, lambda role, oid, privileges, name=name: probe(name, role, oid, privileges))
    return conn


@pytest.mark.parametrize("granted", [None, "table", "column", "sequence"])
def test_mixed_catalog_types_only_reach_appropriate_privilege_checks(granted):
    table, sequence = expressions()
    calls = []
    conn = database(granted, calls)
    try:
        # Evaluate each extracted expression over EVERY kind, without relying on
        # a WHERE predicate to filter unsafe inputs before the privilege call.
        rows = conn.execute("SELECT c.oid,("+table+") OR ("+sequence+") FROM pg_class c "
                            "CROSS JOIN (SELECT 'restricted_runtime' AS rolname) r").fetchall()
        for oid, denied in rows:
            expected = ((granted in ("table", "column") and KINDS[oid] in TABLE_KINDS)
                        or (granted == "sequence" and KINDS[oid] == "S"))
            assert bool(denied) == expected
        assert {oid for name, oid in calls if name == "table"} == {
            oid for oid, kind in KINDS.items() if kind in TABLE_KINDS}
        assert {oid for name, oid in calls if name == "sequence"} == {
            oid for oid, kind in KINDS.items() if kind == "S"}
        assert not any(KINDS[oid] in set("iIct") for _, oid in calls)
        if granted == "column":
            assert any(name == "column" for name, _ in calls)
    finally:
        conn.close()


def test_negative_control_probe_rejects_nonsequence_without_case():
    conn = database(None, [])
    try:
        with pytest.raises(sqlite3.OperationalError, match="user-defined function raised exception"):
            conn.execute("SELECT has_sequence_privilege('restricted_runtime',1,'USAGE,SELECT,UPDATE')").fetchall()
    finally:
        conn.close()
