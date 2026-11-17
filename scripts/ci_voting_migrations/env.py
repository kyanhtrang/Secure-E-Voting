"""Explicit marked-disposable migration environment; no fallback connection."""

from alembic import context

from scripts.voting_disposable_integration import verify_database

config = context.config
connection = config.attributes.get("connection")
database = config.attributes.get("disposable_database")
marker = config.attributes.get("disposable_marker")
if context.is_offline_mode() or connection is None:
    raise RuntimeError("Explicit disposable fixture connection required")

# Use the raw psycopg connection to repeat the independent safety check.
verify_database(connection.connection.driver_connection, database, marker)
connection.exec_driver_sql("SET LOCAL ROLE voting_owner")
connection.exec_driver_sql("SET LOCAL search_path TO voting,pg_catalog")
if connection.exec_driver_sql("SELECT current_database(),session_user,current_user,current_schema()").one() != (
    database, "voting_migrator_login", "voting_owner", "voting"
):
    raise RuntimeError("Unexpected disposable migration identity")
context.configure(connection=connection, version_table_schema="voting", transactional_ddl=True)
with context.begin_transaction():
    context.run_migrations()
