"""Injected, verified connection ONLY; no URL or offline migration execution."""
from alembic import context

from deployment.local_demo_policy import require

config = context.config
require(not context.is_offline_mode() and set(config.attributes) == {'connection','owner','schema','database'}, 'CONFIG')
connection = config.attributes['connection']
kind = config.attributes['schema']
require(kind in {'ra','voting'} and config.attributes['owner'] == kind+'_owner', 'ROLE')
connection.exec_driver_sql('SET LOCAL ROLE '+kind+'_owner')
# The reviewed baseline contains unqualified CREATE TABLE. Its trusted schema
# must be the creation target, exactly as in the existing guarded CI envs. This
# setup-only path is distinct from fixed pg_catalog-first SECURITY DEFINER paths.
connection.exec_driver_sql('SET LOCAL search_path TO '+kind+',pg_catalog')
require(connection.exec_driver_sql('SELECT current_database(),session_user,current_user,current_schema()').one() ==
    (config.attributes['database'],kind+'_migrator_login',kind+'_owner',kind), 'IDENTITY')
context.configure(connection=connection,version_table='alembic_version',version_table_schema=kind,transaction_per_migration=False)
with context.begin_transaction(): context.run_migrations()
