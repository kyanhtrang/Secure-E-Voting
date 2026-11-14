"""CI-only Alembic environment; never discovers URLs or prompts for credentials."""
from alembic import context


def run():
    config=context.config
    connection=config.attributes.get("connection")
    guard=config.attributes.get("disposable_connection_guard")
    if context.is_offline_mode() or connection is None or not callable(guard):
        raise RuntimeError("Verified disposable CI connection required")
    # Guard is injected by the trusted ephemeral-container coordinator, verifies
    # hosted CI, database marker, endpoint, login and initially empty RA schema.
    guard(connection)
    connection.exec_driver_sql("SET LOCAL ROLE ra_owner")
    connection.exec_driver_sql("SET LOCAL search_path TO ra, pg_catalog")
    context.configure(connection=connection,target_metadata=None,version_table_schema="ra",
                      include_schemas=True,transactional_ddl=True)
    with context.begin_transaction():
        context.run_migrations()


run()
