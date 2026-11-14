"""Alembic environment for RA Database."""

from getpass import getpass

from alembic import context
from sqlalchemy import URL, create_engine
from sqlalchemy.pool import NullPool


DATABASE = "ra_db"
SCHEMA = "ra"
LOGIN = "ra_migrator_login"
OWNER = "ra_owner"

target_metadata = None


def run_migrations_offline():
    raise RuntimeError(
        "Offline migrations are disabled. "
        "Use an authenticated PostgreSQL connection."
    )


def run_migrations_online():
    password = getpass(
        "PostgreSQL password for ra_migrator_login: "
    )

    url = URL.create(
        drivername="postgresql+psycopg",
        username=LOGIN,
        password=password,
        host="127.0.0.1",
        port=5432,
        database=DATABASE,
    )

    engine = create_engine(
        url,
        poolclass=NullPool,
    )

    try:
        with engine.connect() as connection:
            with connection.begin():

                connection.exec_driver_sql(
                    "SET LOCAL ROLE ra_owner"
                )

                connection.exec_driver_sql(
                    "SET LOCAL search_path TO ra, pg_catalog"
                )

                identity = connection.exec_driver_sql(
                    "SELECT current_database(), "
                    "session_user, current_user, "
                    "current_schema()"
                ).one()

                expected = (
                    DATABASE,
                    LOGIN,
                    OWNER,
                    SCHEMA,
                )

                if tuple(identity) != expected:
                    raise RuntimeError(
                        f"Unexpected database identity: {identity}"
                    )

                print(
                    f"Connected: database={identity[0]}, "
                    f"login={identity[1]}, "
                    f"role={identity[2]}, "
                    f"schema={identity[3]}"
                )

                context.configure(
                    connection=connection,
                    target_metadata=target_metadata,
                    version_table_schema=SCHEMA,
                    include_schemas=True,
                    transactional_ddl=True,
                )

                with context.begin_transaction():
                    context.run_migrations()

    finally:
        engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()