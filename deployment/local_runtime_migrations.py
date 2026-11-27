"""Separately authorized setup capability; never included in a runtime package."""
from pathlib import Path

from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine
from sqlalchemy.pool import NullPool

from deployment.local_demo_policy import ROOT, database_spec, fingerprint, require
from deployment.local_runtime_database import IDENTITY_SQL


def setup_identity(conn, plan, kind):
    spec = database_spec(plan,kind)
    login = kind+'_migrator_login'
    row = conn.execute(IDENTITY_SQL).fetchone()
    require(row[:5] == (spec['name'],login,login,spec['owner'],spec['marker'])
        and type(row[5]) is int and 180000 <= row[5] < 190000, 'IDENTITY')


def migrate(plan, approval, kind, setup_connection, *, boundary, confirmation):
    approval.check(plan)
    require(confirmation == 'MIGRATE OWNED DEMO '+fingerprint(plan), 'APPROVAL_REQUIRED')
    spec = database_spec(plan,kind)
    boundary()
    def creator():
        boundary()
        conn = setup_connection()
        try: setup_identity(conn,plan,kind); conn.commit(); return conn
        except BaseException: conn.close(); raise
    config = Config()
    config.set_main_option('script_location',str(Path(__file__).parent/'local_migrations'))
    folders = ('ra','admin_ra') if kind == 'ra' else ('voting','admin_voting','tally','board')
    config.set_main_option('version_locations',' '.join(str(ROOT/'migrations'/folder/'versions') for folder in folders))
    config.set_main_option('path_separator','space')
    head = plan['migration_heads'][kind]
    require(ScriptDirectory.from_config(config).get_heads() == [head], 'SOURCE')
    engine = create_engine('postgresql+psycopg://',creator=creator,poolclass=NullPool,echo=False,hide_parameters=True)
    try:
        with engine.begin() as connection:
            config.attributes.update(connection=connection,owner=spec['owner'],schema=kind,database=spec['name'])
            command.upgrade(config,head)
    finally: engine.dispose()
