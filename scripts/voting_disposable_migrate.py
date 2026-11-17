"""Human-approved test migration runner. Never targets voting_db or ra_db.

Does not provision roles, databases, schemas or markers. Those must be created
independently inside a fresh isolated PostgreSQL instance before invoking this.
"""

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine
from sqlalchemy.pool import NullPool

from scripts.voting_disposable_integration import designation, factory, password


def main():
    parser = argparse.ArgumentParser(description="Explicit marked-disposable Voting migrations")
    parser.add_argument("--allow-disposable-migrations", action="store_true", required=True)
    parser.add_argument("--database", required=True)
    parser.add_argument("--marker", required=True)
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args()
    try:
        designation(args.database, args.marker)
        secret = password("Disposable voting_migrator_login password: ")
        connect = factory(args.database, args.marker, args.port, secret, fixture=True)
        engine = create_engine("postgresql+psycopg://", creator=connect, poolclass=NullPool,
                               echo=False, hide_parameters=True)
        try:
            with engine.begin() as connection:
                config = Config()
                config.set_main_option("script_location", str(ROOT / "scripts/ci_voting_migrations"))
                config.set_main_option("version_locations", str(ROOT / "migrations/voting/versions"))
                config.set_main_option("path_separator", "os")
                config.attributes.update(connection=connection, disposable_database=args.database,
                                         disposable_marker=args.marker)
                command.upgrade(config, "d8f27a4c610b")
        finally:
            engine.dispose()
        print("PASS: marked-disposable Voting migrations committed")
    except Exception:
        parser.exit(1, "FAIL: disposable Voting migration (sensitive details suppressed)\n")


if __name__ == "__main__":
    main()
