"""ra least privilege acl

Revision ID: 00e554fb031a
Revises: e52b0a9227ef
Create Date: 2026-11-13 00:10:36.868884

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '00e554fb031a'
down_revision: Union[str, Sequence[str], None] = 'e52b0a9227ef'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Apply fail-closed RA runtime permissions."""

    op.execute("""
        REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA ra
        FROM PUBLIC, ra_service, ra_recovery_worker, ra_audit_reader
    """)

    op.execute("""
        REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA ra
        FROM PUBLIC, ra_service, ra_recovery_worker, ra_audit_reader
    """)

    op.execute("""
        REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA ra
        FROM PUBLIC, ra_service, ra_recovery_worker, ra_audit_reader
    """)

    op.execute("""
        ALTER DEFAULT PRIVILEGES FOR ROLE ra_owner
        REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC
    """)

    op.execute("""
        GRANT SELECT ON TABLE ra.ra_audit_events
        TO ra_audit_reader
    """)


def downgrade() -> None:
    """Security hardening requires an explicitly reviewed rollback."""
    raise RuntimeError(
        "Automatic rollback of RA access controls is disabled"
    )