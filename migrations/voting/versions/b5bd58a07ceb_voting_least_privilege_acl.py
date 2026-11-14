"""voting least privilege acl

Revision ID: b5bd58a07ceb
Revises: 643decaa90ab
Create Date: 2026-11-13 00:20:22.288280

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b5bd58a07ceb'
down_revision: Union[str, Sequence[str], None] = '643decaa90ab'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Apply fail-closed Voting runtime permissions."""

    op.execute("""
        REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA voting
        FROM PUBLIC,
             voting_admin_service,
             voting_ballot_service,
             voting_snapshot_worker,
             voting_tally_worker,
             voting_publication_service,
             voting_board_reader,
             voting_audit_reader
    """)

    op.execute("""
        REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA voting
        FROM PUBLIC,
             voting_admin_service,
             voting_ballot_service,
             voting_snapshot_worker,
             voting_tally_worker,
             voting_publication_service,
             voting_board_reader,
             voting_audit_reader
    """)

    op.execute("""
        REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA voting
        FROM PUBLIC,
             voting_admin_service,
             voting_ballot_service,
             voting_snapshot_worker,
             voting_tally_worker,
             voting_publication_service,
             voting_board_reader,
             voting_audit_reader
    """)

    op.execute("""
        ALTER DEFAULT PRIVILEGES FOR ROLE voting_owner
        REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC
    """)


def downgrade() -> None:
    """Security hardening requires an explicitly reviewed rollback."""
    raise RuntimeError(
        "Automatic rollback of Voting access controls is disabled"
    )