"""ra session lookup volatility hardening

Revision ID: ad688fa2b359
Revises: 90fb90d58296
Create Date: 2026-11-13 02:11:25.126988

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'ad688fa2b359'
down_revision: Union[str, Sequence[str], None] = '90fb90d58296'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("""
        ALTER FUNCTION ra.find_active_session(text)
        VOLATILE
    """)


def downgrade() -> None:
    raise RuntimeError(
        "Automatic rollback of session volatility "
        "hardening is disabled"
    )