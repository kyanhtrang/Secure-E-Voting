"""ra active voter identity lookup restricted

Revision ID: 74f0541eff26
Revises: ad688fa2b359
Create Date: 2026-11-13 02:36:34.035354

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '74f0541eff26'
down_revision: Union[str, Sequence[str], None] = 'ad688fa2b359'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    pass


def downgrade() -> None:
    """Downgrade schema."""
    pass
