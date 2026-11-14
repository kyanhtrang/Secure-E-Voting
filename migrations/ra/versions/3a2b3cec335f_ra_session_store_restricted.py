"""ra session store restricted

Revision ID: 3a2b3cec335f
Revises: 1dcfbb1dd9a4
Create Date: 2026-11-13 01:56:28.015589

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '3a2b3cec335f'
down_revision: Union[str, Sequence[str], None] = '1dcfbb1dd9a4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(r"""
        CREATE TABLE ra.ra_sessions (
            token_digest VARCHAR(64) PRIMARY KEY,

            voter_id UUID NOT NULL,

            created_at TIMESTAMPTZ NOT NULL
                DEFAULT pg_catalog.clock_timestamp(),

            expires_at TIMESTAMPTZ NOT NULL,

            revoked_at TIMESTAMPTZ,

            CONSTRAINT fk_ra_sessions_voter
                FOREIGN KEY (voter_id)
                REFERENCES ra.voters(voter_id)
                ON DELETE RESTRICT,

            CONSTRAINT ck_ra_sessions_digest
                CHECK (
                    token_digest ~ '^[0-9a-f]{64}$'
                ),

            CONSTRAINT ck_ra_sessions_expiry
                CHECK (expires_at > created_at),

            CONSTRAINT ck_ra_sessions_revocation
                CHECK (
                    revoked_at IS NULL
                    OR revoked_at >= created_at
                )
        );
    """)

    op.execute("""
        CREATE INDEX ix_ra_sessions_voter_id
        ON ra.ra_sessions (voter_id)
    """)

    op.execute("""
        CREATE INDEX ix_ra_sessions_expires_at
        ON ra.ra_sessions (expires_at)
    """)

    # Keep application roles unable to read/write sessions.
    op.execute("""
        REVOKE ALL PRIVILEGES
        ON TABLE ra.ra_sessions
        FROM PUBLIC,
             ra_service,
             ra_service_login,
             ra_recovery_worker,
             ra_audit_reader
    """)


def downgrade() -> None:
    raise RuntimeError(
        "Automatic RA session store downgrade disabled "
        "to prevent session data loss"
    )