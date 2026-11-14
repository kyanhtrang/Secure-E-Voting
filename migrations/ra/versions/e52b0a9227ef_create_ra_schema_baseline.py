"""RA schema baseline using reviewed DDL from evoting-sql-review.zip.

Revision ID: e52b0a9227ef
Revises:

Important: review the SQL and role permissions before production use.
"""

from typing import Sequence, Union

from alembic import op

revision: str = "e52b0a9227ef"
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create RA tables and supporting constraints/indexes."""
    # 01. CREATE TABLE voters (
    op.execute("""
CREATE TABLE voters (
    voter_id UUID PRIMARY KEY,

    auth_provider VARCHAR(128) NOT NULL,
    auth_subject VARCHAR(255) NOT NULL,

    is_active BOOLEAN NOT NULL DEFAULT TRUE,

    created_at TIMESTAMPTZ NOT NULL
        DEFAULT clock_timestamp(),

    updated_at TIMESTAMPTZ NOT NULL
        DEFAULT clock_timestamp(),

    CONSTRAINT uq_voters_auth_subject
        UNIQUE (auth_provider, auth_subject),

    CONSTRAINT ck_voters_auth_provider
        CHECK (btrim(auth_provider) <> ''),

    CONSTRAINT ck_voters_auth_subject
        CHECK (btrim(auth_subject) <> '')
);
    """)

    # 02. CREATE TABLE voter_eligibility (
    op.execute("""
CREATE TABLE voter_eligibility (
    eligibility_id UUID PRIMARY KEY,

    voter_id UUID NOT NULL,

    election_id UUID NOT NULL,

    is_eligible BOOLEAN NOT NULL
        DEFAULT FALSE,

    created_at TIMESTAMPTZ NOT NULL
        DEFAULT clock_timestamp(),

    updated_at TIMESTAMPTZ NOT NULL
        DEFAULT clock_timestamp(),

    CONSTRAINT fk_eligibility_voter
        FOREIGN KEY (voter_id)
        REFERENCES voters(voter_id)
        ON DELETE RESTRICT,

    CONSTRAINT uq_voter_election_eligibility
        UNIQUE (voter_id, election_id)
);
    """)

    # 03. CREATE TABLE blind_issuances (
    op.execute("""
CREATE TABLE blind_issuances (
    issuance_id UUID PRIMARY KEY,

    voter_id UUID NOT NULL,
    election_id UUID NOT NULL,
    request_id UUID NOT NULL,

    blinded_request_hash BYTEA NOT NULL,

    ra_key_id VARCHAR(128) NOT NULL,

    encrypted_blind_signature BYTEA,
    storage_nonce BYTEA,
    storage_key_id VARCHAR(128),

    issuance_status VARCHAR(16) NOT NULL
        DEFAULT 'ISSUED',

    recovery_state VARCHAR(16) NOT NULL
        DEFAULT 'RETAINED',

    issued_at TIMESTAMPTZ NOT NULL
        DEFAULT clock_timestamp(),

    recovery_expires_at TIMESTAMPTZ NOT NULL,

    CONSTRAINT fk_blind_issuance_eligibility
        FOREIGN KEY (voter_id, election_id)
        REFERENCES voter_eligibility (
            voter_id, election_id
        )
        ON UPDATE RESTRICT
        ON DELETE RESTRICT,

    CONSTRAINT uq_blind_issuance_voter_election
        UNIQUE (voter_id, election_id),

    CONSTRAINT ck_blinded_request_hash_length
        CHECK (
            octet_length(blinded_request_hash) = 32
        ),

    CONSTRAINT ck_issuance_status
        CHECK (issuance_status = 'ISSUED'),

    CONSTRAINT ck_ra_key_id
        CHECK (btrim(ra_key_id) <> ''),

    CONSTRAINT ck_recovery_expiry
        CHECK (recovery_expires_at > issued_at),

    CONSTRAINT ck_recovery_data
        CHECK (
            (
                recovery_state = 'RETAINED'
                AND encrypted_blind_signature
                    IS NOT NULL
                AND octet_length(
                    encrypted_blind_signature
                ) > 16
                AND storage_nonce IS NOT NULL
                AND octet_length(storage_nonce) = 12
                AND storage_key_id IS NOT NULL
                AND btrim(storage_key_id) <> ''
            )
            OR
            (
                recovery_state = 'PURGED'
                AND encrypted_blind_signature IS NULL
                AND storage_nonce IS NULL
                AND storage_key_id IS NULL
            )
        )
);
    """)

    # 04. CREATE TABLE ra_signing_keys (
    op.execute("""
CREATE TABLE ra_signing_keys (
    ra_key_id VARCHAR(128) PRIMARY KEY,

    election_id UUID NOT NULL,

    public_key_spki_der BYTEA NOT NULL,
    public_key_fingerprint BYTEA NOT NULL,

    signature_profile VARCHAR(64) NOT NULL
        DEFAULT 'RSABSSA-SHA384-PSS-Randomized',

    private_key_reference VARCHAR(255) NOT NULL,

    key_state VARCHAR(16) NOT NULL
        DEFAULT 'STAGED',

    created_at TIMESTAMPTZ NOT NULL
        DEFAULT clock_timestamp(),

    activated_at TIMESTAMPTZ,
    retired_at TIMESTAMPTZ,

    CONSTRAINT uq_ra_key_election
        UNIQUE (election_id),

    CONSTRAINT uq_ra_key_election_pair
        UNIQUE (election_id, ra_key_id),

    CONSTRAINT ck_ra_key_id_nonblank
        CHECK (btrim(ra_key_id) <> ''),

    CONSTRAINT ck_ra_public_key_nonempty
        CHECK (octet_length(public_key_spki_der) > 0),

    CONSTRAINT ck_ra_key_fingerprint_length
        CHECK (octet_length(public_key_fingerprint) = 32),

    CONSTRAINT ck_ra_private_key_reference
        CHECK (btrim(private_key_reference) <> ''),

    CONSTRAINT ck_ra_signature_profile
        CHECK (
            signature_profile =
            'RSABSSA-SHA384-PSS-Randomized'
        ),

    CONSTRAINT ck_ra_key_state
        CHECK (
            key_state IN (
                'STAGED',
                'ACTIVE',
                'RETIRED'
            )
        ),

    CONSTRAINT ck_ra_key_state_timestamps
        CHECK (
            (
                key_state = 'STAGED'
                AND activated_at IS NULL
                AND retired_at IS NULL
            )
            OR
            (
                key_state = 'ACTIVE'
                AND activated_at IS NOT NULL
                AND retired_at IS NULL
            )
            OR
            (
                key_state = 'RETIRED'
                AND activated_at IS NOT NULL
                AND retired_at IS NOT NULL
                AND retired_at >= activated_at
            )
        )
);
    """)

    # 05. ALTER TABLE blind_issuances
    op.execute("""
ALTER TABLE blind_issuances
ADD CONSTRAINT fk_blind_issuance_ra_key
FOREIGN KEY (election_id, ra_key_id)
REFERENCES ra_signing_keys (
    election_id, ra_key_id
)
ON UPDATE RESTRICT
ON DELETE RESTRICT;
    """)

    # 06. CREATE TABLE ra_audit_events (
    op.execute("""
CREATE TABLE ra_audit_events (
    audit_event_id UUID PRIMARY KEY,

    election_id UUID,
    voter_id UUID,
    issuance_id UUID,

    actor_type VARCHAR(16) NOT NULL,
    actor_principal_id UUID NOT NULL,

    event_type VARCHAR(64) NOT NULL,
    outcome VARCHAR(16) NOT NULL,

    reason_code VARCHAR(64),

    occurred_at TIMESTAMPTZ NOT NULL
        DEFAULT clock_timestamp(),

    CONSTRAINT fk_ra_audit_voter
        FOREIGN KEY (voter_id)
        REFERENCES voters(voter_id)
        ON DELETE RESTRICT,

    CONSTRAINT fk_ra_audit_issuance
        FOREIGN KEY (issuance_id)
        REFERENCES blind_issuances(issuance_id)
        ON DELETE RESTRICT,

    CONSTRAINT ck_ra_audit_actor_type
        CHECK (
            actor_type IN (
                'VOTER',
                'ADMIN',
                'SERVICE',
                'SYSTEM'
            )
        ),

    CONSTRAINT ck_ra_audit_outcome
        CHECK (
            outcome IN (
                'SUCCESS',
                'REJECTED',
                'ERROR'
            )
        ),

    CONSTRAINT ck_ra_audit_event_type
        CHECK (
            event_type IN (
                'ELIGIBILITY_GRANTED',
                'ELIGIBILITY_REVOKED',
                'VOTER_DISABLED',
                'BLIND_ISSUANCE_ISSUED',
                'BLIND_ISSUANCE_REPLAYED',
                'BLIND_ISSUANCE_REJECTED',
                'RECOVERY_PURGED',
                'RA_KEY_STAGED',
                'RA_KEY_ACTIVATED',
                'RA_KEY_RETIRED',
                'SECURITY_CHECK_FAILED'
            )
        ),

    CONSTRAINT ck_ra_audit_reason_code
        CHECK (
            reason_code IS NULL
            OR btrim(reason_code) <> ''
        )
);
    """)


def downgrade() -> None:
    """Drop only this baseline revision objects (destructive; development only)."""
    op.execute("DROP TABLE ra.ra_audit_events;")
    op.execute("DROP TABLE ra.blind_issuances;")
    op.execute("DROP TABLE ra.ra_signing_keys;")
    op.execute("DROP TABLE ra.voter_eligibility;")
    op.execute("DROP TABLE ra.voters;")
