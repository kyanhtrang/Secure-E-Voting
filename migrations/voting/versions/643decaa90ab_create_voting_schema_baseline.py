"""Voting schema baseline using reviewed DDL from evoting-sql-review.zip.

Revision ID: 643decaa90ab
Revises:

Important: review the SQL and role permissions before production use.
"""

from typing import Sequence, Union

from alembic import op

revision: str = "643decaa90ab"
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create Voting tables and supporting constraints/indexes."""
    # 01. CREATE TABLE elections (
    op.execute("""
CREATE TABLE elections (
    election_id UUID PRIMARY KEY,

    title VARCHAR(255) NOT NULL,

    status VARCHAR(16) NOT NULL
        DEFAULT 'DRAFT',

    opens_at TIMESTAMPTZ NOT NULL,
    closes_at TIMESTAMPTZ NOT NULL,

    election_config_digest BYTEA,

    active_tally_job_id UUID,

    tally_fencing_token BIGINT NOT NULL
        DEFAULT 0,

    created_at TIMESTAMPTZ NOT NULL
        DEFAULT clock_timestamp(),

    updated_at TIMESTAMPTZ NOT NULL
        DEFAULT clock_timestamp(),

    CONSTRAINT ck_election_title
        CHECK (btrim(title) <> ''),

    CONSTRAINT ck_election_status
        CHECK (
            status IN (
                'DRAFT',
                'OPEN',
                'CLOSED',
                'TALLIED',
                'PUBLISHED'
            )
        ),

    CONSTRAINT ck_election_time_range
        CHECK (opens_at < closes_at),

    CONSTRAINT ck_election_config_digest
        CHECK (
            election_config_digest IS NULL
            OR octet_length(
                election_config_digest
            ) = 32
        ),

    CONSTRAINT ck_election_frozen_config
        CHECK (
            status = 'DRAFT'
            OR election_config_digest IS NOT NULL
        ),

    CONSTRAINT ck_tally_fencing_token
        CHECK (tally_fencing_token >= 0)
);
    """)

    # 02. CREATE TABLE candidates (
    op.execute("""
CREATE TABLE candidates (
    election_id UUID NOT NULL,
    candidate_id UUID NOT NULL,

    candidate_name VARCHAR(255) NOT NULL,

    created_at TIMESTAMPTZ NOT NULL
        DEFAULT clock_timestamp(),

    updated_at TIMESTAMPTZ NOT NULL
        DEFAULT clock_timestamp(),

    CONSTRAINT pk_candidates
        PRIMARY KEY (election_id, candidate_id),

    CONSTRAINT fk_candidate_election
        FOREIGN KEY (election_id)
        REFERENCES elections(election_id)
        ON UPDATE RESTRICT
        ON DELETE RESTRICT,

    CONSTRAINT ck_candidate_name
        CHECK (btrim(candidate_name) <> '')
);
    """)

    # 03. CREATE TABLE election_configs (
    op.execute("""
CREATE TABLE election_configs (
    election_id UUID PRIMARY KEY,

    config_schema_version SMALLINT NOT NULL
        DEFAULT 1,

    config_bytes BYTEA NOT NULL,
    config_digest BYTEA NOT NULL,
    config_signature BYTEA NOT NULL,

    config_signing_key_id VARCHAR(128)
        NOT NULL,

    config_signing_key_fingerprint BYTEA
        NOT NULL,

    evidence_reference VARCHAR(1024)
        NOT NULL,

    frozen_at TIMESTAMPTZ NOT NULL
        DEFAULT clock_timestamp(),

    CONSTRAINT fk_config_election
        FOREIGN KEY (election_id)
        REFERENCES elections(election_id)
        ON UPDATE RESTRICT
        ON DELETE RESTRICT,

    CONSTRAINT ck_config_schema_version
        CHECK (config_schema_version = 1),

    CONSTRAINT ck_config_bytes
        CHECK (octet_length(config_bytes) > 0),

    CONSTRAINT ck_config_digest_length
        CHECK (octet_length(config_digest) = 32),

    CONSTRAINT ck_config_signature_length
        CHECK (octet_length(config_signature) = 64),

    CONSTRAINT ck_config_signing_key_id
        CHECK (
            btrim(config_signing_key_id) <> ''
        ),

    CONSTRAINT ck_config_key_fingerprint
        CHECK (
            octet_length(
                config_signing_key_fingerprint
            ) = 32
        ),

    CONSTRAINT ck_config_evidence_reference
        CHECK (
            btrim(evidence_reference) <> ''
        )
);
    """)

    # 04. CREATE TABLE accepted_ballots (
    op.execute("""
CREATE TABLE accepted_ballots (
    ballot_id UUID PRIMARY KEY,

    election_id UUID NOT NULL,

    serial BYTEA NOT NULL,
    envelope BYTEA NOT NULL,
    prepared_msg BYTEA NOT NULL,
    signature BYTEA NOT NULL,

    envelope_hash BYTEA NOT NULL,
    receipt_hash BYTEA NOT NULL,

    accepted_at TIMESTAMPTZ NOT NULL
        DEFAULT clock_timestamp(),

    CONSTRAINT fk_ballot_election
        FOREIGN KEY (election_id)
        REFERENCES elections(election_id)
        ON UPDATE RESTRICT
        ON DELETE RESTRICT,

    CONSTRAINT uq_ballot_election_serial
        UNIQUE (election_id, serial),

    CONSTRAINT uq_ballot_election_receipt
        UNIQUE (election_id, receipt_hash),

    CONSTRAINT ck_ballot_serial_length
        CHECK (octet_length(serial) = 32),

    CONSTRAINT ck_ballot_envelope_size
        CHECK (
            octet_length(envelope)
            BETWEEN 1 AND 65536
        ),

    CONSTRAINT ck_ballot_prepared_msg_size
        CHECK (
            octet_length(prepared_msg)
            BETWEEN 33 AND 8192
        ),

    CONSTRAINT ck_ballot_signature_length
        CHECK (octet_length(signature) = 384),

    CONSTRAINT ck_ballot_envelope_hash_length
        CHECK (octet_length(envelope_hash) = 32),

    CONSTRAINT ck_ballot_receipt_hash_length
        CHECK (octet_length(receipt_hash) = 32)
);
    """)

    # 05. CREATE TABLE final_snapshots (
    op.execute("""
CREATE TABLE final_snapshots (
    snapshot_id UUID PRIMARY KEY,

    election_id UUID NOT NULL,

    status VARCHAR(16) NOT NULL
        DEFAULT 'PREPARING',

    snapshot_schema_version SMALLINT NOT NULL
        DEFAULT 1,

    election_config_digest BYTEA,
    snapshot_digest BYTEA,

    ballot_count BIGINT,

    snapshot_artifact_ref VARCHAR(1024),

    manifest_bytes BYTEA,
    manifest_signature BYTEA,
    signing_key_id VARCHAR(128),

    evidence_reference VARCHAR(1024),

    failure_code VARCHAR(64),

    created_at TIMESTAMPTZ NOT NULL
        DEFAULT clock_timestamp(),

    finalized_at TIMESTAMPTZ,
    failed_at TIMESTAMPTZ,

    CONSTRAINT fk_snapshot_election
        FOREIGN KEY (election_id)
        REFERENCES elections(election_id)
        ON UPDATE RESTRICT
        ON DELETE RESTRICT,

    CONSTRAINT ck_snapshot_status
        CHECK (
            status IN (
                'PREPARING',
                'FINALIZED',
                'FAILED'
            )
        ),

    CONSTRAINT ck_snapshot_schema_version
        CHECK (snapshot_schema_version = 1),

    CONSTRAINT ck_snapshot_config_digest
        CHECK (
            election_config_digest IS NULL
            OR octet_length(
                election_config_digest
            ) = 32
        ),

    CONSTRAINT ck_snapshot_digest_length
        CHECK (
            snapshot_digest IS NULL
            OR octet_length(snapshot_digest) = 32
        ),

    CONSTRAINT ck_snapshot_ballot_count
        CHECK (
            ballot_count IS NULL
            OR ballot_count >= 0
        ),

    CONSTRAINT ck_snapshot_signature_length
        CHECK (
            manifest_signature IS NULL
            OR octet_length(manifest_signature) = 64
        ),

    CONSTRAINT ck_snapshot_finalized_data
        CHECK (
            status <> 'FINALIZED'
            OR (
                election_config_digest IS NOT NULL
                AND snapshot_digest IS NOT NULL
                AND ballot_count IS NOT NULL
                AND snapshot_artifact_ref IS NOT NULL
                AND btrim(snapshot_artifact_ref) <> ''
                AND manifest_bytes IS NOT NULL
                AND octet_length(manifest_bytes) > 0
                AND manifest_signature IS NOT NULL
                AND signing_key_id IS NOT NULL
                AND btrim(signing_key_id) <> ''
                AND evidence_reference IS NOT NULL
                AND btrim(evidence_reference) <> ''
                AND finalized_at IS NOT NULL
                AND failed_at IS NULL
                AND failure_code IS NULL
            )
        ),

    CONSTRAINT ck_snapshot_failure_data
        CHECK (
            status <> 'FAILED'
            OR (
                failed_at IS NOT NULL
                AND finalized_at IS NULL
                AND failure_code IS NOT NULL
                AND btrim(failure_code) <> ''
            )
        ),

    CONSTRAINT ck_snapshot_preparing_data
        CHECK (
            status <> 'PREPARING'
            OR (
                finalized_at IS NULL
                AND failed_at IS NULL
                AND failure_code IS NULL
            )
        )
);
    """)

    # 06. CREATE UNIQUE INDEX ux_snapshot_one_finalized
    op.execute("""
CREATE UNIQUE INDEX ux_snapshot_one_finalized
ON final_snapshots (election_id)
WHERE status = 'FINALIZED';
    """)

    # 07. CREATE UNIQUE INDEX ux_snapshot_one_preparing
    op.execute("""
CREATE UNIQUE INDEX ux_snapshot_one_preparing
ON final_snapshots (election_id)
WHERE status = 'PREPARING';
    """)

    # 08. ALTER TABLE final_snapshots
    op.execute("""
ALTER TABLE final_snapshots
ADD CONSTRAINT uq_snapshot_id_election
UNIQUE (snapshot_id, election_id);
    """)

    # 09. CREATE TABLE tally_jobs (
    op.execute("""
CREATE TABLE tally_jobs (
    tally_job_id UUID PRIMARY KEY,

    election_id UUID NOT NULL,
    snapshot_id UUID NOT NULL,

    election_config_digest BYTEA NOT NULL,
    snapshot_digest BYTEA NOT NULL,

    algorithm_version VARCHAR(64) NOT NULL,

    status VARCHAR(16) NOT NULL
        DEFAULT 'RUNNING',

    fencing_token BIGINT,

    lease_until TIMESTAMPTZ,
    last_heartbeat_at TIMESTAMPTZ,

    created_at TIMESTAMPTZ NOT NULL
        DEFAULT clock_timestamp(),

    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,

    failure_code VARCHAR(64),

    CONSTRAINT fk_tally_job_election
        FOREIGN KEY (election_id)
        REFERENCES elections(election_id)
        ON DELETE RESTRICT,

    CONSTRAINT fk_tally_job_snapshot
        FOREIGN KEY (snapshot_id, election_id)
        REFERENCES final_snapshots (
            snapshot_id, election_id
        )
        ON DELETE RESTRICT,

    CONSTRAINT uq_tally_job_election_pair
        UNIQUE (election_id, tally_job_id),

    CONSTRAINT uq_tally_job_election_fence
        UNIQUE (election_id, fencing_token),

    CONSTRAINT ck_tally_job_status
        CHECK (
            status IN (
                'PENDING',
                'RUNNING',
                'SUCCEEDED',
                'FAILED'
            )
        ),

    CONSTRAINT ck_tally_job_config_digest
        CHECK (
            octet_length(
                election_config_digest
            ) = 32
        ),

    CONSTRAINT ck_tally_job_snapshot_digest
        CHECK (
            octet_length(snapshot_digest) = 32
        ),

    CONSTRAINT ck_tally_job_algorithm
        CHECK (btrim(algorithm_version) <> ''),

    CONSTRAINT ck_tally_job_fencing
        CHECK (
            fencing_token IS NULL
            OR fencing_token > 0
        ),

    CONSTRAINT ck_tally_job_state_data
        CHECK (
            (
                status = 'PENDING'
                AND fencing_token IS NULL
                AND lease_until IS NULL
                AND started_at IS NULL
                AND last_heartbeat_at IS NULL
                AND finished_at IS NULL
                AND failure_code IS NULL
            )
            OR
            (
                status = 'RUNNING'
                AND fencing_token IS NOT NULL
                AND lease_until IS NOT NULL
                AND started_at IS NOT NULL
                AND last_heartbeat_at IS NOT NULL
                AND finished_at IS NULL
                AND failure_code IS NULL
                AND lease_until > started_at
            )
            OR
            (
                status = 'SUCCEEDED'
                AND fencing_token IS NOT NULL
                AND lease_until IS NOT NULL
                AND started_at IS NOT NULL
                AND finished_at IS NOT NULL
                AND failure_code IS NULL
            )
            OR
            (
                status = 'FAILED'
                AND fencing_token IS NOT NULL
                AND lease_until IS NOT NULL
                AND started_at IS NOT NULL
                AND finished_at IS NOT NULL
                AND failure_code IS NOT NULL
                AND btrim(failure_code) <> ''
            )
        )
);
    """)

    # 10. CREATE UNIQUE INDEX ux_tally_one_running
    op.execute("""
CREATE UNIQUE INDEX ux_tally_one_running
ON tally_jobs (election_id)
WHERE status = 'RUNNING';
    """)

    # 11. CREATE UNIQUE INDEX ux_tally_one_succeeded
    op.execute("""
CREATE UNIQUE INDEX ux_tally_one_succeeded
ON tally_jobs (election_id)
WHERE status = 'SUCCEEDED';
    """)

    # 12. ALTER TABLE elections
    op.execute("""
ALTER TABLE elections
ADD CONSTRAINT fk_election_active_tally_job
FOREIGN KEY (election_id, active_tally_job_id)
REFERENCES tally_jobs (
    election_id, tally_job_id
)
DEFERRABLE INITIALLY IMMEDIATE;
    """)

    # 13. CREATE TABLE tally_reports (
    op.execute("""
CREATE TABLE tally_reports (
    tally_id UUID PRIMARY KEY,

    election_id UUID NOT NULL,
    snapshot_id UUID NOT NULL,

    report_version SMALLINT NOT NULL
        DEFAULT 1,

    election_config_digest BYTEA NOT NULL,
    snapshot_digest BYTEA NOT NULL,

    accepted_total BIGINT NOT NULL,
    valid_total BIGINT NOT NULL,
    invalid_total BIGINT NOT NULL,
    counted_total BIGINT NOT NULL,

    candidate_counts JSONB NOT NULL,

    algorithm_version VARCHAR(64) NOT NULL,

    report_bytes BYTEA NOT NULL,
    report_digest BYTEA NOT NULL,

    finalized_at TIMESTAMPTZ NOT NULL
        DEFAULT clock_timestamp(),

    CONSTRAINT fk_tally_report_job
        FOREIGN KEY (election_id, tally_id)
        REFERENCES tally_jobs (
            election_id, tally_job_id
        )
        ON UPDATE RESTRICT
        ON DELETE RESTRICT,

    CONSTRAINT fk_tally_report_snapshot
        FOREIGN KEY (snapshot_id, election_id)
        REFERENCES final_snapshots (
            snapshot_id, election_id
        )
        ON UPDATE RESTRICT
        ON DELETE RESTRICT,

    CONSTRAINT uq_tally_report_election
        UNIQUE (election_id),

    CONSTRAINT ck_tally_report_version
        CHECK (report_version = 1),

    CONSTRAINT ck_tally_report_config_digest
        CHECK (
            octet_length(
                election_config_digest
            ) = 32
        ),

    CONSTRAINT ck_tally_report_snapshot_digest
        CHECK (
            octet_length(snapshot_digest) = 32
        ),

    CONSTRAINT ck_tally_report_digest_length
        CHECK (
            octet_length(report_digest) = 32
        ),

    CONSTRAINT ck_tally_report_bytes
        CHECK (octet_length(report_bytes) > 0),

    CONSTRAINT ck_tally_report_algorithm
        CHECK (btrim(algorithm_version) <> ''),

    CONSTRAINT ck_tally_report_totals
        CHECK (
            accepted_total >= 0
            AND valid_total >= 0
            AND invalid_total >= 0
            AND counted_total >= 0
            AND accepted_total =
                valid_total + invalid_total
            AND counted_total = valid_total
        ),

    CONSTRAINT ck_tally_report_candidates
        CHECK (
            jsonb_typeof(candidate_counts)
                = 'array'
        )
);
    """)

    # 14. ALTER TABLE tally_reports
    op.execute("""
ALTER TABLE tally_reports
ADD CONSTRAINT uq_tally_report_election_tally
UNIQUE (election_id, tally_id);
    """)

    # 15. CREATE TABLE publications (
    op.execute("""
CREATE TABLE publications (
    publication_id UUID PRIMARY KEY,

    election_id UUID NOT NULL,
    tally_id UUID NOT NULL,
    snapshot_id UUID NOT NULL,

    election_config_digest BYTEA NOT NULL,
    snapshot_digest BYTEA NOT NULL,
    tally_report_digest BYTEA NOT NULL,

    manifest_bytes BYTEA NOT NULL,
    manifest_signature BYTEA NOT NULL,

    publication_key_id VARCHAR(128) NOT NULL,
    evidence_reference VARCHAR(1024) NOT NULL,

    published_at TIMESTAMPTZ NOT NULL
        DEFAULT clock_timestamp(),

    CONSTRAINT fk_publication_election
        FOREIGN KEY (election_id)
        REFERENCES elections(election_id)
        ON UPDATE RESTRICT
        ON DELETE RESTRICT,

    CONSTRAINT fk_publication_tally_report
        FOREIGN KEY (election_id, tally_id)
        REFERENCES tally_reports (
            election_id, tally_id
        )
        ON UPDATE RESTRICT
        ON DELETE RESTRICT,

    CONSTRAINT fk_publication_snapshot
        FOREIGN KEY (snapshot_id, election_id)
        REFERENCES final_snapshots (
            snapshot_id, election_id
        )
        ON UPDATE RESTRICT
        ON DELETE RESTRICT,

    CONSTRAINT uq_publication_election
        UNIQUE (election_id),

    CONSTRAINT ck_publication_config_digest
        CHECK (
            octet_length(
                election_config_digest
            ) = 32
        ),

    CONSTRAINT ck_publication_snapshot_digest
        CHECK (
            octet_length(snapshot_digest) = 32
        ),

    CONSTRAINT ck_publication_report_digest
        CHECK (
            octet_length(tally_report_digest) = 32
        ),

    CONSTRAINT ck_publication_manifest_bytes
        CHECK (
            octet_length(manifest_bytes) > 0
        ),

    CONSTRAINT ck_publication_signature
        CHECK (
            octet_length(manifest_signature) = 64
        ),

    CONSTRAINT ck_publication_key_id
        CHECK (
            btrim(publication_key_id) <> ''
        ),

    CONSTRAINT ck_publication_evidence
        CHECK (
            btrim(evidence_reference) <> ''
        )
);
    """)

    # 16. CREATE TABLE voting_audit_events (
    op.execute("""
CREATE TABLE voting_audit_events (
    audit_event_id UUID PRIMARY KEY,

    election_id UUID NOT NULL,

    actor_type VARCHAR(16) NOT NULL,
    actor_principal_id UUID,

    event_type VARCHAR(64) NOT NULL,
    outcome VARCHAR(16) NOT NULL,

    reason_code VARCHAR(64),

    occurred_at TIMESTAMPTZ NOT NULL
        DEFAULT clock_timestamp(),

    CONSTRAINT fk_voting_audit_election
        FOREIGN KEY (election_id)
        REFERENCES elections(election_id)
        ON UPDATE RESTRICT
        ON DELETE RESTRICT,

    CONSTRAINT ck_voting_audit_actor_type
        CHECK (
            actor_type IN (
                'ADMIN',
                'SERVICE',
                'SYSTEM',
                'TALLY_OPERATOR',
                'AUDITOR'
            )
        ),

    CONSTRAINT ck_voting_audit_outcome
        CHECK (
            outcome IN (
                'SUCCESS',
                'REJECTED',
                'ERROR'
            )
        ),

    CONSTRAINT ck_voting_audit_event_type
        CHECK (
            event_type IN (
                'ELECTION_CREATED',
                'ELECTION_OPENED',
                'ELECTION_CLOSED',
                'ELECTION_TALLIED',
                'ELECTION_PUBLISHED',
                'CANDIDATE_CREATED',
                'CANDIDATE_UPDATED',
                'CANDIDATE_DELETED',
                'CONFIG_FROZEN',
                'CONFIG_VERIFICATION_FAILED',
                'SNAPSHOT_PREPARING',
                'SNAPSHOT_FINALIZED',
                'SNAPSHOT_FAILED',
                'TALLY_JOB_CLAIMED',
                'TALLY_JOB_RECOVERED',
                'TALLY_JOB_SUCCEEDED',
                'TALLY_JOB_FAILED',
                'PUBLICATION_REJECTED',
                'PUBLICATION_FAILED',
                'ACCESS_REJECTED',
                'SECURITY_INTEGRITY_FAILURE'
            )
        ),

    CONSTRAINT ck_voting_audit_reason_code
        CHECK (
            reason_code IS NULL
            OR btrim(reason_code) <> ''
        )
);
    """)

    # 17. CREATE INDEX ix_voting_audit_election_time
    op.execute("""
CREATE INDEX ix_voting_audit_election_time
ON voting_audit_events (
    election_id,
    occurred_at DESC,
    audit_event_id
);
    """)

    # 18. CREATE INDEX ix_voting_audit_event_type
    op.execute("""
CREATE INDEX ix_voting_audit_event_type
ON voting_audit_events (
    event_type,
    occurred_at DESC
);
    """)


def downgrade() -> None:
    """Drop only this baseline revision objects (destructive; development only)."""
    # Break the election -> tally_jobs foreign key cycle before dropping tally_jobs.
    op.execute("ALTER TABLE voting.elections DROP CONSTRAINT fk_election_active_tally_job;")

    op.execute("DROP TABLE voting.voting_audit_events;")
    op.execute("DROP TABLE voting.publications;")
    op.execute("DROP TABLE voting.tally_reports;")
    op.execute("DROP TABLE voting.tally_jobs;")
    op.execute("DROP TABLE voting.final_snapshots;")
    op.execute("DROP TABLE voting.accepted_ballots;")
    op.execute("DROP TABLE voting.election_configs;")
    op.execute("DROP TABLE voting.candidates;")
    op.execute("DROP TABLE voting.elections;")
