
# Secure E-Voting System
## 06 - Election Lifecycle Design

Version: 1.0
Status: Draft
Phase: P01.2.1

---

## 1. Objective

Define election states, permitted transitions,
responsible components and security invariants.

## 2. State Machine

```mermaid
stateDiagram-v2
    [*] --> DRAFT
    DRAFT --> OPEN: Open Election
    OPEN --> CLOSED: Close Election
    CLOSED --> TALLIED: Execute Tally
    TALLIED --> PUBLISHED: Publish Results
    PUBLISHED --> [*]
```

## 3. States

### DRAFT
- Admin configures election metadata.
- Admin manages candidates.
- Admin configures voter eligibility through RA.
- Voting must reject ballot submissions.
- RA must reject credential issuance.

### OPEN
- Eligible voters may request credentials.
- Voting may accept valid encrypted ballots.
- Candidate information is frozen.
- Eligibility configuration is frozen.

### CLOSED
- RA must reject new credential issuance.
- Voting must reject new ballots.
- Existing accepted ballots remain unchanged.
- Final snapshot preparation is allowed.

### TALLIED
- Restricted tally has completed successfully.
- Aggregate tally report is available.
- No new ballots can be accepted.
- Results are not yet public.

### PUBLISHED
- Aggregate results become public.
- Signed publication manifest is available.
- Election cannot be reopened.
- Public verification remains available.

---

## 4. State Ownership

Authoritative State:
Election Service / voting_db

RA Service:
Reads state through an authenticated
internal Election Metadata API.

Voting Service:
Checks state using the authoritative DB
and enforces atomic ballot acceptance.

Tally Process:
Checks the authoritative CLOSED state
before starting restricted tally.

### 4.1. Frozen Election Configuration

Before an election transitions from DRAFT
to OPEN, the system creates an immutable
election configuration.

The configuration contains:

- schema_version
- election_id
- opens_at
- closes_at
- candidates
- ra_signing_key_id
- ra_public_key_fingerprint
- tally_encryption_key_id
- tally_public_key_fingerprint
- snapshot_signing_key_id
- snapshot_public_key_fingerprint
- cryptographic_profile

Candidate entries contain:

- candidate_id
- candidate_name

Candidates are sorted by candidate_id.

Duplicate candidate IDs are rejected.

All election timestamps use UTC.

The configuration must not contain:
- voter identities
- voter eligibility lists
- authentication credentials
- private keys
- plaintext ballots

### 4.2. Configuration Integrity

The configuration is serialized using
RFC 8785 JSON Canonicalization Scheme.

config_bytes = JCS(election_configuration)

election_config_digest = SHA256(config_bytes)

The digest is represented as lowercase
64-character hexadecimal text.

Public key fingerprints are computed as:

SHA256(DER SubjectPublicKeyInfo)

Each fingerprint uses lowercase hex encoding.

The configuration is signed using the
dedicated snapshot/evidence Ed25519 key.

signed_bytes =
    UTF8("EVOTE-CONFIG-v1") ||
    byte(0) ||
    config_bytes

config_signature = Ed25519.Sign(
    snapshot_signing_private_key,
    signed_bytes
)

The signature is stored separately
from the configuration object.

The signing public key must be trusted
through an independent channel.

The configuration must not be considered
trusted solely because the Board serves
its public key.

### 4.3. Freeze During Election Opening

Before transitioning DRAFT to OPEN:

1. Verify Election Admin authorization.
2. Validate the candidate catalog.
3. Confirm at least one valid candidate.
4. Validate opens_at and closes_at.
5. Verify required public keys are assigned.
6. Verify cryptographic profile consistency.
7. Construct canonical election configuration.
8. Compute election_config_digest.
9. Sign the configuration.
10. Verify the configuration signature.
11. Preserve independently trusted evidence.
12. Begin the election-opening transaction.
13. Lock the authoritative election row.
14. Recheck DRAFT state and readiness.
15. Store the immutable configuration
    reference and digest.
16. Transition election to OPEN.
17. Record the audit event.
18. Commit the transaction.

If preparation or evidence preservation
fails, the election must not open.

External artifact storage and database
transactions are not automatically atomic.

Recovery must verify previously staged
artifacts before reuse.

### 4.4. Configuration Immutability

After the election becomes OPEN:

- Candidate IDs cannot be changed.
- Candidate names cannot be changed.
- Candidate records cannot be added.
- Candidate records cannot be deleted.
- Election public-key assignments
  cannot be changed.
- The cryptographic profile cannot change.
- opens_at and closes_at cannot change
  under the MVP policy.

These restrictions remain effective
during CLOSED, TALLIED and PUBLISHED.

The system must reject unauthorized
configuration modification attempts.

Application checks alone are not enough.

Database permissions and integrity
verification must also enforce
configuration immutability.

### 4.5. Snapshot and Tally Binding

The FINALIZED snapshot must reference
the immutable election configuration.

The snapshot contains:

election_config_digest

The signed snapshot manifest must also
contain the same election_config_digest.

Before decrypting ballots, Tally must:

1. Load the trusted election configuration.
2. Verify its signature.
3. Recalculate election_config_digest.
4. Compare with the finalized snapshot.
5. Compare with the snapshot manifest.
6. Verify the frozen candidate catalog.
7. Verify RA and Tally key identifiers.
8. Reject inconsistent configuration data.

If the configuration integrity check fails,
Tally must abort.

The frozen candidate catalog is the
authoritative source for validating
decrypted candidate_id values.

Document 09 and Document 10 must be
updated to use this binding.

This design protects configuration
consistency but does not establish
complete end-to-end tally verifiability.

---

## 5. Transition Rules

| From | To | Authorized Actor |
|---|---|---|
| DRAFT | OPEN | Election Admin |
| OPEN | CLOSED | Election Admin |
| CLOSED | TALLIED | Tally Operator |
| TALLIED | PUBLISHED | Election Admin |

All other transitions are rejected.

---

## 6. Security Invariants

INV-01:
Only OPEN elections accept new ballots.

INV-02:
Only eligible voters may receive credentials.

INV-03:
A voter can obtain at most one credential
per election.

INV-04:
A serial can be accepted at most once
per election.

INV-05:
Tally cannot begin before CLOSED.

INV-06:
Election transitions cannot be reversed.

INV-07:
Sensitive transitions require authorization
and audit logging.

---

## 7. Concurrency Considerations

### 7.1. Authoritative Election State

The Election Service owns the authoritative
election state in Voting DB.

Voting acceptance and election closing must
use the same election row for concurrency control.

All state-changing operations must validate
the authoritative state inside a DB transaction.

### 7.2. Atomic Ballot Acceptance

Voting performs:

1. Validate request schema and cryptographic evidence.
2. BEGIN transaction.
3. SELECT election row FOR UPDATE.
4. Verify election status == OPEN.
5. Obtain authoritative DB clock_timestamp().
6. Verify opens_at <= decision_time < closes_at.
7. INSERT accepted ballot.
8. Enforce UNIQUE(election_id, serial).
9. COMMIT transaction.
10. Return HTTP 201 only after commit.

The deadline is evaluated after acquiring
the election row lock.

The acceptance decision time may precede
the transaction commit time.

### 7.3. Atomic Election Closing

Election Service performs:

1. BEGIN transaction.
2. SELECT election row FOR UPDATE.
3. Verify election status == OPEN.
4. UPDATE election status to CLOSED.
5. INSERT administrative audit event.
6. COMMIT transaction.

Closing and ballot acceptance serialize
through the same election row lock.

If Voting acquires the lock first and
satisfies all acceptance conditions,
its transaction completes before closing.

If Closing acquires the lock first,
subsequent Voting requests see CLOSED
and must reject new ballots.

### 7.4. Server-Side Election Deadline

Election participation requires:

- status == OPEN
- current server time >= opens_at
- current server time < closes_at

All election timestamps are stored in UTC.

The Client clock is never authoritative.

Manual closing remains required before
final snapshot preparation and tallying.

Automatic state transition at the deadline
is deferred for the MVP.

### 7.5. RA Issuance Concurrency Limitation

RA uses a separate RA Database.

The Voting DB row lock does not provide
a distributed transaction with RA DB.

RA checks the trusted Election Service
before authorizing a new credential.

If the trusted state is unavailable,
new issuance must fail closed.

An issuance authorized before closure
may complete after closure.

However, Voting must reject new ballots
when the election is CLOSED or expired.

Exact retrieval of a previously committed
blind signature is not a new issuance.

Strict atomic RA/Close coordination remains
outside the MVP guarantee.

### 7.6. Required Concurrency Tests

CON-T01:
Close Election and Submit Ballot concurrently.

Expected:
Acceptance follows transaction ordering.

CON-T02:
Close Election and Issue Credential concurrently.

Expected:
Behavior matches documented RA limitation.

CON-T03:
Submit Ballot exactly at closes_at.

Expected:
Rejected.

CON-T04:
Submit Ballot before opens_at.

Expected:
Rejected.

CON-T05:
Retry original credential issuance after CLOSED.

Expected:
Return existing credential response only;
do not create a second issuance record.

---

## 8. Failure Policy

- If trusted election state is unavailable,
  RA must not issue credentials.
- Voting must not accept ballots when it
  cannot verify the authoritative state.
- Failed transitions must not partially
  change the authoritative election state.
- A successful state change must produce
  an audit record.

---

## 9. Acceptance Criteria

- All five states are documented.
- Only four forward transitions are allowed.
- Unauthorized transitions are rejected.
- Invalid transitions preserve the state.
- Voting and close ordering is defined.
- Remaining RA concurrency risks are tracked.

## 10. Open Decisions

DR-02:
Finalize consistency between RA credential
issuance and election closure.

OD-03:
Define scheduled versus manual closing.

OD-13:
Define exact handling of concurrent
closing and ballot submission.
