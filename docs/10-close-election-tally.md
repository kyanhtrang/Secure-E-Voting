# Secure E-Voting System
## 10 - Close Election & Restricted Tally

- **Version:** 1.0
- **Status:** Draft
- **Phase:** P01.2.5

---

## 1. Objective

Design secure election closing, final snapshot preparation, restricted decryption, vote validation, tally reporting and result publication.

Related Use Cases:

- UC-10: Close Election
- UC-11: Execute Tally
- UC-12: Publish Results
- UC-13: Verify Public Snapshot
- UC-14: View Security Audit

Security Requirements:

- SR-04: Integrity and partial auditability
- SR-06: Secure storage and key protection
- SR-07: Election state enforcement

---

## 2. System Components

### Election Service

- Owns the authoritative election state
- Validates administrative permissions
- Coordinates election closing
- Rejects invalid state transitions
- Records administrative audit events

### Voting Service

- Accepts ballots only during OPEN
- Uses the authoritative election state
- Stores encrypted ballots
- Cannot access the Tally private key

### Snapshot Publisher

- Reads the frozen accepted-ballot dataset
- Produces a canonical final snapshot
- Calculates the snapshot digest
- Signs the manifest using a dedicated key

### Restricted Tally Process

- Runs only after CLOSED
- Verifies the final snapshot
- Unlocks the Tally private key
- Decrypts and validates accepted ballots
- Produces aggregate results

### Public Bulletin Board

- Publishes encrypted ballot records
- Publishes final snapshot evidence
- Publishes approved results after PUBLISHED
- Provides read-only public access

---

## 3. Election State Transitions

Required sequence:

`DRAFT → OPEN → CLOSED → TALLIED → PUBLISHED`

### Closing

Allowed transition:

`OPEN → CLOSED`

Authorized Actor: Election Admin

### Tallying

Allowed transition:

`CLOSED → TALLIED`

Authorized Actor: Tally Operator

### Publication

Allowed transition:

`TALLIED → PUBLISHED`

Authorized Actor: Election Admin

All reverse transitions are prohibited.

A failed tally does not change CLOSED to TALLIED.

A failed publication does not change TALLIED to PUBLISHED.

---

## 4. Close Election Workflow

### Preconditions

- Election exists
- Election state is OPEN
- Admin is authenticated and authorized

### Main Flow

1. Admin selects an OPEN election.
2. Admin requests Close Election.
3. Backend verifies authorization.
4. Backend begins a database transaction.
5. Backend locks the authoritative election row.
6. Backend confirms that the state is OPEN.
7. Backend updates the state to CLOSED.
8. Backend inserts the security audit event.
9. Backend commits the transaction.
10. Backend returns the CLOSED status.

### Concurrent Ballot Submissions

Ballot acceptance and election closing must lock the same authoritative election row.

If acceptance obtains the lock first:

- The ballot may commit while the election remains OPEN
- Closing executes afterward

If closing obtains the lock first:

- The state becomes CLOSED
- Subsequent ballot acceptance is rejected

The transaction commit ordering determines whether the ballot was accepted before closure.

### Important Limitation

RA uses a separate database.

The election-row lock does not automatically guarantee atomic coordination between RA issuance and closing.

This issue remains under DR-02.

---

## 5. Final Snapshot Preparation

### 5.1. Preconditions

Final snapshot preparation requires:

- Election state == CLOSED.
- Closing transaction has committed.
- No further ballot acceptance is possible.
- Previously accepted transactions have resolved.
- Snapshot Publisher is authorized.
- No authoritative FINALIZED snapshot exists.

The final snapshot must follow the format
and verification rules of Document 09.

### 5.2. Snapshot Construction

Snapshot Publisher performs:

1. Verify authoritative CLOSED state.
2. Create a PREPARING snapshot attempt.
3. Read committed accepted ballots
   using a consistent database view.
4. Construct public ballot records.
5. Recalculate receipt hashes.
6. Verify the ballot record count.
7. Sort records by receipt_hash ascending.
8. Construct the canonical snapshot.
9. Serialize using RFC 8785 JCS.
10. Calculate SHA-256 snapshot digest.

Formula:

snapshot_digest = SHA256(JCS(snapshot))

No voter identity or plaintext vote
may appear in the final snapshot.

### 5.3. Signing and Preservation

After constructing the snapshot:

1. Write snapshot to private staging storage.
2. Create the unsigned manifest.
3. Sign manifest using dedicated Ed25519 key.
4. Verify the manifest signature.
5. Preserve independent integrity evidence.
6. Confirm the Auditor has received
   and verified the evidence package.
7. Atomically persist the authoritative
   snapshot reference and FINALIZED state.
8. Expose finalized artifacts to Board.

Snapshot and signing formats must match
Document 09 exactly.

### 5.4. Snapshot Lifecycle

Allowed states:

- PREPARING
- FINALIZED
- FAILED

Valid transitions:

PREPARING -> FINALIZED
PREPARING -> FAILED
FAILED -> PREPARING (controlled retry)

FINALIZED is terminal.

At most one authoritative FINALIZED
snapshot is allowed per election.

### 5.5. Tally Input Contract

Tally must load the exact immutable
snapshot referenced by the authoritative
FINALIZED snapshot record.

Tally must not independently query
a new accepted-ballot dataset.

The Tally input includes:

- FINALIZED snapshot
- Signed snapshot manifest
- Independently preserved evidence
- Frozen election configuration
- Configuration signature
- Trusted signing public key
- Snapshot signing public key
- Election-specific RA public key
- Election-specific Tally key metadata

Before decrypting, Tally verifies:

1. Election status == CLOSED.
2. Snapshot status == FINALIZED.
3. Snapshot schema and election_id.
4. Snapshot ballot count.
5. SHA-256 snapshot digest.
6. Ed25519 snapshot manifest signature.
7. Independently trusted signing key.
8. Independently preserved evidence.
9. Frozen configuration signature.
10. SHA256(JCS(frozen_configuration)).
11. Configuration digest equals the
    snapshot election_config_digest.
12. Configuration digest equals the
    manifest election_config_digest.
13. Frozen candidate catalog integrity.
14. RA public key identifier and fingerprint.
15. Tally public key identifier and fingerprint.
16. Cryptographic profile consistency.

The verification process must use
the frozen configuration defined
in Document 06.

Snapshot and manifest formats must
follow Document 09.

If any mandatory verification fails:

- Abort the entire tally.
- Do not unlock the Tally private key.
- Do not decrypt individual ballots.
- Do not mark the job SUCCEEDED.
- Keep the election CLOSED.
- Record a privacy-safe integrity failure.

A valid snapshot signature alone
is not sufficient.

The frozen election configuration
must also be verified successfully.

### 5.6. Failure Recovery

If snapshot creation fails:

- Keep election state CLOSED.
- Mark preparation FAILED when possible.
- Do not expose incomplete artifacts.
- Do not start Tally.
- Allow a controlled retry.

If a FINALIZED snapshot exists:

- Return its original metadata.
- Verify its immutable stored bytes.
- Do not silently regenerate or replace it.

Database writes and external file storage
are not automatically atomic.

Recovery must identify incomplete staging
artifacts and reconcile publication state.

---

## 6. Tally Authorization and Key Management

### Tally Operator

The Tally Operator is separate from the Election Admin role.

Responsibilities:

- Request restricted tally execution
- Verify the correct election
- Unlock the Tally private key
- Review the aggregate tally report

### Private Key Storage

For the local MVP:

- Generate a dedicated RSA Tally key pair
- Store the private key in encrypted PEM format
- Protect the private key with a passphrase
- Keep the key outside source code and Git
- Make the key available only to Tally Process
- Never mount the private key into Voting Service

The passphrase must not be hard-coded or supplied as a command-line argument.

A protected interactive prompt is preferred for the demonstration.

### Execution Policy

1. Verify the authoritative election state.
2. Verify that the election is CLOSED.
3. Verify the Tally Operator's authorization.
4. Verify the final snapshot and signature.
5. Start the restricted tally execution.
6. Unlock the correct private key.
7. Process accepted encrypted ballots.
8. Remove sensitive key material from process scope when execution ends.

Python cannot guarantee immediate erasure of every private-key byte from memory. The MVP therefore relies on process isolation, limited access and process termination.

---

## 7. Ballot Decryption and Validation

### 7.1. Security Preconditions

Before processing any ballot:

1. Verify authorized Tally Operator.
2. Verify election state == CLOSED.
3. Load the authoritative FINALIZED snapshot.
4. Verify snapshot SHA-256 digest.
5. Verify Ed25519 manifest signature.
6. Verify the independently trusted
   snapshot signing public key.
7. Compare independent integrity evidence.
8. Verify snapshot election ID and count.
9. Verify unique election_id and serial
   combinations inside the snapshot.
10. Load the frozen election configuration.
11. Verify the configuration signature.
12. Recalculate election_config_digest.
13. Compare configuration digest with
    the snapshot and signed manifest.
14. Load candidates from the verified
    frozen configuration.
15. Verify election-specific RA key
    ID and public key fingerprint.
16. Verify Tally key ID and public
    key fingerprint.
17. Verify the cryptographic profile
    matches the frozen configuration.

Only after all checks succeed may
Tally unlock its private key.

Tally must not load candidate definitions
from mutable live configuration tables.

If snapshot or configuration integrity
verification fails:

- Abort the entire tally.
- Keep election CLOSED.
- Do not publish any partial result.
- Preserve a controlled audit event.

### 7.2. Load Restricted Private Key

Tally Process loads the encrypted PEM
private key associated with the election.

Requirements:

- Authorized operator interaction
- Passphrase supplied through protected input
- No private key exposed to Voting Service
- No private key written to logs
- Correct Tally key_id verification

If private-key loading fails:

- Abort tally execution.
- Mark tally job FAILED.
- Keep election state CLOSED.

### 7.3. Validate Individual Ballot

For each ballot in the verified snapshot:

1. Read election_id and serial.
2. Validate the encrypted envelope.
3. Validate RSA signature metadata.
4. Verify finalized blind signature
   using the trusted election-specific
   RA public key.
5. Verify prepared_msg and the
   application-message binding.
6. Confirm the encrypted-envelope hash.
7. Confirm the correct Tally key_id.

The verification rules must match
Document 08.

A ballot failing individual validation
must not contribute to candidate counts.

Such a ballot is classified as invalid
and its failure category is recorded.

Unexpected evidence failures must also
produce a security audit event.

### 7.4. Recover AES Session Key

For each ballot passing the previous checks:

K = RSA-OAEP-SHA256.Decrypt(
    tally_private_key,
    encrypted_key
)

The recovered AES key must be
exactly 32 bytes.

If RSA-OAEP decryption fails:

- Mark ballot invalid.
- Do not count it as a valid vote.
- Do not expose internal key details.

### 7.5. Reconstruct AAD and Decrypt

Construct AAD using:

- schema_version
- election_id
- serial

Serialize AAD using RFC 8785 JCS.

Decrypt using:

AES-256-GCM.Decrypt(
    key=K,
    nonce=envelope.nonce,
    ciphertext_and_tag=envelope.ciphertext,
    associated_data=AAD
)

The AES-GCM authentication tag
must be verified.

If authentication fails:

- Mark the ballot invalid.
- Do not use its plaintext.
- Continue processing other ballots.

### 7.6. Validate Decrypted Plaintext

After successful AES-GCM decryption:

1. Parse plaintext as JSON.
2. Validate schema_version.
3. Verify election_id.
4. Verify exactly one candidate_id.
5. Verify candidate_id belongs to the
   verified frozen election configuration.
6. Reject unsupported plaintext fields.
7. Reject malformed or inconsistent data.

If plaintext validation succeeds:

- Increment valid_total.
- Increment selected candidate count.

Otherwise:

- Increment invalid_total.
- Record non-sensitive failure category.

Individual plaintext votes must never
be persisted in the public database
or written to general-purpose logs.

### Candidate Catalog Source

The only authoritative candidate catalog
for Tally is the one contained in the
verified frozen election configuration.

Tally must not use candidate records
retrieved from mutable live tables.

If a candidate_id does not exist in
the verified frozen catalog:

- Classify the individual ballot INVALID.
- Increment invalid_total.
- Do not increment any candidate count.

If the frozen configuration itself
cannot be verified:

- Abort the entire tally.
- Do not classify individual ballots.
- Do not produce an authoritative report.

### 7.7. Counting Consistency

For each accepted snapshot record,
exactly one final classification applies:

- VALID
- INVALID

Define:

accepted_total = number of snapshot ballots

valid_total = number of valid ballots

invalid_total = number of invalid ballots

counted_total = valid_total

Mandatory checks:

accepted_total = valid_total + invalid_total

SUM(candidate_vote_count) = counted_total

Each accepted ballot contributes
at most one vote to candidate totals.

If consistency checks fail:

- Do not mark tally SUCCEEDED.
- Do not transition election to TALLIED.
- Investigate and preserve audit evidence.

### 7.8. Security and Design Limitations

Tally must use the trusted final snapshot,
not a live database query.

The frozen candidate catalog must also
be protected from unauthorized changes.

Its exact integrity binding to the
election snapshot or signed evidence
requires final cross-document review.

A valid snapshot signature does not
prove that the tally implementation
decrypted and counted every vote correctly.

The MVP provides restricted tallying
and consistency checks, not complete
end-to-end tally verifiability.

---

## 8. Tally Consistency Rules

Define:

- `accepted_total`: Number of records in the final accepted-ballot snapshot
- `valid_total`: Accepted ballots passing all required checks
- `invalid_total`: Accepted ballots failing one or more checks
- `counted_total`: Number of valid votes included in candidate totals

Mandatory invariants:

**TCR-01**

`accepted_total = valid_total + invalid_total`

**TCR-02**

`counted_total = valid_total`

**TCR-03**

`SUM(candidate_vote_count) = counted_total`

**TCR-04**

Each snapshot record contributes to exactly one of valid_total or invalid_total.

**TCR-05**

Tally must not modify the original accepted-ballot dataset.

### Example

- Accepted ballots: 100
- Valid ballots: 97
- Invalid ballots: 3
- Counted ballots: 97

- Candidate A: 40
- Candidate B: 35
- Candidate C: 22

Total counted: 97

These values are illustrative.

---

## 9. Tally Job Lifecycle

### 9.1. Objective

Manage restricted tally execution safely,
including authorization, concurrency,
failures, retries and result persistence.

The Tally Job status is separate from
the authoritative Election status.

### 9.2. Job States

Supported statuses:

- PENDING
- RUNNING
- SUCCEEDED
- FAILED

Allowed transitions:

PENDING -> RUNNING
RUNNING -> SUCCEEDED
RUNNING -> FAILED
RUNNING -> FAILED after crash recovery

A failed run is preserved for audit.
A retry creates a new tally attempt.

SUCCEEDED is terminal.

### 9.3. Preconditions

Tally execution requires:

1. Election status == CLOSED.
2. Authoritative snapshot == FINALIZED.
3. Snapshot digest verification succeeds.
4. Manifest signature verification succeeds.
5. Trusted signing key is available.
6. Independent evidence verification succeeds.
7. Frozen candidate catalog is available.
8. Tally Operator is authorized.
9. No authoritative successful tally
   already exists for the election.
10. No other active tally job exists
    for the same election.

If preconditions fail:
- Do not begin decryption.
- Do not mark election TALLIED.
- Return a controlled error.

### 9.4. Tally Execution

#### Job Claim Transaction

Before starting cryptographic operations:

1. Authenticate and authorize Tally Operator.
2. BEGIN database transaction.
3. Lock the authoritative election row.
4. Verify election status == CLOSED.
5. Verify snapshot status == FINALIZED.
6. Verify no successful tally already exists.
7. Check the current active tally job.
8. Reject if an active job has a valid lease.
9. If an old lease has expired, invalidate
   the abandoned job under the lock.
10. Increment the election fencing token.
11. Create a new Tally Job with:
    - tally_job_id
    - election_id
    - snapshot_digest
    - status = RUNNING
    - fencing_token
    - lease_until
12. Store active_tally_job_id on election.
13. Commit the claim transaction.

Only after a successful claim may
the Tally Process begin restricted work.

#### Restricted Execution

1. Load authoritative FINALIZED snapshot.
2. Verify snapshot and configuration evidence.
3. Unlock the restricted Tally private key.
4. Validate and decrypt encrypted ballots.
5. Calculate valid and invalid totals.
6. Calculate candidate vote counts.
7. Validate all consistency equations.
8. Construct deterministic aggregate report.
9. Calculate report digest.
10. Request atomic tally finalization.

During execution, the active worker
must periodically renew its job lease.

Lease renewal succeeds only if:
- The job is still RUNNING.
- The election references the same job.
- The fencing token still matches.
- The lease has not expired.

If renewal fails, the worker must stop
processing and must not finalize results.

Long-running decryption must not hold
a database transaction open.

Lease duration and renewal interval
will be defined in P01.3.

### 9.5. Atomic Tally Finalization

When counting is complete:

1. BEGIN database transaction.
2. Lock the authoritative election row.
3. Verify election status == CLOSED.
4. Verify the authoritative snapshot digest.
5. Verify active_tally_job_id matches
   the requesting job.
6. Verify the fencing token matches
   the current election fencing token.
7. Verify the job remains RUNNING.
8. Verify the job lease is still valid
   using authoritative database time.
9. Verify no successful tally already exists.
10. Verify the tally report digest.
11. Verify the counting equations.
12. Insert the authoritative tally report.
13. Mark the job SUCCEEDED.
14. Change election state to TALLIED.
15. Clear active_tally_job_id.
16. Insert a security audit event.
17. COMMIT transaction.

The report insertion, job success
and election transition must commit
in one authoritative transaction.

If the transaction fails:

- Roll back related writes.
- Do not claim successful tally.
- Do not publish partial results.

If the commit outcome is unknown,
the worker must query the authoritative
database before retrying finalization.

### 9.6. Concurrency and Idempotency

#### Single Active Job

At most one active Tally Job is permitted
for each election.

The authoritative election row tracks:

- active_tally_job_id
- tally_fencing_token

The detailed PostgreSQL schema will
enforce this using transactional locking
and appropriate constraints.

#### Fencing Token

Each newly authorized job receives
a monotonically increasing token.

For example:

Job A: token = 1

After Job A expires and is invalidated:

Job B: token = 2

If Job A resumes later, it must not
finalize because token 1 is stale.

A stale job must never overwrite or
replace a successful authoritative tally.

#### Successful Result Uniqueness

Only one authoritative successful
Tally Report is permitted per election.

Enforce this at the database level.

Repeated requests after success:

- Return the existing authoritative result
  or reject duplicate execution.
- Do not launch another authoritative tally.
- Do not add candidate counts again.

#### Snapshot Binding

Every Tally Job is associated with:

- election_id
- election_config_digest
- snapshot_digest
- algorithm_version

A job cannot switch snapshot inputs
during execution.

### 9.7. Failure and Crash Recovery

#### Expected Failures

- Invalid snapshot evidence
- Untrusted configuration
- Wrong private-key passphrase
- Worker process crash
- Database connection failure
- Lease expiration
- Report persistence failure
- Counting consistency failure

#### Worker Failure

If a worker fails:

- Do not transition election to TALLIED.
- Do not publish partial results.
- Record privacy-safe diagnostics.
- Mark the failed attempt FAILED
  when the authoritative database
  confirms it has not succeeded.

#### Lease Expiration

If the RUNNING worker stops renewing
its lease:

1. The lease eventually expires.
2. A recovery process checks database state.
3. Recovery locks the election row.
4. Recovery verifies the job identity,
   fencing token and lease expiration.
5. Recovery marks the abandoned job FAILED.
6. Recovery clears the active job reference.
7. A new authorized attempt may be claimed.

All recovery state changes must be
performed transactionally.

#### Stale Worker

If an old worker resumes after recovery:

- Its fencing token is no longer current.
- Lease renewal must fail.
- Atomic finalization must fail.
- It must not publish an authoritative result.

#### Recovery After Unknown Commit

If a worker loses its database connection
during tally finalization:

1. Reconnect to the authoritative database.
2. Read election status.
3. Read the authoritative tally result.
4. Read the original job status.
5. Determine whether finalization committed.

If finalization committed:
- Return the existing result.
- Do not rerun tally.

If finalization did not commit:
- Follow the controlled retry policy.
- Do not create competing authoritative
  results.

#### Integrity Failure

If snapshot or configuration verification
fails:

- Abort tally execution.
- Preserve security-safe failure evidence.
- Keep the election CLOSED.
- Do not automatically replace the
  authoritative FINALIZED snapshot.

#### Database Design Dependencies

P01.3 must define:

- Tally Job table
- Tally Report table
- active_tally_job_id
- tally_fencing_token
- lease_until
- Unique successful result constraint
- Active job concurrency constraints
- Required row locks and transactions

### 9.8. Audit and Security

Audit events should include:

- election_id
- tally_job_id
- snapshot_digest
- operator authorization outcome
- job start and completion
- failure category
- aggregate report digest

Audit logs must not contain:

- Private keys or passphrases
- Decrypted individual votes
- RA session tokens
- Identity-to-ballot mappings

Tally reports contain aggregate
counts only.

Successful aggregate counting does
not establish complete end-to-end
verifiability.

---

## 10. Tally Report Format

The report contains:

- tally_id
- election_id
- snapshot_digest
- accepted_total
- valid_total
- invalid_total
- counted_total
- candidate_counts
- algorithm_version
- tally_status
- report_digest
- election_config_digest

Example:

```json
{
  "report_version": 1,
  "tally_id": "<TALLY_UUID>",
  "election_id": "<ELECTION_UUID>",
  "election_config_digest": "<SHA256_HEX>",
  "snapshot_digest": "<SHA256_HEX>",
  "accepted_total": 100,
  "valid_total": 97,
  "invalid_total": 3,
  "counted_total": 97,
  "candidate_counts": [
    {"candidate_id": "CANDIDATE_A", "vote_count": 40},
    {"candidate_id": "CANDIDATE_B", "vote_count": 35},
    {"candidate_id": "CANDIDATE_C", "vote_count": 22}
  ],
  "algorithm_version": "tally-v1",
  "tally_status": "SUCCEEDED",
  "report_digest": "<SHA256_HEX>"
}
```

The digest must be calculated from the report payload excluding report_digest, according to Section 10.1. This example is schematic: all UUID and hash placeholders must be replaced with canonical values when running tests.

The report must not include:

- Voter identity
- Plaintext individual ballots
- Private keys
- RA authentication tokens
- Identity-to-ballot mappings

### 10.1. Canonical Tally Report Digest

The authoritative tally report uses
the following required payload fields:

- report_version
- tally_id
- election_id
- election_config_digest
- snapshot_digest
- accepted_total
- valid_total
- invalid_total
- counted_total
- candidate_counts
- algorithm_version
- tally_status

All counts are non-negative integers.

candidate_counts is sorted by candidate_id
ascending and includes every candidate
from the verified frozen configuration,
including candidates with zero votes.

Duplicate candidate IDs are rejected.

The authoritative successful report uses:

tally_status = "SUCCEEDED"

Before calculating the digest, verify:

accepted_total = valid_total + invalid_total

counted_total = valid_total

SUM(candidate_vote_count) = counted_total

The report_digest field is NOT included
in the data being hashed.

Define:

report_payload = report excluding report_digest

report_bytes = JCS(report_payload)

report_digest = SHA256(
    UTF8("EVOTE-TALLY-REPORT-v1") ||
    byte(0) ||
    report_bytes
)

Represent report_digest as lowercase
64-character hexadecimal text.

The stored authoritative report includes
the report_payload and report_digest.

Public verification must recompute the
digest using exactly these rules.

Any change to election configuration,
snapshot identity, candidate counts or
aggregate totals changes the report digest.

The report digest alone is not a
digital signature or proof of correct
cryptographic tallying.

---

## 11. Result Publication

### 11.1. Objective

Publish only approved aggregate election
results that correspond to the authoritative
successful tally and finalized snapshot.

Publication must be authenticated,
auditable and recoverable.

### 11.2. Preconditions

Result publication requires:

1. Election status == TALLIED.
2. Authorized Election Admin.
3. One authoritative successful Tally.
4. Tally report digest is valid.
5. Report snapshot_digest matches
   the FINALIZED snapshot.
6. Counting invariants hold.
7. No authoritative publication
   already exists for the election.

Individual decrypted votes must never
appear in publication artifacts.

### 11.3. Publication Manifest

#### Purpose

The Publication Manifest cryptographically
binds the approved aggregate Tally Report
to the verified frozen election configuration
and the authoritative FINALIZED snapshot.

The manifest is signed by the authorized
Snapshot/Evidence Publisher using the
dedicated Ed25519 evidence-signing key.

For the MVP, the same evidence-signing key
may sign snapshot and result manifests,
using different domain separators.

The key identifier must match the
snapshot_signing_key_id recorded in the
verified frozen election configuration.

#### Unsigned Manifest Schema

The unsigned manifest is:

{
  "manifest_version": 1,
  "election_id": "<ELECTION_UUID>",
  "election_config_digest": "<SHA256_HEX>",
  "snapshot_digest": "<SHA256_HEX>",
  "tally_report_digest": "<SHA256_HEX>",
  "accepted_total": 100,
  "valid_total": 97,
  "invalid_total": 3,
  "counted_total": 97,
  "publication_key_id": "<EVIDENCE_SIGNING_KEY_ID>",
  "signature_algorithm": "Ed25519"
}

The numeric values are illustrative.

All fields are required.

No unknown or duplicate JSON fields
are permitted.

The manifest must not contain:

- Individual decrypted ballots
- Voter identities
- RA issuance records
- Private keys
- Authentication tokens

#### Digest Binding

Before signing, Publisher verifies:

1. Election state == TALLIED.
2. Admin authorization is valid.
3. Authoritative Tally Report exists.
4. Tally Report status == SUCCEEDED.
5. Recalculated tally_report_digest matches.
6. election_config_digest matches the
   trusted frozen configuration.
7. snapshot_digest matches the
   authoritative FINALIZED snapshot.
8. The aggregate counts match the report.
9. Counting consistency equations hold.
10. The signing key ID matches the
    verified frozen configuration.

Any mismatch must reject publication.

#### Signing Procedure

Construct the unsigned manifest.

Canonicalize using RFC 8785 JCS.

signed_bytes =
    UTF8("EVOTE-RESULTS-v1") ||
    byte(0) ||
    JCS(unsigned_manifest)

signature = Ed25519.Sign(
    evidence_signing_private_key,
    signed_bytes
)

Encode the signature using Base64url
without padding.

The published manifest contains all
unsigned fields plus:

"signature": "<BASE64URL_SIGNATURE>"

The signature field itself is excluded
from signed_bytes.

#### Publication Rules

The signed manifest must be verified
before publication finalization.

The authoritative publication reference
must identify immutable report and
manifest artifacts.

Only one authoritative publication
is allowed per election.

A failed signing operation must not
transition the election to PUBLISHED.

The Public Board exposes the official
result only after the authoritative
PUBLISHED transaction commits.

### 11.4. Safe Publication Workflow

1. Admin reviews the aggregate results.
2. Admin requests publication.
3. Backend verifies authorization.
4. Backend verifies election is TALLIED.
5. Backend loads the authoritative tally.
6. Backend verifies report consistency.
7. Publisher prepares immutable report
   and manifest artifacts in staging.
8. Authorized component signs manifest.
9. Publisher verifies signature and digest.
10. Persist immutable publication artifacts.
11. Begin the authoritative DB transaction.
12. Lock the election row.
13. Recheck state and report identity.
14. Store the immutable artifact reference.
15. Transition election to PUBLISHED.
16. Record administrative audit event.
17. Commit the transaction.
18. Public Board serves the verified
    published aggregate artifacts.

The Public Board must check the
authoritative PUBLISHED state.

Staged artifacts are not public results.

### 11.5. Atomicity Boundary

The database transaction cannot make
external artifact storage fully atomic.

The design therefore uses:

- Immutable staged artifacts
- Digest verification
- Authoritative database references
- Publication-state gating
- Idempotent retry and reconciliation

A result is authoritative only when
the PUBLISHED transition commits
and references verified artifacts.

If the database transaction fails,
previously staged artifacts remain
non-authoritative.

If a committed artifact becomes
temporarily unavailable, Board must
report unavailability rather than
substituting a different report.

### 11.6. Publication Failure Recovery

If signing fails:

- Do not transition to PUBLISHED.
- Preserve a controlled error record.

If artifact storage fails:

- Do not transition to PUBLISHED.
- Retry after storage is restored.

If the DB transaction fails:

- Keep election TALLIED.
- Reconcile any orphaned artifacts.
- Do not claim successful publication.

If the HTTP response is lost after
successful commit:

- Read the authoritative election state.
- Return the existing publication metadata.
- Do not generate competing results.

If a publication already exists:

- Verify the referenced artifacts.
- Return the existing publication.
- Do not silently overwrite it.

### 11.7. Public Verification

Public Board exposes aggregate results
only when election state == PUBLISHED.

The Public Auditor obtains:

- Frozen election configuration
- Configuration signature
- FINALIZED snapshot
- Signed snapshot manifest
- Authoritative aggregate Tally Report
- Signed publication manifest
- Independently trusted verification key
- Independently preserved evidence

Verification procedure:

1. Verify the frozen configuration
   signature and trusted signing key.
2. Recalculate election_config_digest.
3. Verify the FINALIZED snapshot digest.
4. Verify the snapshot manifest signature.
5. Compare snapshot and configuration
   digest bindings.
6. Recalculate tally_report_digest
   according to Section 10.1.
7. Verify the Tally Report contains only
   the required supported fields.
8. Verify aggregate counting equations.
9. Verify candidate IDs and their counts
   against the frozen candidate catalog.
10. Extract the publication signature.
11. Remove the signature field to
    reconstruct unsigned_manifest.
12. Reconstruct signed_bytes using
    the EVOTE-RESULTS-v1 domain separator.
13. Verify Ed25519 signature using
    the independently trusted evidence
    signing public key.
14. Verify publication_key_id matches
    the frozen configuration.
15. Compare election_config_digest,
    snapshot_digest and tally_report_digest
    across all corresponding artifacts.
16. Compare the publication totals
    with the authoritative Tally Report.
17. Verify independently preserved
    evidence when available.

Verification outcomes:

PASS:
All mandatory integrity, signature and
cross-artifact consistency checks succeed.

FAIL:
A mandatory integrity or consistency
check fails.

UNVERIFIED:
Required trusted evidence or keys
are unavailable.

A PASS result establishes consistency
of the published artifacts under
the stated trust assumptions.

It does not independently prove that
the restricted Tally implementation
correctly decrypted every ballot.

The MVP does not claim full end-to-end
verifiable electronic voting.

### 11.8. Privacy and Audit

Published information must exclude:

- Individual decrypted vote values
- Voter identities
- RA credential issuance records
- Authentication tokens
- Tally private keys
- Identity-to-ballot mappings

Record authorized publication events
and controlled failures in audit logs.

The public report contains only
approved aggregate election results.

---

## 12. Error Handling

| Scenario | Expected Behavior |
|---|---|
| Close DRAFT election | Reject |
| Close already CLOSED election | Reject |
| Submit after CLOSED | Reject |
| Run Tally during OPEN | Reject |
| Missing final snapshot | Do not start Tally |
| Snapshot digest mismatch | Abort Tally |
| Invalid snapshot signature | Abort Tally |
| Wrong private key or passphrase | Fail job |
| One invalid ciphertext | Count ballot as invalid |
| Unknown candidate after decryption | Count ballot as invalid |
| Tally process crashes | Election remains CLOSED |
| Repeat successful Tally | No double counting |
| Publish before TALLIED | Reject |
| Publication signing fails | Do not mark PUBLISHED |

An invalid individual ballot does not automatically invalidate all other accepted ballots.

A corrupted or untrusted final snapshot does invalidate the tally input and must stop the tally.

---

## 13. Security Audit

Record security-safe events for:

- Election closing
- Unauthorized closing attempts
- Final snapshot creation
- Snapshot verification failure
- Tally job start
- Tally key-unlock failure
- Tally job completion or failure
- Result publication
- Unauthorized access attempts

Audit logs must not contain:

- Private key material
- Key passphrases
- Plaintext vote choices
- Individual decrypted vote values
- RA authentication tokens

Admin audit, RA audit and Voting audit must not create an identity-to-ballot mapping.

---

## 14. Security Invariants

**TALLY-01:** Tally cannot run before CLOSED.

**TALLY-02:** Voting cannot access the Tally private key.

**TALLY-03:** Tally uses the verified final snapshot.

**TALLY-04:** Snapshot verification failure aborts tallying.

**TALLY-05:** AES-GCM authentication must pass before a decrypted ballot is considered valid.

**TALLY-06:** Candidate IDs must belong to the election.

**TALLY-07:** Accepted totals must equal valid plus invalid totals.

**TALLY-08:** Candidate counts must sum to counted_total.

**TALLY-09:** Tally cannot modify accepted-ballot records.

**TALLY-10:** Plaintext individual votes are not published.

**TALLY-11:** Failed tally jobs do not transition the election to TALLIED.

**TALLY-12:** Repeated tally execution does not double-count votes.

---

## 15. Planned Tests

| Test ID | Scenario | Expected Result |
|---|---|---|
| TALLY-T01 | Close valid OPEN election | CLOSED |
| TALLY-T02 | Close already CLOSED election | Rejected |
| TALLY-T03 | Submit after CLOSED | Rejected |
| TALLY-T04 | Run tally in OPEN | Rejected |
| TALLY-T05 | Run tally in CLOSED | Success |
| TALLY-T06 | Use wrong key passphrase | Job failed |
| TALLY-T07 | Decrypt valid ballot | Counted |
| TALLY-T08 | Decrypt corrupted ciphertext | Invalid |
| TALLY-T09 | Unknown candidate ID | Invalid |
| TALLY-T10 | Invalid snapshot digest | Tally aborted |
| TALLY-T11 | Invalid snapshot signature | Tally aborted |
| TALLY-T12 | Count valid and invalid ballots | Consistency PASS |
| TALLY-T13 | Repeat completed tally | No double counting |
| TALLY-T14 | Simulate tally process crash | Election remains CLOSED |
| TALLY-T15 | Publish before TALLIED | Rejected |
| TALLY-T16 | Publish approved results | PUBLISHED |
| TALLY-T17 | Inspect logs for plaintext votes | None found |
| TALLY-T18 | Voting attempts to read Tally key | Access denied |

---

## 16. Open Decisions and Acceptance Criteria

### Remaining Design Decisions

**DR-02:** Finalize RA issuance versus election-closing concurrency.

**DR-03:** Finalize snapshot creation, signing and independent integrity evidence.

**DR-04:** Finalize restricted key storage and unlocking.

**OD-13:** Define the final ballot acceptance ordering.

**OD-15:** Define the Tally Process execution environment.

**OD-16:** Define operator approval and key-unlock permissions.

**OD-17:** Define failure recovery and publication atomicity.

### Acceptance Criteria

- Election closing workflow is defined
- Concurrent acceptance and closing rules are documented
- Final snapshot preparation is defined
- Tally authorization policy is documented
- Private-key handling is documented
- Ballot decryption and validation are specified
- Counting equations are defined
- Tally job lifecycle is specified
- Result publication is documented
- Error handling and negative tests are defined
- Remaining security limitations are tracked

**Status: DESIGN DRAFT — IMPLEMENTATION NOT STARTED**
