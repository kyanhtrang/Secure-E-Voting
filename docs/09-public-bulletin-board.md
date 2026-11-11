# Secure E-Voting System
## 09 - Public Bulletin Board & Receipt Verification

- **Version:** 1.0
- **Status:** Draft
- **Phase:** P01.2.4

---

## 1. Objective

Design a public, read-only bulletin board that supports:

- Publication of accepted encrypted ballots
- Deterministic receipt verification
- Final ballot snapshots
- SHA-256 integrity verification
- Ed25519 snapshot authentication
- Independent preservation of verification evidence
- Privacy-preserving public access

Related Use Cases:

- UC-08: Submit Encrypted Ballot
- UC-09: Verify Receipt
- UC-11: Execute Tally
- UC-13: Verify Public Snapshot

Security Requirements:

- SR-01: Conditional anonymity
- SR-04: Ballot integrity and inclusion
- SR-06: Secure storage
- SR-07: Authorized election lifecycle

---

## 2. System Components

### 2.1 Voting Service

Responsibilities:

- Verify encrypted ballot submissions
- Insert accepted ballots atomically
- Calculate deterministic receipt hashes
- Store receipt and ballot in the same transaction
- Return receipt only after commit

### 2.2 Voting Database

Stores:

- Election ID
- Ballot ID
- Serial
- Encrypted envelope
- Prepared message
- Finalized blind signature
- Envelope hash
- Receipt hash
- Acceptance metadata

Voting DB must not store voter identities or plaintext choices.

### 2.3 Public Board Service

Responsibilities:

- Expose accepted ballot records through GET APIs
- Support receipt lookup
- Serve published snapshots and manifests
- Provide public verification metadata

Public Board must not have permission to modify accepted ballots.

### 2.4 Snapshot Publisher

Responsibilities:

- Build deterministic snapshots
- Calculate SHA-256 digests
- Create and sign snapshot manifests
- Publish verification artifacts

Snapshot signing keys must be separate from RA and Tally private keys.

### 2.5 Independent Auditor

Responsibilities:

- Download public verification artifacts
- Recompute snapshot digests
- Verify digital signatures
- Compare hashes with independently preserved evidence
- Report verification outcomes

---

## 3. Board Publication Policy

### During OPEN

- Accepted ballot records are readable after database commit.
- Users may search for their receipt hashes.
- Records remain encrypted.
- No candidate selection is disclosed.
- Final signed snapshot is not yet available.

### During CLOSED

- New ballot submissions are rejected.
- Accepted ballot dataset is frozen.
- Final snapshot is generated.
- Snapshot digest and signature are created.
- The final snapshot is made available for verification.

### During TALLIED

- Public encrypted ballots remain accessible.
- Final snapshot remains unchanged.
- Tally results remain unpublished.

### During PUBLISHED

- Approved aggregate results are available.
- Final snapshot and signed manifests remain accessible.
- Public auditors may verify the published evidence.

Public Board does not authenticate voter identity.

---

## 4. Public Ballot Record

A public ballot record contains:

- election_id
- serial
- envelope
- prepared_msg
- signature
- receipt_hash

The envelope contains encrypted ballot data only.

Public records must not contain:

- voter_id
- username
- password
- RA session token
- plaintext candidate_id
- Tally private key
- Full IP address
- Precise identity-correlating timestamps

The public record must be sufficient to independently recompute and validate the receipt according to Document 08.

---

## 5. Receipt Verification

Receipt construction follows:

`docs/08-encryption-ballot-submission.md`

The existing receipt definition must be reused without modification.

### Main Flow

1. Voter submits an encrypted ballot.
2. Voting validates and commits the ballot.
3. Voting returns the deterministic receipt hash.
4. Client stores the receipt locally.
5. Voter opens the Public Board.
6. Voter enters the receipt hash.
7. Board searches committed accepted ballots.
8. Board returns the matching public record.
9. Client independently recalculates the receipt hash.
10. Client compares both values.
11. Client displays the verification result.

### Verification Outcomes

**FOUND**

A matching accepted record exists and its receipt hash can be recomputed.

**NOT_FOUND**

No matching accepted record is currently available.

**MISMATCH**

A returned record does not reproduce the expected receipt hash.

**UNAVAILABLE**

The Public Board cannot complete the query.

A NOT_FOUND result does not, by itself, prove that the ballot was rejected or lost.

Finding a receipt proves only the limited inclusion property supported by the observed Board response.

---

## 6. Public Board API Contract

All endpoints use the `/api/v1` prefix.

### GET /board/{election_id}/ballots

Purpose: Retrieve paginated accepted ballot records.

Query parameters:

- limit
- cursor

Returns:

- election_id
- records
- next_cursor

Only committed accepted records may be returned.

### GET /board/{election_id}/receipts/{receipt_hash}

Purpose: Look up a public ballot record by receipt hash.

HTTP 200: Matching record found

HTTP 404: No matching record currently available

HTTP 503: Board temporarily unavailable

The client independently validates the returned record.

### GET /board/{election_id}/snapshots/final

Purpose: Retrieve final snapshot metadata and the published snapshot.

Available only after final snapshot publication.

### GET /board/{election_id}/snapshots/final/manifest

Purpose: Retrieve the signed manifest.

### GET /board/{election_id}/results

Purpose: Retrieve aggregate results after PUBLISHED.

No public POST, PUT, PATCH or DELETE endpoint is provided by the Board Service.

---

## 7. Final Snapshot Construction

### 7.1. Objective

Create one authoritative final snapshot
containing all committed accepted ballots
for a closed election.

The finalized snapshot is the only
authoritative input for restricted Tally.

### 7.2. Preconditions

Before snapshot construction:

1. Election status must be CLOSED.
2. Election closing transaction must commit.
3. No new ballot acceptance is permitted.
4. Previously accepted ballot transactions
   must have completed.
5. The caller must be authorized.
6. No authoritative FINALIZED snapshot
   may already exist for this election.

The Snapshot Publisher must not use
uncommitted or partially written ballots.

### 7.3. Snapshot State Machine

Snapshot publication uses three statuses:

- PREPARING
- FINALIZED
- FAILED

Allowed transitions:

PREPARING -> FINALIZED
PREPARING -> FAILED
FAILED -> PREPARING (new attempt)

FINALIZED is terminal.

Only one authoritative FINALIZED snapshot
is permitted per election.

A failed attempt must never replace
an existing FINALIZED snapshot.

### 7.4. Canonical Snapshot Format

The snapshot contains:

{
  "schema_version": 1,
  "election_id": "<ELECTION_UUID>",
  "election_config_digest": "<SHA256_HEX>",
  "ballots": []
}

Each item in ballots follows the public
accepted-ballot record format defined
in Section 4 of this document.

Receipt construction must remain identical
to Document 08.

The snapshot excludes:

- voter_id
- username
- RA request_id
- plaintext candidate_id
- Tally private key
- Identity-correlating timestamps

### 7.5. Deterministic Construction

Snapshot Publisher performs:

1. Verify election is CLOSED.
2. Create or resume a controlled
   snapshot preparation attempt.
3. Read all committed accepted ballots
   using a consistent database view.
4. Convert every ballot to its defined
   public record format.
5. Recompute each receipt hash.
6. Verify the record count.
7. Sort records by receipt_hash ascending.
8. Reject duplicate or inconsistent
   snapshot record identifiers.
9. Construct the snapshot object.
10. Serialize with RFC 8785 JCS.
11. Compute SHA-256 digest.

Formula:

snapshot_bytes = JCS(snapshot)

snapshot_digest = SHA256(snapshot_bytes)

Represent snapshot_digest as lowercase
64-character hexadecimal text.

Do not add nondeterministic fields,
such as generation timestamps,
to the canonical snapshot object.

The same frozen input dataset must
produce exactly the same digest.

### 7.6. Safe Finalization

The system must not expose an incomplete
snapshot as authoritative.

Proposed procedure:

1. Construct snapshot bytes.
2. Write snapshot to private staging storage.
3. Compute and verify snapshot digest.
4. Create and sign the manifest.
5. Verify the manifest signature.
6. Preserve independent integrity evidence.
7. Atomically record the finalized snapshot
   reference in the authoritative database.
8. Mark the snapshot FINALIZED.
9. Expose only verified finalized artifacts
   through Public Board.

The authoritative database reference must
identify the exact immutable artifact bytes.

Staging artifacts are not public evidence.

Database transactions and external file
storage are not automatically atomic.

Recovery must reconcile orphaned staging
artifacts instead of claiming that one
database transaction protects both systems.

### 7.7. Concurrent Snapshot Requests

If multiple publishers attempt to create
a final snapshot for the same election:

- Coordinate through a database lock
  and uniqueness constraints.
- Permit at most one authoritative
  FINALIZED snapshot.
- Do not publish competing final digests.
- A repeated request for an already
  finalized snapshot returns its existing
  metadata without rebuilding it.

If a preparation attempt fails:

- Mark the attempt FAILED when possible.
- Keep election state CLOSED.
- Do not produce an authoritative snapshot.
- Allow a controlled retry after recovery.

### 7.8. Frozen Election Configuration Binding

The final snapshot must be bound to the
immutable election configuration created
before the election transitioned to OPEN.

The configuration format and signing
rules are defined in Document 06.

Before snapshot finalization:

1. Load the frozen election configuration.
2. Verify its schema and election_id.
3. Verify its Ed25519 signature using
   an independently trusted public key.
4. Recalculate SHA256(JCS(configuration)).
5. Compare the computed digest with the
   authoritative election_config_digest.
6. Verify the frozen candidate catalog.
7. Verify the assigned RA, Tally and
   snapshot signing public-key fingerprints.
8. Include election_config_digest in
   the canonical snapshot object.
9. Include the same digest in the
   signed snapshot manifest.

The snapshot and manifest must contain
identical election_config_digest values.

The configuration digest must not be
recomputed from mutable live candidate
records after the election is OPEN.

If configuration verification fails:

- Do not mark the snapshot FINALIZED.
- Do not expose it as authoritative.
- Record a controlled integrity failure.
- Keep the election CLOSED.

The frozen configuration and its
signature must remain available
for independent verification.

---

## 8. Signed Snapshot Manifest

### 8.1. Purpose

The manifest binds the final snapshot
digest to an election, a ballot count
and an authorized signing key.

The manifest uses:

- SHA-256
- Ed25519
- RFC 8785 JCS
- Base64url without padding for signatures

The snapshot signing key must be
independent from RA and Tally keys.

### 8.2. Unsigned Manifest Format

Example:

{
  "manifest_version": 1,
  "election_id": "<ELECTION_UUID>",
  "election_config_digest": "<SHA256_HEX>",
  "snapshot_schema_version": 1,
  "snapshot_digest": "<SHA256_HEX>",
  "ballot_count": 100,
  "digest_algorithm": "SHA-256",
  "signature_algorithm": "Ed25519",
  "signing_key_id": "snapshot-key-01"
}

The unsigned manifest must not contain
a signature field.

All fields are required.

The manifest must reference exactly
one final snapshot.

### 8.3. Signing Procedure

Snapshot Publisher performs:

1. Build the unsigned manifest.
2. Serialize it using JCS.
3. Construct the signed input bytes.
4. Sign using the dedicated Ed25519
   private key.
5. Encode the signature using Base64url
   without padding.
6. Add the signature to the published
   manifest representation.

Signed bytes:

signed_bytes =
    UTF8("EVOTE-SNAPSHOT-v1") ||
    byte(0) ||
    JCS(unsigned_manifest)

signature = Ed25519.Sign(
    snapshot_private_key,
    signed_bytes
)

The signature covers the unsigned
manifest fields, including the digest,
election ID and ballot count.

The signature field itself is excluded
from signed_bytes.

### 8.4. Verification Procedure

Public Auditor performs:

1. Download snapshot and manifest.
2. Validate the required schemas.
3. Extract signature from manifest.
4. Reconstruct unsigned_manifest.
5. Canonicalize snapshot using JCS.
6. Recompute SHA-256 snapshot digest.
7. Compare digest to the manifest.
8. Compare ballot count to snapshot.
9. Confirm election_id and versions.
10. Obtain the trusted Ed25519 public key.
11. Reconstruct signed_bytes.
12. Verify the Ed25519 signature.
13. Compare with independently preserved
    evidence when available.

Possible results:

PASS:
Digest, schema and signature checks
succeed under a trusted public key.

FAIL:
A required integrity check fails.

UNVERIFIED:
Verification cannot establish trust,
for example because the trusted key
is unavailable.

A valid signature alone does not prove
that all eligible voters participated
or that every attempted vote was accepted.

### 8.5. Public Key Trust

The signing_key_id identifies the expected
snapshot verification key.

The Public Board may serve a copy of
the corresponding public key.

However, the auditor must not trust
that key solely because the same Board
provided it.

For the MVP, publish and independently
preserve a trusted public-key fingerprint
through an auditor-controlled channel.

The Auditor must compare the fingerprint
or use a previously trusted public key.

A substituted Board key must not be
silently accepted as trusted.

### 8.6. Publication and Failure Rules

Only a FINALIZED snapshot may be exposed
as the official final snapshot.

If signing fails:

- Do not mark the snapshot FINALIZED.
- Do not expose a final manifest.
- Record a controlled failure.

If signature verification fails:

- Reject finalization.
- Preserve diagnostic metadata.
- Do not publish the artifact as valid.

If the process crashes during staging:

- Recover or discard uncommitted artifacts
  using the documented recovery procedure.
- Do not mark the snapshot FINALIZED
  without verifying the stored bytes.

If a FINALIZED snapshot already exists:

- Return the existing authoritative digest.
- Do not silently regenerate or overwrite it.

Tally must verify the finalized snapshot
and manifest before decrypting ballots.

### 8.7. Configuration Cross-Verification

During final snapshot verification,
the Auditor must also verify the
frozen election configuration.

Required checks:

1. Verify the configuration signature.
2. Verify the trusted configuration
   signing public key.
3. Recalculate election_config_digest.
4. Compare the digest with the snapshot.
5. Compare the digest with the manifest.
6. Verify the frozen candidate catalog
   and cryptographic key assignments.

If a required comparison fails,
the verification result must be FAIL.

If trusted configuration evidence
is unavailable, the result must
not be reported as PASS.

A valid snapshot signature cannot
replace configuration verification.

---

## 9. Independent Integrity Evidence

### 9.1. Objective

Preserve independently verifiable evidence
of the finalized election snapshot.

The purpose is to detect unauthorized
modifications or inconsistent publication
after trusted evidence has been preserved.

The mechanism must not rely exclusively
on records stored in Voting Database
or served by Public Bulletin Board.

### 9.2. Evidence Package

Each finalized election snapshot has
an independent verification package.

Required contents:

- election_id
- snapshot_digest
- ballot_count
- snapshot_schema_version
- signed_manifest
- manifest_signature
- signing_key_id
- trusted_public_key_fingerprint
- evidence_format_version
- election_config_digest
- frozen_election_configuration
- configuration_signature
- trusted_configuration_key_fingerprint

The evidence package must not contain:

- voter_id
- username
- RA access token
- plaintext candidate_id
- private cryptographic keys
- identity-to-ballot mappings

The snapshot_digest must be computed
from the canonical snapshot bytes
defined in Section 7.

The signed manifest must follow
the signature format in Section 8.

The Auditor must preserve the exact
frozen configuration bytes and signature.

The configuration evidence must match
the election_config_digest referenced
by the finalized snapshot and manifest.

The configuration signing key must be
verified against an independently
trusted key or fingerprint.

A configuration returned solely by
the potentially compromised Board
must not be trusted without verification.

### 9.3. Independent Preservation

For the local MVP, use an
Auditor-controlled evidence directory
outside the application repository
and outside Board publication storage.

The directory must have separate
write permissions from the Voting
and Public Board processes.

Recommended procedure:

1. Snapshot Publisher constructs
   the final snapshot in staging.
2. Publisher calculates the digest.
3. Publisher signs the manifest.
4. Publisher verifies the signature.
5. Auditor receives the evidence package.
6. Auditor verifies the signature using
   a previously trusted public key.
7. Auditor preserves an independent copy.
8. Publisher receives confirmation
   that evidence preservation succeeded.
9. Publisher records the finalized
   snapshot reference and marks
   the snapshot FINALIZED.
10. Public Board exposes the verified
    finalized snapshot.

The independently preserved package
must not be silently overwritten.

For the MVP demonstration, a separate
Auditor-controlled directory is acceptable.

However, storing both copies on the
same physical computer does not protect
against compromise of that entire host.

An offline or separately administered
storage location provides stronger
separation.

### 9.4. Verification Against Evidence

Auditor performs:

1. Load the independently preserved
   evidence package.
2. Obtain the trusted signing public key.
3. Verify the preserved manifest signature.
4. Download the current public snapshot.
5. Validate the snapshot schema.
6. Canonicalize the snapshot using JCS.
7. Recompute SHA-256 snapshot digest.
8. Compare the digest against the
   independently preserved digest.
9. Compare election_id and ballot_count.
10. Verify the current published manifest.
11. Confirm that the current manifest
    matches the preserved evidence.
12. Produce a verification report.

Possible outcomes:

PASS:
All required digest, schema, signature
and independent-evidence comparisons pass.

FAIL:
At least one required integrity check
or evidence comparison fails.

UNVERIFIED:
Trusted evidence or verification keys
are unavailable or insufficient.

A successful verification establishes
consistency with the trusted preserved
snapshot evidence.

It does not prove that every attempted
vote was accepted or correctly tallied.

### 9.5. Tampering Demonstration

The MVP must demonstrate detection
of post-finalization modification.

Test procedure:

1. Prepare a test election.
2. Accept several encrypted ballots.
3. Close the election.
4. Generate the final snapshot.
5. Preserve trusted independent evidence.
6. Verify the original snapshot.

Expected initial result:
PASS

7. Create a modified copy of the snapshot.
8. Alter one encrypted ballot record
   or remove one ballot from the copy.
9. Recalculate the modified snapshot digest.
10. Verify the modified snapshot against
    the preserved evidence.

Expected result:
FAIL

The demonstration must not modify
the production authoritative snapshot.

Additional scenarios:

- Modify the published manifest.
- Replace the manifest signature.
- Use an untrusted public key.
- Remove the independent evidence package.
- Attempt to publish a different final
  snapshot for the same election.

Expected results:

- Modified snapshot: FAIL
- Modified signed manifest: FAIL
- Invalid signature: FAIL
- Untrusted public key: UNVERIFIED
- Missing trusted evidence: UNVERIFIED
- Competing finalized snapshot: Rejected

### 9.6. Failure and Recovery Policy

If evidence preservation fails:

- Do not mark the snapshot FINALIZED.
- Do not expose incomplete final evidence.
- Preserve operational failure metadata.
- Keep the election CLOSED.
- Allow a controlled recovery attempt.

If stored snapshot bytes fail verification:

- Reject the artifact.
- Do not silently recompute a new
  authoritative snapshot.
- Do not start Tally using that artifact.

If a FINALIZED snapshot already exists:

- Reuse its authoritative reference.
- Verify the stored bytes and signature.
- Do not overwrite the snapshot.

If independent evidence is unavailable:

- Return UNVERIFIED.
- Do not claim integrity verification PASS.

If the signing private key or trusted
verification key is compromised:

- Treat affected verification evidence
  as requiring security investigation.
- Do not silently substitute another key.
- Record the incident for audit review.

### 9.7. Security Limitations

Independent evidence can detect certain
changes made after the trusted snapshot
was preserved.

It cannot automatically detect:

- Ballots omitted before snapshot creation
- Valid attempts rejected by a malicious
  Voting Service
- Incorrect decryption or tally logic
- Compromise of the trusted signing key
  before evidence preservation
- Collusion between all trusted parties
- Voter coercion or compromised clients

Signed snapshots support integrity and
limited public auditability.

They do not provide complete end-to-end
verifiable electronic voting.

---

## 10. Data Storage and Permissions

### Voting Database

Stores accepted ballot records.

Voting Service:

- Insert accepted ballots
- Read necessary election metadata
- No unrestricted update/delete permissions for accepted records

### Board Service

- SELECT on approved public data
- No INSERT, UPDATE or DELETE privileges

### Snapshot Publisher

- Read frozen accepted records
- Write signed publication artifacts using a restricted workflow
- Access only the dedicated snapshot signing key

### Public Auditor

- Read public records
- Read signed manifests
- Verify evidence using trusted public keys
- No database write access

Database roles and security-zone separation will be finalized in P01.3 and P01.5.

---

## 11. Privacy Considerations

Public Board must not expose a direct mapping between voter identity and encrypted ballot.

Controls:

- No RA login token on Board requests
- No identity cookies shared between RA and Board
- No analytics or cross-service identity tracking
- Minimize access logs and correlation metadata
- Avoid publishing unnecessary precise acceptance timestamps
- Never publish plaintext vote choices

Receipt hashes are verification identifiers, not authentication credentials.

Publishing or sharing a receipt may link an individual to a particular encrypted ballot record.

The MVP does not guarantee anonymity against complete traffic correlation or collusion.

---

## 12. Failure Handling

### Receipt Not Found

Return NOT_FOUND.

Do not claim the ballot was definitively rejected.

### Board Unavailable

Return UNAVAILABLE.

Client retains local receipt data.

### Snapshot Digest Mismatch

Mark verification as FAIL.

Do not silently replace the trusted reference digest.

### Invalid Manifest Signature

Mark verification as FAIL.

### Untrusted Verification Key

Mark verification as UNVERIFIED.

### Snapshot Publication Failure

Do not claim final snapshot publication succeeded.

Preserve the existing election state and record a security-safe operational failure.

Recovery and publication atomicity will be finalized in P01.2.6.

---

## 13. Security Invariants

**BOARD-01:** Public Board exposes no voter identity.

**BOARD-02:** Public Board exposes no plaintext candidate selection.

**BOARD-03:** Only committed accepted ballots appear on Board.

**BOARD-04:** Public Board API is read-only.

**BOARD-05:** Receipt construction is deterministic.

**BOARD-06:** Receipt validation recomputes the expected hash.

**BOARD-07:** Final snapshot contains the frozen accepted-ballot dataset.

**BOARD-08:** Snapshot serialization is deterministic.

**BOARD-09:** Manifest signature uses a dedicated signing key.

**BOARD-10:** Snapshot verification requires a trusted public key.

**BOARD-11:** Independently preserved evidence is not stored solely in the same database.

**BOARD-12:** Receipt inclusion does not imply correct tallying.

---

## 14. Planned Tests

| Test ID | Scenario | Expected Result |
|---|---|---|
| BOARD-T01 | Search valid receipt | FOUND |
| BOARD-T02 | Search unknown receipt | NOT_FOUND |
| BOARD-T03 | Recompute receipt hash | MATCH |
| BOARD-T04 | Modify public record | MISMATCH |
| BOARD-T05 | Access Board without login | Allowed |
| BOARD-T06 | Attempt public POST | Rejected |
| BOARD-T07 | Attempt public DELETE | Rejected |
| BOARD-T08 | Inspect public fields | No voter identity |
| BOARD-T09 | Generate snapshot twice | Same digest |
| BOARD-T10 | Modify snapshot | Digest FAIL |
| BOARD-T11 | Verify valid manifest | PASS |
| BOARD-T12 | Verify altered manifest | FAIL |
| BOARD-T13 | Verify with untrusted key | UNVERIFIED |
| BOARD-T14 | Modify DB after independent snapshot preservation | Integrity mismatch |
| BOARD-T15 | Request unpublished results | Rejected |
| BOARD-T16 | Lose ballot submission response | Reconcile via Board |

---

## 15. Open Design Decisions

**DR-03:** Finalize snapshot publication and independent integrity anchoring.

**OD-09:** Confirm receipt schema interoperability with Document 08.

**OD-14:** Define final snapshot freezing and atomic publication.

**OD-17:** Define recovery from interrupted publication.

**OD-19:** Define public versus restricted audit information.

Additional decisions:

- Snapshot file storage format
- Public Board pagination guarantees
- Long-term evidence retention
- Exact permissions for Snapshot Publisher

---

## 16. Acceptance Criteria

- Public Board responsibilities documented
- Public API contract defined
- Receipt verification workflow defined
- Snapshot canonicalization defined
- Signed manifest format defined
- Public-key trust requirement documented
- Independent evidence requirement documented
- Privacy controls documented
- Negative tests documented
- Security limitations stated explicitly

**Status: DESIGN DRAFT — IMPLEMENTATION NOT STARTED**
