# Secure E-Voting System
## 11 - Concurrency, Recovery & Security Review

- **Version:** 1.0
- **Status:** Design Review Draft
- **Phase:** P01.2.6

---

## 1. Objective

Resolve critical workflow decisions before database and API implementation.

This document reviews:

- Concurrent ballot acceptance
- Election closing consistency
- Blind credential issuance recovery
- Public receipt and snapshot consistency
- Private key management
- Identity and ballot privacy separation
- Tally and publication failure recovery
- Residual security risks

Related documents: 06, 07, 08, 09 and 10.

---

## 2. Decision Register

This register summarizes the current
technical design decisions for the MVP.

"Specified" means the design is documented.
It does NOT mean the implementation has
been developed or security-tested.

| ID | Decision | Status | Reference |
|---|---|---|---|
| DR-01 | Idempotent blind credential issuance | Specified | Doc 07 |
| DR-02 | Election state, locking and RA boundary | Partial | Docs 06, 07, 08 |
| DR-03 | Receipt, final snapshot and evidence | Specified | Docs 08, 09 |
| DR-04 | Separate RA, Tally and evidence keys | Specified | Docs 06, 07, 10 |
| DR-05 | Identity and ballot session separation | Specified | Docs 07, 08, 09 |
| DR-06 | Server-side election deadlines | Specified | Docs 06, 08 |
| DR-07 | Tally and publication failure recovery | Specified | Doc 10 |
| DR-08 | Frozen election configuration | Specified | Docs 06, 09, 10 |
| DR-09 | Digest-bound tally report and signed publication manifest | Specified | Doc 10 |
| DR-10 | Tally lease and fencing token | Specified | Doc 10 |

### 2.1. Design Status Definitions

SPECIFIED:
The technical approach is documented,
but implementation and tests are pending.

PARTIAL:
A documented design limitation or
unresolved coordination problem remains.

IMPLEMENTED:
The corresponding code and database
controls have been developed.

VERIFIED:
The implementation has passed the
required functional and security tests.

No decision may be marked IMPLEMENTED
or VERIFIED based only on documentation.

### 2.2. Outstanding Design Limitations

DR-02 remains PARTIAL because RA and
Voting use separate databases.

Election row locking does not provide
an atomic transaction across both services.

An RA issuance authorized before
election closure may finish afterward.

Voting still rejects new ballots when
the election is CLOSED or past deadline.

The following implementation details
also remain pending:

- RA recovery metadata retention period
- Client encrypted recovery storage
- Exact PostgreSQL role permissions
- Tally lease duration and renewal interval
- Immutable artifact storage implementation
- Trusted key distribution and backup policy
- Security test vectors for message encoding

These dependencies must be tracked
during database, API and security design.

### 2.3. MVP Security Claims

The MVP aims to provide:

- Authenticated and controlled eligibility
- One blind credential issuance per voter
- Encrypted ballot submission
- Single-use ballot serial enforcement
- Election lifecycle enforcement
- Restricted decryption and tallying
- Signed integrity evidence
- Public receipt verification
- Aggregate result publication

The MVP does not claim:

- Complete end-to-end verifiability
- Guaranteed anonymity against all
  network or metadata correlation
- Coercion resistance
- Protection against fully colluding
  trusted administrators
- Production-grade HSM-level key security

The final report must distinguish
design goals from implemented and
experimentally verified guarantees.

---

## 3. DR-01 - Blind Issuance Recovery

### Decision

Use idempotent credential issuance.

RA enforces:

`UNIQUE(voter_id, election_id)`

Client generates a random `request_id` and persists the complete original blinded request and unblinding state in protected local storage.

RA stores:

- voter_id
- election_id
- request_id
- blinded_request_hash
- protected_blind_signature
- ra_key_id
- issued_at

### First Issuance

1. Authenticate voter.
2. Verify eligibility.
3. Verify issuance is authorized.
4. Lock the corresponding eligibility record.
5. Check whether an issuance already exists.
6. Blind-sign the request.
7. Store the issuance and recoverable response.
8. Commit.
9. Return the blind signature.

### Exact Retry

If the same authenticated voter retries with the same request ID and blinded message:

- Retrieve the existing record.
- Verify the original request hash.
- Return the previously issued signature.
- Do not generate another signature.

### Different Request

Reject with HTTP 409.

### Retry After CLOSED

An exact retry may retrieve a previously committed signature during the documented recovery period.

This is not a new issuance.

The credential cannot authorize a new accepted ballot after the voting deadline or CLOSED state.

### Limitations

- Client recovery state must be protected.
- Lost blinding state may prevent recovery.
- Recovery metadata requires a retention policy.
- A second independent credential is never automatically issued.

### Required Tests

- Exact request retry
- Different request retry
- Concurrent issuance
- Lost-response recovery
- Retry after CLOSED
- Client recovery-state loss

---

## 4. DR-02 - Election State Consistency

### Authoritative State

The Election Service owns election state in Voting DB.

Allowed lifecycle:

`DRAFT → OPEN → CLOSED → TALLIED → PUBLISHED`

RA reads authoritative state through an authenticated internal API.

Voting reads authoritative state directly within its database transaction.

### Ballot Acceptance

1. Validate request cryptography.
2. Begin transaction.
3. Lock the election row using SELECT FOR UPDATE.
4. Verify OPEN status.
5. Verify the server-side deadline.
6. Insert the accepted ballot.
7. Enforce UNIQUE(election_id, serial).
8. Commit.
9. Return HTTP 201.

### Election Closing

1. Begin transaction.
2. Lock the same election row.
3. Verify OPEN status.
4. Update state to CLOSED.
5. Record audit event.
6. Commit.

### Ordering Guarantee

If ballot acceptance acquires the lock first and commits, it is accepted before closure.

If closing acquires the lock first and commits, the later ballot request is rejected.

No ballot may commit after the successful closing transaction.

### RA Issuance Boundary

RA uses a separate database.

An RA state check followed by an issuance transaction is not globally atomic with election closing.

For the MVP:

- No new issuance is authorized after the Election Service reports CLOSED.
- RA fails closed if the trusted state cannot be checked.
- An in-flight issuance authorized before closure may finish afterward.
- Any such credential is unusable for submitting a ballot after CLOSED.
- Exact retry of an existing issuance is not a new issuance.

### Residual Risk

Strict atomic coordination of RA issuance commits with election closing is not guaranteed.

A production-grade solution would require an additional coordinated issuance barrier or equivalent protocol.

This limitation must be disclosed in the final report.

---

## 5. DR-06 - Election Deadline Policy

### Decision

Use manual lifecycle transitions with server-enforced time boundaries.

All authoritative timestamps use UTC.

Voting acceptance requires:

- election.status == OPEN
- server_time >= opens_at
- server_time < closes_at

The deadline must be checked inside the acceptance transaction using authoritative server-side time.

RA authorization for a new issuance also checks the trusted election time window.

### Consequences

- Election cannot start accepting votes before opens_at.
- Election stops accepting new votes at closes_at.
- Administrative CLOSE is still required before final snapshot creation.
- Tally remains unavailable until CLOSED.

Automatic administrative closing is deferred.

---

## 6. DR-03 - Receipt and Snapshot Integrity

### Receipt

Receipt construction is defined in Document 08.

Receipt hash must be deterministic and reproducible from the public accepted-ballot record.

The client calculates the expected receipt locally.

Voting returns receipt only after database commit.

A lost HTTP response can be reconciled using Public Board lookup.

### Final Snapshot

After CLOSED:

1. Read the frozen accepted-ballot dataset.
2. Sort public records deterministically.
3. Serialize using RFC 8785 JCS.
4. Calculate SHA-256 digest.
5. Create the manifest.
6. Sign the manifest with Ed25519.
7. Persist the snapshot and manifest.
8. Preserve independent integrity evidence.

### Snapshot State

Introduce a publication state:

- PREPARING
- FINALIZED
- FAILED

Only one authoritative FINALIZED snapshot is allowed per election.

### Failure Recovery

A failed PREPARING attempt may be retried.

Before reusing an existing artifact, verify its digest and signature.

Never silently replace an already finalized authoritative snapshot.

### Limitations

Snapshot signatures support post-publication integrity verification.

They do not prove that every valid attempted submission was accepted or that all accepted ballots were counted correctly.

---

## 7. DR-04 - Private Key Management

### Separate Cryptographic Keys

Use independent key pairs for:

- RA blind signing
- Tally key decryption
- Snapshot/manifest signing

### Local MVP Storage

Store encrypted private-key files outside the repository.

Use restrictive filesystem permissions.

Do not store private keys or passphrases inside:

- Git
- Source code
- SQL seed files
- Application logs
- API responses

### RA Key

Accessible only to RA Service.

Used solely for the selected RSABSSA profile.

### Tally Key

Accessible only inside the restricted Tally Process.

Unlocked interactively by the authorized operator after CLOSED and successful snapshot verification.

### Snapshot Key

Accessible only to the authorized Snapshot Publisher.

Its corresponding public key must be independently trusted by auditors.

### Residual Risk

Local encrypted PEM files and operating-system permissions do not provide the same protection as production HSM/KMS infrastructure.

---

## 8. DR-05 - Privacy and Session Separation

### RA Service

RA may know:

- voter_id
- account identity
- election eligibility
- issuance status

RA must not store:

- ballot serial
- plaintext vote choice
- encrypted ballot envelope
- finalized signature linked to voter identity

### Voting Service

Voting may know:

- election_id
- serial
- encrypted envelope
- prepared message
- finalized blind signature
- receipt hash

Voting must not receive:

- voter_id
- username
- RA authentication token
- RA identity cookie

### Client Separation

The Client must call Voting without RA identity credentials.

RA request IDs must never be sent to Voting.

### Logging

- Do not log plaintext votes.
- Do not log private keys or passphrases.
- Do not log full authentication tokens.
- Avoid shared correlation identifiers.
- Minimize IP address and timestamp retention.
- Review reverse-proxy logs for metadata leaks.

### Limitation

The MVP does not guarantee anonymity against complete traffic observation, device compromise or RA/Voting collusion.

---

## 9. DR-07 - Tally and Publication Recovery

### Tally Preconditions

- Election is CLOSED.
- A FINALIZED snapshot exists.
- Snapshot digest and signature verify.
- Authorized Tally Operator is present.
- Tally private key is available.

### Tally Success

The Tally Process:

1. Verifies the snapshot.
2. Decrypts accepted ballots.
3. Validates plaintext structure.
4. Counts valid and invalid ballots.
5. Creates the aggregate report.
6. Checks counting invariants.
7. Persists the successful result.
8. Transitions election to TALLIED.

### Tally Failure

If the process crashes or a required integrity check fails:

- Election remains CLOSED.
- No partial report becomes authoritative.
- Job is marked FAILED.
- A controlled retry is allowed.

### Idempotency

Only one authoritative successful tally result is permitted for the final snapshot.

### Publication Success

1. Admin approves the report.
2. Publication manifest is signed.
3. Publication artifacts are persisted and verified.
4. Results become publicly accessible.
5. Election transitions to PUBLISHED.

### Publication Failure

If artifacts cannot be safely published:

- Election does not become PUBLISHED.
- Partial artifacts are not represented as final.
- Retry reuses or verifies existing artifacts.

---

## 10. Threat to Control Mapping

| Threat | Control | Planned Test |
|---|---|---|
| Double issuance | Unique issuance + idempotency | ISS-T06, ISS-T07 |
| Duplicate ballot | Unique serial + transaction | BAL-T10, BAL-T11 |
| Close/submit race | Shared election row lock | CON-T01 |
| RA/close race | Trusted state check + documented limitation | CON-T02 |
| Modified envelope | Signature binding | BAL-T05 |
| Forged credential | RSABSSA verification | BAL-T06 |
| Voting key access | Key separation | TALLY-T18 |
| Modified final snapshot | SHA-256 + Ed25519 | BOARD-T10, BOARD-T11 |
| Invalid encrypted choice | Tally validation | TALLY-T09 |
| Identity leakage | API/session/log separation | CON-T06 |
| Tally process failure | Job lifecycle + idempotency | TALLY-T14 |

---

## 11. Additional Concurrency Tests

| ID | Scenario | Expected |
|---|---|---|
| CON-T01 | Close and submit concurrently | Defined transaction ordering |
| CON-T02 | Close and issue concurrently | Behavior matches documented limitation |
| CON-T03 | Submit at exact deadline | Rejected at or after cutoff |
| CON-T04 | Retry original issuance after CLOSED | Same response, no new signature |
| CON-T05 | Concurrent snapshot creation | One authoritative final snapshot |
| CON-T06 | Review RA/Voting logs | No direct identity-to-ballot mapping |
| CON-T07 | Tally process crashes | Election remains CLOSED |
| CON-T08 | Publication fails halfway | No false PUBLISHED status |
| CON-T09 | Repeat successful tally | No double counting |
| CON-T10 | Trusted election-state API unavailable | New issuance rejected |

### Additional Security Review Tests

| ID | Scenario | Expected |
|---|---|---|
| CON-T11 | Two operators start Tally together | One active job |
| CON-T12 | Active Tally lease expires | Controlled recovery |
| CON-T13 | Expired worker attempts finalization | Rejected by fencing token |
| CON-T14 | Worker loses response after finalization commit | Existing result recovered |
| CON-T15 | Frozen candidate catalog modified | Integrity verification fails |
| CON-T16 | RA public key replaced after OPEN | Configuration verification fails |
| CON-T17 | Publication manifest altered | Signature verification fails |
| CON-T18 | Published report counts modified | Digest/signature verification fails |
| CON-T19 | Snapshot config digest mismatches manifest | Tally aborted |
| CON-T20 | Duplicate successful tally persistence attempted | Database rejects duplicate |

All these cases are planned tests.

They are not considered passed until
the relevant implementation is exercised
and its results are recorded.

---

## 12. Required Cross-Document Corrections

### Document 06

Clarify that RA issuance and election closing are not atomically coordinated by Voting DB row locks.

Add the server-side deadline policy.

### Document 07

Clarify the difference between:

- A new issuance request
- Exact retrieval of a previously committed issuance

Document the possible RA/Close race.

### Document 08

Enforce the server-side deadline inside ballot acceptance.

Keep cryptographic verification outside the long-lived database transaction where practical.

Ensure receipt construction matches Document 09.

### Document 09

Define one authoritative FINALIZED snapshot per election.

Ensure auditors obtain a trusted verification key independently.

### Document 10

Require the Tally Process to use the finalized verified snapshot.

Ensure publication artifacts are verified before declaring PUBLISHED.

---

## 13. Residual Security Risks

**RISK-01:** RA and Election Service lack a globally atomic issuance/closing transaction.

**RISK-02:** Client losing all local blinding state may prevent recovery.

**RISK-03:** Network metadata may allow identity-to-ballot correlation.

**RISK-04:** A malicious publisher may omit ballots before the first trusted snapshot.

**RISK-05:** Receipt inclusion does not establish end-to-end correct tallying.

**RISK-06:** Local key storage does not provide production-grade HSM protection.

**RISK-07:** Device malware and voter coercion remain outside MVP security guarantees.

These risks must be included in the final security assessment.

---

## 14. Review Acceptance Criteria

- DR-01 to DR-05 are documented with clear decisions or remaining limitations.
- Election-state ownership is defined.
- Ballot acceptance versus closing is serializable through locking.
- RA issuance versus closing limitations are documented.
- Server-side deadlines are enforced.
- Credential retry is idempotent.
- Snapshot finalization rules are defined.
- Key ownership and access boundaries are defined.
- Privacy and logging controls are specified.
- Tally and publication recovery are specified.
- Tests are mapped to the main threats.
- Cross-document corrections are identified.

**Status: DESIGN REVIEW DRAFT — IMPLEMENTATION NOT STARTED**
