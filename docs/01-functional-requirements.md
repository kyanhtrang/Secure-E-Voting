
# Secure E-Voting System
## 01 - Functional Requirements

Version: 1.0
Status: Draft
Project: Secure & Anonymous E-Voting System

## 1. System Objective

Build a secure electronic voting prototype
that supports:

- Voter eligibility verification
- Anonymous blind credential issuance
- Client-side encrypted ballots
- Single-use ballot submission
- Public receipt verification
- Restricted vote tallying
- Partial auditability

## 2. Actors

### ACT-01: Voter
Authenticate with RA, select a candidate,
encrypt a ballot, obtain a blind signature,
submit the ballot and verify the receipt.

### ACT-02: Election Admin
Create elections, manage candidates,
manage eligibility through RA,
control election states and publish results.

### ACT-03: Tally Operator
Run the restricted tally process
only after the election is closed.

### ACT-04: Public Auditor
Verify public receipts, bulletin board
snapshots and published results.

## 3. Use Cases

| ID | Use Case |
|---|---|
| UC-01 | Create Election |
| UC-02 | Manage Candidates |
| UC-03 | Manage Voter Eligibility |
| UC-04 | Open Election |
| UC-05 | Authenticate Voter |
| UC-06 | Select and Encrypt Ballot |
| UC-07 | Request Blind Credential |
| UC-08 | Submit Encrypted Ballot |
| UC-09 | Verify Receipt |
| UC-10 | Close Election |
| UC-11 | Execute Tally |
| UC-12 | Publish Results |
| UC-13 | Verify Public Snapshot |
| UC-14 | View Security Audit |

## 4. Business Rules

- BR-01: Only eligible voters can obtain credentials.
- BR-02: One credential issuance per voter and election.
- BR-03: One candidate per ballot.
- BR-04: RA must not store ballot serials or choices.
- BR-05: Voting must not receive voter identity or RA sessions.
- BR-06: Voting must verify a valid blind signature
  bound to the election and encrypted envelope.
- BR-07: Ballots can only be accepted during OPEN and within the server-enforced election time window.
- BR-08: A serial can be accepted only once per election.
- BR-09: Tally cannot run before CLOSED.
- BR-10: Only valid accepted ballots are counted.
- BR-11: Public Board is read-only.
- BR-12: Election transitions are irreversible.
- BR-13: Private keys must not appear in source,
  ballot databases or application logs.
- BR-14: Sensitive admin actions require
  authorization and audit logging.

## 5. Election Lifecycle

DRAFT -> OPEN -> CLOSED -> TALLIED -> PUBLISHED

## 6. Deferred Features

- Coercion resistance
- National identity integration
- Blockchain
- Homomorphic tallying
- Zero-knowledge tally proofs
- Threshold decryption
- Production HSM/KMS

## 7. Open Design Questions

- Recovery after credential issuance failure
- Publication and anchoring of board snapshots
- Tally private-key release and approval
- Handling invalid encrypted ballots
- Avoiding RA/Voting metadata correlation

## 8. Acceptance Criteria

- Actors and permissions are documented.
- Every use case has a defined owner.
- Business rules are traceable to tests.
- Sensitive data ownership is defined.
- Open security decisions are documented.
