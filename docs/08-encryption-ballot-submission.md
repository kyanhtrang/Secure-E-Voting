
# Secure E-Voting System
## 08 - Encryption and Ballot Submission

Version: 1.0
Status: Draft
Phase: P01.2.3

---

## 1. Objective

Design secure client-side ballot encryption,
blind-signature verification, atomic ballot
acceptance, replay protection and receipts.

Related Use Cases:
- UC-06: Select and Encrypt Ballot
- UC-08: Submit Encrypted Ballot
- UC-09: Verify Receipt

Security Requirements:
- SR-01: Conditional anonymity
- SR-02: Credential authenticity
- SR-03: Single-use ballot submission
- SR-04: Ballot integrity and inclusion
- SR-06: Secure storage
- SR-07: Election state enforcement

---

## 2. Security Principles

- Plaintext vote choices remain on Client
  until authorized Tally.
- Voting receives encrypted ballots only.
- Voting never receives voter_id or RA token.
- RA and Tally use different RSA key pairs.
- Ballots must be bound to the correct election.
- Signed ballot content cannot be changed.
- Only OPEN elections accept new ballots.
- One serial can be accepted once per election.
- Successful acceptance requires DB commit.

---

## 3. Cryptographic Algorithms

Ballot encryption:
AES-256-GCM

AES key:
256-bit random key per ballot

Nonce:
96-bit random value

Key wrapping:
RSA-OAEP with SHA-256

Blind signature:
RSABSSA-SHA384-PSS-Randomized

Hash:
SHA-256

Canonical serialization:
RFC 8785 JSON Canonicalization Scheme (JCS)

Binary field representation:
Base64url without padding

All algorithms and encoding conventions
must be implemented consistently across
Client, RA, Voting and Tally.

---

## 4. Ballot Plaintext Format

The plaintext ballot contains only the
minimum data necessary for tallying.

Example:

{
  "schema_version": 1,
  "election_id": "<ELECTION_UUID>",
  "candidate_id": "<CANDIDATE_UUID>"
}

Rules:

- Exactly one candidate_id per ballot.
- Candidate must belong to the election.
- Additional unsupported fields are rejected.
- No voter identity is included.
- No RA authentication token is included.

Client canonicalizes the plaintext using JCS
before encryption.

---

## 5. Ballot Encryption

### Step 0: Verify Trusted Frozen Election Configuration

Before candidate display or cryptographic encryption, Client MUST:

1. Retrieve the signed frozen election configuration for the selected election.
2. Verify its Ed25519 signature using an evidence-signing public key trusted independently of the Board/API supplying the configuration.
3. Recompute and compare election_config_digest against independently trusted election metadata.
4. Verify the RA and Tally public-key fingerprints against the signed configuration, using SHA-256 over DER SubjectPublicKeyInfo.
5. Load candidate IDs only from the verified candidate catalog and confirm that the cryptographic profile matches.
6. Abort encryption if any signature, digest, key fingerprint or election ID check fails.

A public key received from the same untrusted endpoint is not independently authenticated merely because its key_id matches. An attacker-controlled Tally public key could compromise vote confidentiality even if Tally later rejects the ciphertext.

This trust prerequisite and the evidence distribution method must be tested before the MVP is treated as secure.

### Step 1: Generate Random Values

Client generates:

serial = CSPRNG(32 bytes)

K = CSPRNG(32 bytes)

nonce = CSPRNG(12 bytes)

A new AES key is generated for every ballot.

### Step 2: Construct AAD

AAD object:

{
  "schema_version": 1,
  "election_id": "<ELECTION_UUID>",
  "serial": "<BASE64URL_SERIAL>"
}

AAD = JCS(AAD object)

### Step 3: Encrypt Plaintext

plaintext = JCS(ballot payload)

ciphertext_and_tag = AES-256-GCM.Encrypt(
    key=K,
    nonce=nonce,
    plaintext=plaintext,
    associated_data=AAD
)

The ciphertext includes an authentication tag.

### Step 4: Wrap AES Key

encrypted_key = RSA-OAEP-SHA256.Encrypt(
    public_key=PK_Tally,
    plaintext=K
)

The Tally private key is never available
to Voting or Voter Client.

---

## 6. Encrypted Envelope

Example structure:

{
  "schema_version": 1,
  "key_id": "tally-key-01",
  "cipher_algorithm": "AES-256-GCM",
  "key_wrap_algorithm": "RSA-OAEP-SHA256",
  "nonce": "<BASE64URL_NONCE>",
  "ciphertext": "<BASE64URL_CIPHERTEXT_AND_TAG>",
  "encrypted_key": "<BASE64URL_ENCRYPTED_KEY>"
}

Rules:

- All required fields must exist.
- Unknown fields are rejected.
- Algorithm identifiers must match the
  supported cryptographic profile.
- Encoded binary values must be valid.
- Nonce must decode to exactly 12 bytes.
- Wrapped key length must match RSA modulus.
- Envelope size must be bounded.
- key_id must match the election Tally key.

The exact envelope is canonicalized using JCS.

envelope_hash = SHA256(JCS(envelope))

---

## 7. Credential Message Binding

Application message object:

{
  "domain": "secure-evoting-ballot-v1",
  "schema_version": 1,
  "election_id": "<ELECTION_UUID>",
  "serial": "<BASE64URL_SERIAL>",
  "envelope_hash": "<SHA256_HEX>"
}

M = JCS(application message object)

For the randomized RSABSSA variant:

prepared_msg = PrepareRandomize(M)

prepared_msg = random_32_bytes || M

Client then blinds prepared_msg using PK_RA.

RA blind-signs the request after checking
the voter eligibility and issuance status.

Client finalizes the signature and verifies
it before submitting the ballot.

---

## 8. Ballot Submission API

Endpoint:

POST /api/v1/vote/ballots

Authentication:
Valid blind credential.

No RA session token is accepted.

Request:

{
  "election_id": "<ELECTION_UUID>",
  "serial": "<BASE64URL_SERIAL>",
  "envelope": {
    "schema_version": 1,
    "key_id": "tally-key-01",
    "cipher_algorithm": "AES-256-GCM",
    "key_wrap_algorithm": "RSA-OAEP-SHA256",
    "nonce": "<BASE64URL_NONCE>",
    "ciphertext": "<BASE64URL_CIPHERTEXT_AND_TAG>",
    "encrypted_key": "<BASE64URL_WRAPPED_KEY>"
  },
  "prepared_msg": "<BASE64URL_PREPARED_MESSAGE>",
  "signature": "<BASE64URL_RSA_SIGNATURE>"
}

All values in angle-bracket placeholders
are illustrative.

---

## 9. Voting Server Validation

### 9.1. Request Validation

Voting performs the following checks before
starting the ballot-acceptance transaction:

1. Validate request JSON structure.
2. Reject unknown or unsupported fields.
3. Validate schema version.
4. Validate Base64url encodings and sizes.
5. Validate the ballot serial length.
6. Validate encrypted envelope metadata.
7. Verify that envelope key_id belongs
   to the requested election.
8. Load the trusted election-specific
   RA public key.
9. Verify the finalized RSA blind signature
   against the complete prepared_msg.
10. Remove the 32-byte randomized prefix
    from prepared_msg.
11. Parse and validate the application message.
12. Recalculate SHA256(JCS(envelope)).
13. Reconstruct the expected application
    message using election_id, serial,
    envelope_hash and domain separator.
14. Compare the reconstructed message
    bytes with the signed application message.
15. Reject mismatches or invalid signatures.

The accepted RSABSSA cryptographic profile
must be identical on Client and Voting.

A signature issued for another election
must not authorize this election.

### 9.2. Atomic Acceptance

Only after cryptographic validation succeeds:

1. Begin a PostgreSQL transaction.
2. Lock the authoritative election row
   using SELECT FOR UPDATE.
3. Verify election status == OPEN.
4. Obtain PostgreSQL clock_timestamp()
   after acquiring the row lock.
5. Verify opens_at <= decision_time
   and decision_time < closes_at.
6. Insert the accepted encrypted ballot.
7. Enforce UNIQUE(election_id, serial).
8. Store the deterministic receipt hash.
9. Commit the transaction.
10. Return HTTP 201 and receipt_hash.

The receipt must not be returned as
accepted before the transaction commits.

### 9.3. Election Closing Race

Voting acceptance and election closing
must lock the same authoritative election row.

If Voting obtains the lock first:

- It checks OPEN and the server deadline.
- The accepted ballot may commit.
- Closing proceeds after that transaction.

If Closing obtains the lock first:

- Election state becomes CLOSED.
- A later Voting transaction is rejected.

### 9.4. Deadline Enforcement

The Client clock is not authoritative.

The server must reject ballots:

- Before opens_at
- At or after closes_at
- When election status is not OPEN

Use PostgreSQL clock_timestamp()
after obtaining the election row lock.

Do not rely on transaction-start now()
for the final deadline decision.

### 9.5. Encrypted Payload Limitation

Voting cannot decrypt the ballot.

Voting cannot independently verify the
AES-GCM tag or plaintext candidate_id.

A correctly signed encrypted ballot with
invalid plaintext may be accepted.

Such a ballot is validated and classified
as invalid during the restricted Tally.

### 9.6. Privacy

Voting must not receive:

- voter_id
- username
- RA access token
- RA request_id
- RA identity cookies

Voting must not log plaintext vote choices,
credentials or other sensitive data.

---

## 10. Database Acceptance Rules

### 10.1. Accepted Ballot Fields

The accepted_ballots table stores:

- ballot_id
- election_id
- serial
- envelope
- prepared_msg
- signature
- envelope_hash
- receipt_hash
- accepted_at

Mandatory database constraint:

UNIQUE(election_id, serial)

The database must not store:

- voter_id
- username
- RA authentication token
- RA issuance request_id
- plaintext candidate selection

### 10.2. Atomic Acceptance

The Voting Service uses a transaction
and locks the authoritative election row.

The election status and deadline must
be checked while holding this lock.

The accepted ballot and receipt hash
are inserted in the same transaction.

The database unique constraint prevents
multiple accepted records with the same
(election_id, serial).

The API returns HTTP 201 only after
the complete transaction commits.

### 10.3. Duplicate Submission

If an accepted record already exists
for the same election and serial:

- Do not create a second ballot.
- Return HTTP 409.
- Do not change the existing ballot.
- Do not generate a second acceptance.

The existing public receipt may be checked
through Public Bulletin Board.

### 10.4. Concurrent Submissions

If multiple requests submit the same
serial concurrently:

- The unique constraint enforces one
  accepted record at most.
- One transaction may commit successfully.
- Other conflicting transactions fail.
- No duplicate ballots are counted.

### 10.5. Transaction Failure

If the transaction fails before commit:

- Roll back all ballot-related writes.
- Do not return an accepted response.
- Record a privacy-safe operational event.

If the transaction commits but the
HTTP response is lost:

- Do not automatically generate a new
  serial or a new credential.
- Client retains the expected receipt.
- Client checks Public Board inclusion.

### 10.6. Accepted Timestamp

accepted_at is generated by the server,
not supplied by the Client.

The acceptance deadline is evaluated
using decision_time obtained after the
election row lock is acquired.

accepted_at and decision_time may differ.

The system must not claim that the
transaction commit occurred before
closes_at merely because the deadline
check passed earlier.

Precise acceptance timestamps must not
be exposed publicly unless necessary
for an explicitly reviewed protocol.

### 10.7. Database Design Dependencies

The detailed schema will be defined
in P01.3.

Required database features include:

- Foreign key to elections
- Unique election/serial constraint
- Transaction-safe insert
- Election row locking
- Appropriate service permissions
- Restricted UPDATE/DELETE access
- Audit event handling

---

## 11. Receipt Construction

### 11.1. Purpose

The receipt identifies an exact accepted
encrypted ballot record.

A receipt is not proof that the ballot
was correctly decrypted or counted.

### 11.2. Receipt Object

The receipt object contains:

{
  "election_id": "<ELECTION_UUID>",
  "serial": "<BASE64URL_SERIAL>",
  "envelope_hash": "<SHA256_HEX>",
  "prepared_msg": "<BASE64URL_PREPARED_MESSAGE>",
  "signature": "<BASE64URL_SIGNATURE>"
}

The receipt object excludes:

- voter_id
- username
- RA request_id
- plaintext candidate_id
- acceptance timestamp

### 11.3. Deterministic Hash

The receipt object is serialized using
RFC 8785 JSON Canonicalization Scheme.

receipt_hash = SHA256(
    UTF8("EVOTE-RECEIPT-v1") ||
    byte(0) ||
    JCS(receipt_object)
)

The digest is represented as a lowercase
64-character hexadecimal string.

The same input must produce exactly the
same receipt hash on Client and Voting.

### 11.4. Server Acceptance

Voting calculates the receipt hash from
the validated encrypted ballot data.

Voting stores:

- accepted ballot
- envelope hash
- receipt hash

inside the same database transaction.

The API returns HTTP 201 only after
the complete transaction commits.

Example response:

{
  "status": "accepted",
  "receipt_hash": "<SHA256_HEX>"
}

### 11.5. Client Verification

Before submission, Client computes
the expected receipt hash locally.

After receiving HTTP 201:

1. Verify response schema.
2. Compare returned receipt_hash with
   the locally calculated expected hash.
3. Store receipt data locally.
4. Query Public Bulletin Board.
5. Retrieve the matching public record.
6. Recompute the receipt hash from
   the public record.
7. Compare with the expected receipt.

A matching locally recomputed receipt
provides evidence of the returned
record's consistency.

It does not establish correct tallying.

### 11.6. Public Board Consistency

Document 09 must use the same:

- Receipt object fields
- Canonicalization algorithm
- Domain separator
- Digest encoding

Public Board must not construct a
different receipt format.

Only committed accepted ballots may
appear in Public Board results.

A NOT_FOUND result means the receipt
is not currently visible.

It does not automatically prove
the ballot was rejected.

### 11.7. Privacy Considerations

Receipt hashes are public verification
identifiers, not authentication tokens.

A person who shares a receipt may reveal
which encrypted ballot record is theirs.

The system must not expose a direct
identity-to-receipt mapping.

---

## 12. Submission Failure Handling

### 12.1. Invalid Signature

Condition:
RSA blind signature verification fails.

Expected:
- Reject request.
- Do not insert ballot.
- Do not return accepted receipt.

### 12.2. Modified Envelope

Condition:
Envelope hash differs from the signed
application message.

Expected:
- Reject request.
- Do not insert ballot.
- Do not return accepted receipt.

### 12.3. Duplicate Serial

Condition:
An accepted ballot already exists with
the same (election_id, serial).

Expected:
- Return HTTP 409.
- Do not create another ballot.
- Do not modify existing acceptance.
- Allow receipt lookup through Board.

### 12.4. Election Not Accepting Ballots

Conditions:
- Election not OPEN
- Current time before opens_at
- Current time at or after closes_at

Expected:
- Reject new ballot acceptance.
- Do not insert ballot.
- Do not issue accepted response.

### 12.5. Concurrent Duplicate Requests

Condition:
Multiple requests use the same
(election_id, serial).

Expected:
- At most one transaction commits.
- All other conflicting inserts fail.
- Exactly one accepted record exists.

### 12.6. Lost Response After Commit

Condition:
Voting successfully commits the ballot,
but Client does not receive HTTP 201.

Client must:

1. Retain the original encrypted ballot.
2. Retain the finalized blind signature.
3. Retain the locally calculated receipt.
4. Query Public Board for receipt inclusion.

If the receipt is found:

- Verify the returned record.
- Display the confirmed Board result.

If the receipt is not found:

- Display NOT_FOUND or PENDING
  according to the current evidence.
- Do not assume successful acceptance.
- Do not automatically generate
  another serial or credential.

An optional retry of the identical ballot
may be supported, but must never create
a second accepted record.

### 12.7. Database Transaction Failure

Condition:
Ballot acceptance fails before commit.

Expected:
- Roll back related writes.
- Return controlled error.
- Do not claim ballot acceptance.

### 12.8. Invalid Encrypted Plaintext

Condition:
The encrypted ballot has a valid
signature and envelope binding,
but its decrypted plaintext is invalid.

Expected:
- Voting may accept the encrypted record.
- Tally later validates the plaintext.
- Invalid ballot contributes to
  invalid_total, not candidate counts.

### 12.9. Public Board Unavailable

Condition:
Client cannot query Board.

Expected:
- Display UNAVAILABLE.
- Preserve receipt information.
- Do not claim verification PASS.
- Allow later verification.

---

## 13. Security Invariants

BAL-01:
Plaintext vote is never sent to Voting.

BAL-02:
Each ballot uses a fresh AES session key.

BAL-03:
The AES-GCM authentication tag is verified
by Tally before plaintext is accepted.

BAL-04:
The signature binds election, serial
and encrypted-envelope hash.

BAL-05:
Voting verifies the complete prepared message
using the RFC 9474 algorithm parameters.

BAL-06:
No ballot is accepted outside OPEN.

BAL-07:
One serial can be accepted at most once
per election.

BAL-08:
The ballot acceptance transaction is atomic.

BAL-09:
Voting cannot access the Tally private key.

BAL-10:
An accepted ballot contains no voter identity.

BAL-11:
Receipt issuance occurs only after DB commit.

BAL-12:
Receipt inclusion does not prove correct tally.

---

## 14. Planned Tests

| Test ID | Scenario | Expected |
|---|---|---|
| BAL-T01 | Encrypt valid ballot | Success |
| BAL-T02 | Decrypt with correct key | Original plaintext |
| BAL-T03 | Decrypt with wrong key | Failure |
| BAL-T04 | Tamper AES-GCM ciphertext | Authentication failure at Tally |
| BAL-T05 | Modify envelope after signing | Rejected by Voting |
| BAL-T06 | Submit forged RSA signature | Rejected |
| BAL-T07 | Use wrong election_id | Rejected |
| BAL-T08 | Submit ballot in DRAFT | Rejected |
| BAL-T09 | Submit ballot in CLOSED | Rejected |
| BAL-T10 | Submit same serial twice | One accepted |
| BAL-T11 | Submit 20 concurrent duplicates | Exactly one accepted |
| BAL-T12 | Lose response after commit | Receipt recoverable from Board |
| BAL-T13 | Inspect Voting DB | No voter identity |
| BAL-T14 | Submit malformed ciphertext with valid signature | Invalid at Tally |
| BAL-T15 | Modify AAD during decryption | Authentication failure |
| BAL-T16 | Reorder JSON properties | Canonical hash unchanged |

---

## 15. Open Design Decisions

OD-08:
Confirm JCS library conformance
and canonical binary-field encoding.

OD-09:
Finalize receipt publication and
board consistency guarantees.

DR-02:
Finalize atomic locking between
ballot acceptance and election closing.

DR-03:
Define final snapshot creation,
hash anchoring and independent verification.

DR-04:
Define secure Tally private-key storage.

DR-05:
Define privacy-preserving request metadata
and session isolation.

---

## 16. Acceptance Criteria

- Client encryption process is documented.
- Encrypted envelope schema is specified.
- Canonical serialization is defined.
- Signature verification is defined.
- Election and envelope binding is enforced.
- Atomic ballot acceptance is designed.
- Duplicate serial protection is specified.
- Deterministic receipt design is documented.
- Negative test scenarios are identified.
- Remaining design decisions are tracked.

Status:
DESIGN DRAFT - IMPLEMENTATION NOT STARTED
