
# Secure E-Voting System
## 03 - Voter Use Case Specifications

Version: 1.0
Status: Draft
Scope: UC-05 to UC-09

---

## UC-05 - Authenticate Voter

### Actor
Voter

### Description
Authenticate a voter through Registration Authority (RA).

### Pre-conditions
- Voter account exists in RA DB.
- The account is active.
- RA Service is available.

### Input Data
- Username
- Password

### Main Flow
1. Voter opens the Voter Client.
2. Voter enters username and password.
3. Client sends credentials to RA over HTTPS.
4. RA verifies the account and password hash.
5. RA creates a short-lived authenticated session.
6. RA returns the session to Client.
7. Client displays available elections.
8. Voter selects an election.
9. RA checks eligibility for that election.
10. Client displays the eligibility result.

### Alternative Flow
- Voter is authenticated but not eligible.
- Client displays an ineligible message.
- Voter cannot request a credential.

### Exception Flow
- Invalid username/password: authentication denied.
- Disabled account: authentication denied.
- Expired session: re-authentication required.
- RA unavailable: display an error.
- Excessive login attempts: rate limit applied.

### Post-conditions
- Voter has an authenticated RA session.
- No ballot has been submitted.
- No credential has been issued.

### Security Rules
- Passwords must be securely hashed.
- Authentication traffic uses HTTPS.
- RA session must not be sent to Voting API.
- Authentication logs must not contain passwords.
- No Vote Choice is stored at RA.

---

## UC-06 - Select and Encrypt Ballot

### Actor
Voter

### Description
Select a candidate and encrypt the vote locally.

### Pre-conditions
- Voter is authenticated with RA.
- Election is OPEN.
- The signed frozen election configuration is verified against an independently trusted evidence key before candidate display or encryption.
- The RA and Tally public-key fingerprints match the verified frozen configuration.
- Client supports the required crypto algorithms.

### Input Data
- Election ID
- Candidate ID
- Tally Public Key
- RA Public Key

### Main Flow
1. Client displays candidates only from the verified signed frozen election configuration.
2. Voter selects exactly one candidate.
3. Client displays the selected candidate.
4. Voter confirms the final choice.
5. Client generates a random ballot serial.
6. Client generates a fresh AES-256 key.
7. Client creates the canonical ballot payload.
8. Client encrypts the payload using AES-256-GCM.
9. Client wraps the AES key using RSA-OAEP.
10. Client creates the encrypted envelope.
11. Client computes SHA-256(envelope).
12. Client constructs the credential message M.
13. Client prepares and blinds M using RSABSSA.
14. Client retains the ballot and blinding state.
15. Client proceeds to credential issuance.

### Alternative Flow
- Voter changes selection before final confirmation.
- Client cancels and discards the draft.

### Exception Flow
- No candidate selected: validation error.
- Invalid candidate ID: selection rejected.
- Missing, untrusted or substituted public key: operation denied.
- Invalid configuration signature or mismatched fingerprint: abort before ballot encryption.
- Unsupported algorithm: operation denied.
- Encryption failure: abort without issuance.

### Post-conditions
- Encrypted envelope exists locally.
- Random serial exists locally.
- Prepared and blinded messages exist.
- No plaintext ballot has been sent to a server.
- No credential has been issued yet.

### Security Rules
- Random values must use a CSPRNG.
- AES-256-GCM must use a fresh session key.
- AAD binds election ID, serial and schema version.
- The encrypted envelope must be canonicalized.
- Client must not transmit plaintext vote choice.
- Tally private key must never be sent to Client.
- No change to the signed ballot is allowed
  after credential issuance.
- Before encrypting, Client MUST verify the frozen-configuration signature and independently trusted evidence key, then match RA/Tally key fingerprints. A key ID alone is insufficient.

---

## UC-07 - Request Blind Credential

### Actors
Voter, Registration Authority

### Description
Issue a single blind signature for an eligible voter.

### Pre-conditions
- Voter has a valid RA session.
- Voter is eligible for the election.
- Election is OPEN.
- For first issuance, no credential has been issued; an exact retry may retrieve the original committed issuance.
- Client has prepared a blinded message.

### Input Data
- Election ID
- Blinded Message
- RA Authentication Session

### Main Flow
1. Client sends the blinded message to RA.
2. RA verifies the authentication session.
3. RA verifies election eligibility.
4. RA checks the election state.
5. RA checks credential issuance status.
6. RA validates the blinded message format.
7. RA uses its private signing key
   to perform the blind-signing operation.
8. RA records credential issuance atomically.
9. RA returns the blind signature.
10. Client unblinds/finalizes the signature.
11. Client verifies the finalized signature.
12. Client retains the credential for submission.

### Alternative Flow
- Election is not OPEN.
- RA refuses credential issuance.
- No issuance record is created.

### Exception Flow
- Invalid RA session: HTTP 401.
- Ineligible voter: HTTP 403.
- Different second credential request: HTTP 409. Exact retry returns the original stored response.
- Invalid blinded message: HTTP 422.
- Signing failure: no successful issuance.
- Concurrent issuance: only one succeeds.
- Lost response after commit:
  issuance state is uncertain to Client;
  no new credential is automatically issued.

### Post-conditions
- One issuance record exists in RA DB.
- Client possesses a verifiable blind signature
  if the response was received successfully.
- RA does not know the unblinded message.
- RA does not store ballot serial or vote choice.

### Security Rules
- UNIQUE(voter_id, election_id).
- Private signing key is accessible only to RA.
- Blind signatures follow RFC 9474.
- RA must not store unblinded messages.
- RA logs must not contain ballot data.
- Credential issuance must be atomic.

---

## UC-08 - Submit Encrypted Ballot

### Actors
Voter, Voting Server

### Description
Submit a signed encrypted ballot without identity data.

### Pre-conditions
- Election is OPEN.
- Client has a finalized blind signature.
- Client has an encrypted ballot envelope.
- The ballot serial has not been accepted.

### Input Data
- Election ID
- Ballot Serial
- Encrypted Envelope
- Prepared Message
- Blind Signature

### Main Flow
1. Client prepares the ballot submission.
2. Client sends the submission to Voting API.
3. Voting validates the request schema.
4. Voting checks the election state.
5. Voting loads the election RA public key.
6. Voting verifies the blind signature.
7. Voting verifies the signed message binding
   to election ID, serial and envelope hash.
8. Voting checks ballot metadata constraints.
9. Voting inserts the accepted ballot
   in a database transaction.
10. Database enforces serial uniqueness.
11. Voting commits the transaction.
12. Voting generates/returns the receipt.
13. Client displays the accepted status.

### Alternative Flow
- Client loses the response after submission.
- Client checks the Public Board using
  the locally retained receipt data,
  if sufficient information is available.
- Client must not request a second credential.

### Exception Flow
- Election CLOSED: HTTP 409.
- Invalid signature: request rejected.
- Modified envelope: request rejected.
- Duplicate serial: HTTP 409.
- Malformed request: HTTP 400/422.
- Database error: transaction rolled back.
- Invalid ciphertext plaintext:
  may only be detected during Tally.

### Post-conditions
- Exactly one accepted record exists
  for the election and serial.
- Voting DB stores ciphertext and metadata.
- Voting DB does not store Voter ID.
- The accepted ballot is eligible for Tally.
- Receipt is available to the voter.

### Security Rules
- No RA session or identity cookie
  is sent to Voting Server.
- Signature must bind election and envelope.
- UNIQUE(election_id, serial).
- Database insertion must be atomic.
- A successful response requires commit.
- Voting must not possess Tally private key.
- Voting must not log voter identity.

---

## UC-09 - Verify Receipt

### Actors
Voter, Public Auditor

### Description
Verify that an accepted ballot appears
on the Public Bulletin Board.

### Pre-conditions
- Voting accepted a ballot.
- Voter has retained the receipt.
- Public Board is available.

### Input Data
- Election ID
- Receipt Hash

### Main Flow
1. Voter opens the Public Bulletin Board.
2. Voter enters the receipt hash.
3. Board searches public accepted records.
4. Board returns the corresponding record.
5. Client checks the receipt against
   the public ballot record.
6. Client displays the inclusion result.
7. When a signed snapshot is available,
   Client verifies its digest and signature.
8. Client displays the verification status.

### Alternative Flow
- The accepted ballot has not yet appeared
  in a published board snapshot.
- Client displays a pending result.

### Exception Flow
- Receipt not found: verification unavailable.
- Receipt mismatch: verification failed.
- Snapshot hash mismatch: integrity warning.
- Invalid snapshot signature: warning.
- Board unavailable: retry later.

### Post-conditions
- Voter can verify ballot inclusion
  in the published accepted records.
- No plaintext vote is revealed.
- No voter identity is revealed by the board.

### Security Rules
- Public Board is read-only.
- Receipt does not reveal candidate choice.
- Snapshot verification uses public keys.
- Receipt inclusion alone does not prove
  mathematically correct vote counting.

---

## Acceptance Tests

| ID | Scenario | Expected Result |
|---|---|---|
| VOT-01 | Login with valid credentials | Success |
| VOT-02 | Login with wrong password | Rejected |
| VOT-03 | Ineligible voter requests credential | Rejected |
| VOT-04 | Encrypt a valid ballot | Encrypted envelope created |
| VOT-05 | Request first credential | Success |
| VOT-06 | Request a different second credential | HTTP 409; no second issuance |
| VOT-07 | Verify finalized blind signature | Valid |
| VOT-08 | Submit valid encrypted ballot | Accepted |
| VOT-09 | Submit forged signature | Rejected |
| VOT-10 | Modify envelope after signing | Rejected |
| VOT-11 | Submit same serial twice | Second rejected |
| VOT-12 | Submit after CLOSED | Rejected |
| VOT-13 | Send RA token to Voting | Contract violation |
| VOT-14 | Verify valid receipt | Found |
| VOT-15 | Verify unknown receipt | Not found |
| VOT-16 | Modify signed board snapshot | Verification failed |
| VOT-17 | Submit 20 concurrent duplicate requests | Exactly 1 accepted |
| VOT-18 | RA response lost after issuance | Exact retry returns original blind_sig; no new issuance |

---

## Open Design Decisions

OD-06: Define secure client-side temporary state.

OD-07: Define credential issuance recovery
without violating single issuance.

OD-08: Define exact canonical message encoding.

OD-09: Define receipt hash construction
and board publication consistency.

OD-10: Define session separation between
RA and Voting, including cookies and logs.

OD-11: Define how public keys are authenticated
and tied to the correct election.

OD-12: Define the behavior when a ballot is
accepted but decrypts to an invalid choice.
