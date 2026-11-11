
# Secure E-Voting System
## 04 - Tally, Publication and Security Audit Use Cases

Version: 1.0
Status: Draft
Scope: UC-10 to UC-14

---

## UC-10 - Close Election

### Actor
Election Admin

### Description
Close an OPEN election and prevent new ballots
or credential issuance.

### Pre-conditions
- Admin is authenticated and authorized.
- Election exists.
- Election status is OPEN.

### Input Data
- Election ID
- Admin authorization context

### Main Flow
1. Admin opens Election Management.
2. Admin selects an OPEN election.
3. Admin clicks Close Election.
4. System requests confirmation.
5. Admin confirms the operation.
6. Backend validates the Admin role.
7. Backend checks the current election state.
8. Backend atomically changes OPEN to CLOSED.
9. Backend records an audit event.
10. Voting rejects new ballot submissions.
11. RA rejects new credential requests.
12. Admin sees the CLOSED status.

### Alternative Flow
- Admin cancels the confirmation.
- Election remains OPEN.

### Exception Flow
- Unauthorized Admin: HTTP 403.
- Election not found: HTTP 404.
- Election not OPEN: HTTP 409.
- Database failure: transaction rolled back.
- Service state mismatch: fail closed.

### Post-conditions
- Election status is CLOSED.
- No new ballots can be accepted.
- No new credentials can be issued.
- Previously accepted ballots remain unchanged.
- Audit event is recorded.

### Security Rules
- CLOSED cannot transition back to OPEN.
- Closing requires an authorized role.
- State changes must be atomic.
- RA and Voting must reject operations
  when the trusted state is not OPEN.
- In-flight submissions must be resolved
  consistently with the state transition.

---

## UC-11 - Execute Tally

### Actor
Tally Operator

### Description
Decrypt accepted ballots after election closure,
validate them and calculate aggregate results.

### Pre-conditions
- Election status is CLOSED.
- Operator is authenticated and authorized.
- Accepted ballots are available.
- Tally private key is stored securely.
- The authorized tally environment is ready.

### Input Data
- Election ID
- Accepted encrypted ballots
- Tally private key
- Authorized key-unlock credentials

### Main Flow
1. Operator selects a CLOSED election.
2. Operator initiates a tally request.
3. System checks the election state.
4. System verifies operator authorization.
5. System prepares a final ballot snapshot.
6. System records the snapshot hash.
7. Restricted Tally Process is started.
8. Operator unlocks the encrypted Tally key.
9. Tally reads accepted encrypted ballots.
10. Tally unwraps each AES session key.
11. Tally decrypts each ballot using AES-GCM.
12. Tally verifies authentication tags and AAD.
13. Tally validates election ID and schema.
14. Tally checks whether the selected candidate
    belongs to the election.
15. Tally counts valid ballots per candidate.
16. Tally records invalid ballot totals.
17. Tally produces an aggregate tally report.
18. System stores the report and its digest.
19. Election transitions CLOSED to TALLIED.
20. System records a security audit event.

### Alternative Flow
- No accepted ballots exist.
- Tally produces a valid zero-ballot report.

### Exception Flow
- Election OPEN: tally rejected.
- Unauthorized operator: HTTP 403.
- Missing private key: tally cannot start.
- Incorrect key passphrase: unlock denied.
- Invalid AES-GCM tag: ballot marked invalid.
- Unknown candidate: ballot marked invalid.
- Snapshot integrity mismatch:
  tally halted for investigation.
- System failure: no successful TALLIED state.

### Post-conditions
- Election status is TALLIED after success.
- Aggregate tally results exist.
- Individual plaintext votes are not published.
- Tally report is linked to the source snapshot.
- Security audit event exists.

### Security Rules
- Tally private key is unavailable to Voting.
- Tally may run only after CLOSED.
- Tally Process uses restricted permissions.
- No plaintext vote appears in application logs.
- No plaintext ballot is written to a
  persistent general-purpose database.
- Aggregate counted votes must equal
  the number of valid decrypted ballots.
- Tally must be idempotent for a finalized
  snapshot or explicitly reject repeated runs.

---

## UC-12 - Publish Results

### Actor
Election Admin

### Description
Publish approved aggregate election results.

### Pre-conditions
- Admin is authenticated and authorized.
- Election status is TALLIED.
- A successful tally report exists.
- Snapshot integrity checks have passed.

### Input Data
- Election ID
- Approved tally report
- Final snapshot metadata

### Main Flow
1. Admin opens Tally Results.
2. Admin selects a TALLIED election.
3. System displays aggregate results.
4. Admin reviews accepted, valid and invalid
   ballot totals.
5. Admin selects Publish Results.
6. System validates Admin authorization.
7. System checks the TALLIED state.
8. System verifies the report digest.
9. System creates the publication manifest.
10. Authorized signing component signs
    the manifest using Ed25519.
11. System publishes the result and manifest.
12. Election transitions to PUBLISHED.
13. System records an audit event.

### Alternative Flow
- Admin cancels publication.
- Election remains TALLIED.

### Exception Flow
- Election not TALLIED: HTTP 409.
- Unauthorized Admin: HTTP 403.
- Missing tally report: rejected.
- Invalid report digest: publication blocked.
- Signing failure: publication blocked.
- Publication failure: system retains
  a recoverable unpublished state.

### Post-conditions
- Election status is PUBLISHED.
- Aggregate results are publicly accessible.
- A signed publication manifest exists.
- The public can verify the manifest signature.
- Admin publication event is recorded.

### Security Rules
- Never publish individual plaintext votes.
- Never publish Tally private key.
- Report must refer to the exact tally snapshot.
- Signed manifest changes must be detectable.
- Publication must not silently modify
  already accepted ballots.

---

## UC-13 - Verify Public Snapshot

### Actor
Public Auditor

### Description
Verify the integrity and authenticity
of a published bulletin-board snapshot.

### Pre-conditions
- A public snapshot is available.
- Auditor has the trusted verification key.
- Public Board is accessible.

### Input Data
- Election ID
- Published ballot snapshot
- Snapshot manifest
- Manifest signature
- Trusted public verification key

### Main Flow
1. Auditor opens the Public Board.
2. Auditor selects an election.
3. Auditor downloads the snapshot.
4. Auditor downloads the signed manifest.
5. Auditor recalculates the snapshot digest.
6. Auditor compares it with the manifest.
7. Auditor verifies the Ed25519 signature.
8. Auditor verifies the manifest references
   the expected election and snapshot.
9. System displays the verification result.

### Alternative Flow
- Auditor verifies only a receipt inclusion.
- System reports a limited inclusion result.

### Exception Flow
- Snapshot missing: verification unavailable.
- Digest mismatch: integrity failure.
- Invalid signature: authenticity failure.
- Wrong election ID: verification failure.
- Untrusted public key: verification
  cannot establish authenticity.

### Post-conditions
- Auditor obtains PASS, FAIL or UNVERIFIED.
- No voter identity is disclosed.
- No plaintext vote is disclosed.

### Security Rules
- Snapshot integrity uses SHA-256.
- Manifest authenticity uses Ed25519.
- Public verification never requires
  any private signing or decryption key.
- Independent preservation of snapshot hashes
  is required to detect some server-side
  deletion or replacement attacks.
- Receipt inclusion is not proof of
  end-to-end correct tallying.

---

## UC-14 - View Security Audit

### Actors
Election Admin, Authorized Auditor

### Description
Review permitted administrative
and security events without exposing secrets.

### Pre-conditions
- User is authenticated.
- User has the required audit permission.
- Audit data is available.

### Input Data
- Election ID (optional)
- Event type
- Time range
- Authorized access context

### Main Flow
1. User opens Security Audit.
2. System verifies authentication.
3. System checks audit permissions.
4. User selects filters.
5. Backend queries permitted audit events.
6. Backend applies sensitive-data masking.
7. System returns the filtered audit events.
8. User reviews security activities.

### Alternative Flow
- No events match the selected filters.
- System displays an empty result.

### Exception Flow
- Unauthenticated request: HTTP 401.
- Unauthorized request: HTTP 403.
- Invalid filters: HTTP 422.
- Audit storage unavailable: error reported.

### Post-conditions
- Authorized user views permitted events.
- Audit access is itself recorded.
- No ballot choice or secret is exposed.

### Security Rules
- Never log passwords or private keys.
- Never log plaintext votes.
- Never log full RA session tokens.
- Avoid logging precise identifying
  metadata alongside ballot identifiers.
- RA audit and Voting audit remain separated.
- Audit access follows least privilege.
- Audit records need access protection
  and tamper-evidence where practical.

---

## Tally Consistency Rules

TCR-01:
accepted_total = valid_total + invalid_total

TCR-02:
counted_total = valid_total

TCR-03:
SUM(candidate_vote_count) = counted_total

TCR-04:
Only committed accepted ballots are included.

TCR-05:
A tally report must identify the exact
final ballot snapshot used for counting.

TCR-06:
A successful tally run must not mutate
the original accepted ballot records.

---

## Acceptance Tests

| ID | Scenario | Expected Result |
|---|---|---|
| TLY-01 | Close OPEN election | CLOSED |
| TLY-02 | Close CLOSED election | Rejected |
| TLY-03 | Submit ballot after CLOSED | Rejected |
| TLY-04 | Execute tally during OPEN | Rejected |
| TLY-05 | Execute tally after CLOSED | Success |
| TLY-06 | Unlock Tally key with wrong passphrase | Rejected |
| TLY-07 | Decrypt a valid accepted ballot | Counted |
| TLY-08 | Decrypt corrupted ballot | Invalid |
| TLY-09 | Tally with unknown candidate | Invalid |
| TLY-10 | Publish before TALLIED | Rejected |
| TLY-11 | Publish approved results | PUBLISHED |
| TLY-12 | Verify valid snapshot | PASS |
| TLY-13 | Modify published snapshot | FAIL |
| TLY-14 | Verify with untrusted key | UNVERIFIED |
| TLY-15 | Unauthorized user reads audit | Rejected |
| TLY-16 | Search audit logs for secrets | No sensitive data |
| TLY-17 | Repeat finalized tally operation | No double counting |
| TLY-18 | Verify tally consistency equations | PASS |

---

## Open Design Decisions

OD-13:
Define the linearization of close versus
concurrent ballot submissions.

OD-14:
Define how final snapshots are frozen,
signed and independently preserved.

OD-15:
Define the isolated Tally execution mechanism.

OD-16:
Define approval and key-unlock responsibilities.

OD-17:
Define safe recovery from failed tally
and publication operations.

OD-18:
Define audit retention and tamper evidence.

OD-19:
Define which audit information
is accessible to each role.
