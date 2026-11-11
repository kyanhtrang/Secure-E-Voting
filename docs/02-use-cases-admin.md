
# Secure E-Voting System
## 02 - Administrative Use Case Specifications

Version: 1.0
Status: Draft
Scope: UC-01 to UC-04

---

## UC-01 - Create Election

### Actor
Election Admin

### Description
Create a new election with basic configuration.

### Pre-conditions
- Admin is authenticated.
- Admin has permission to create elections.

### Input Data
- Election title
- Description (optional)
- Planned opening time
- Planned closing time

### Main Flow
1. Admin opens Election Management.
2. Admin clicks Create Election.
3. System displays the creation form.
4. Admin enters election information.
5. Admin clicks Save.
6. System validates the input.
7. System generates a unique Election ID.
8. System creates the election with DRAFT status.
9. System records an audit event.
10. System displays the created election.

### Alternative Flow
- Admin cancels creation.
- System closes the form without saving.

### Exception Flow
- Missing title: validation error.
- Invalid date range: validation error.
- Unauthorized account: access denied.
- Database failure: transaction rolled back.

### Post-conditions
- A DRAFT election exists.
- No ballot has been accepted.
- No voter credential has been issued.
- An administration audit event exists.

### Business Rules
- Election ID must be unique.
- Initial status must be DRAFT.
- Closing time must be later than opening time.
- Only authorized Admin can create elections.

---

## UC-02 - Manage Candidates

### Actor
Election Admin

### Description
Add, update or remove election candidates.

### Pre-conditions
- Admin is authenticated.
- Election exists.
- Election status is DRAFT.

### Input Data
- Election ID
- Candidate display name
- Candidate description (optional)

### Main Flow
1. Admin opens an existing DRAFT election.
2. Admin selects Candidate Management.
3. System displays the candidate list.
4. Admin clicks Add Candidate.
5. Admin enters candidate information.
6. Admin clicks Save.
7. System validates the input.
8. System generates a unique Candidate ID.
9. System saves the candidate.
10. System updates the candidate list.

### Alternative Flow
- Admin updates an existing candidate.
- Admin removes a candidate before OPEN.
- Admin cancels without saving.

### Exception Flow
- Missing required data: validation error.
- Invalid Election ID: not found.
- Election is OPEN or later: modification denied.
- Unauthorized account: access denied.

### Post-conditions
- Candidate information is saved.
- Candidate belongs to the selected election.
- Modification is recorded in the audit log.

### Business Rules
- Each candidate has a unique identifier.
- Candidate must belong to an existing election.
- Candidate information cannot change after OPEN.
- At least one candidate is required before OPEN.

---

## UC-03 - Manage Voter Eligibility

### Actor
Election Admin (through authorized RA API)

### Description
Assign eligible voters to an election.

### Pre-conditions
- Admin has the required permission.
- Election exists and is DRAFT.
- Voter accounts already exist in RA DB.

### Input Data
- Election ID
- List of Voter IDs
- Eligibility status

### Main Flow
1. Admin opens Voter Eligibility Management.
2. Admin selects a DRAFT election.
3. Admin uploads a CSV file containing Voter IDs.
4. Admin UI sends the request to RA API.
5. RA validates Admin authorization.
6. RA validates Election ID and DRAFT status.
7. RA checks existing voter accounts.
8. RA checks duplicate records.
9. RA saves eligibility records in a transaction.
10. RA returns an import summary.
11. Admin views the import result.

### Alternative Flow
- Admin manually assigns an existing voter.
- Admin revokes eligibility before OPEN,
  provided no credential was issued.

### Exception Flow
- Unknown Voter ID: reject import.
- Duplicate Voter ID: reject import.
- Invalid CSV structure: reject import.
- Election is OPEN: modification denied.
- Unauthorized request: access denied.
- Database error: rollback.

### Post-conditions
- Eligibility records exist in RA DB.
- Voting DB does not store Voter IDs.
- No credential is issued during import.
- An audit event records the import result.

### Business Rules
- One eligibility record per voter/election.
- RA owns voter identity information.
- Voting Service cannot access RA DB.
- Admin UI cannot directly query RA DB.
- Import is all-or-nothing for MVP.
- Eligibility configuration freezes on OPEN.

---

## UC-04 - Open Election

### Actor
Election Admin

### Description
Activate a prepared election for voting.

### Pre-conditions
- Admin is authenticated and authorized.
- Election exists and is DRAFT.
- At least one candidate exists.
- At least one eligible voter exists.
- RA public key is available.
- Tally public key is available.
- Required election configuration is valid.

### Main Flow
1. Admin opens Election Management.
2. Admin selects a DRAFT election.
3. Admin clicks Open Election.
4. System checks Admin permission.
5. System validates election readiness.
6. System confirms the public-key metadata.
7. System verifies RA readiness.
8. System changes election status to OPEN.
9. System records an audit event.
10. System displays the OPEN status.

### Alternative Flow
- Readiness checks fail.
- System displays missing configuration.
- Election remains DRAFT.

### Exception Flow
- Election is already OPEN: conflict.
- Election is CLOSED: reopening denied.
- Missing candidate: opening denied.
- Missing eligible voters: opening denied.
- Missing or invalid public key: denied.
- Unauthorized Admin: access denied.
- Internal service unavailable: fail closed.

### Post-conditions
- Election status is OPEN.
- Election configuration is locked.
- Authorized voters may request credentials.
- Voting Server may accept valid ballots.
- Admin audit event is recorded.

### Business Rules
- Only DRAFT can transition to OPEN.
- State transition must be atomic.
- No election can be reopened after CLOSED.
- RA and Voting must use consistent
  Election ID, state and public-key metadata.
- RA cannot directly read Voting DB.
- Voting cannot directly read RA DB.

---

## Open Design Decisions

OD-01: Define voter account provisioning.

OD-02: Define the trusted election-state API
used by RA without sharing voter identities.

OD-03: Define the scheduled closing-time policy.

OD-04: Define how encryption keys are generated
and approved before opening.

OD-05: Define recovery if an election-state update
succeeds but a dependent service is unavailable.

---

## Initial Acceptance Tests

| ID | Scenario | Expected Result |
|---|---|---|
| ADM-01 | Create valid election | DRAFT created |
| ADM-02 | Create election with invalid dates | Rejected |
| ADM-03 | Add candidate in DRAFT | Success |
| ADM-04 | Update candidate in OPEN | Rejected |
| ADM-05 | Import valid voter IDs | Success |
| ADM-06 | Import unknown voter ID | Rejected |
| ADM-07 | Duplicate eligibility import | Rejected |
| ADM-08 | Open prepared election | OPEN |
| ADM-09 | Open election without candidates | Rejected |
| ADM-10 | Reopen CLOSED election | Rejected |
| ADM-11 | Unauthorized Admin action | Rejected |
