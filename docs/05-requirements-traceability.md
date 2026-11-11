
# Secure E-Voting System
## 05 - Requirements Traceability and Design Review

Version: 1.0
Status: Draft
Scope: UC-01 to UC-14

---

## 1. Requirements Traceability Matrix

| Business Rule | Security Requirement | Use Case | Test Case |
|---|---|---|---|
| BR-01 | SR-02 | UC-03, UC-07 | VOT-03 |
| BR-02 | SR-03 | UC-07 | VOT-06 |
| BR-03 | Application logic | UC-06, UC-11 | VOT-04, TLY-09 |
| BR-04 | SR-01, SR-06 | UC-06, UC-07 | SEC-08 |
| BR-05 | SR-01 | UC-08 | VOT-13, SEC-08 |
| BR-06 | SR-02, SR-04 | UC-07, UC-08 | VOT-07, VOT-09, VOT-10 |
| BR-07 | SR-07 | UC-04, UC-07, UC-08, UC-10 | VOT-12, TLY-03 |
| BR-08 | SR-03 | UC-08 | VOT-11, VOT-17 |
| BR-09 | SR-07 | UC-10, UC-11 | TLY-04 |
| BR-10 | SR-04 (partial) | UC-11 | TLY-07, TLY-08, TLY-09 |
| BR-11 | SR-04 | UC-09, UC-13 | VOT-16, TLY-13 |
| BR-12 | SR-07 | UC-04, UC-10, UC-11, UC-12 | ADM-10, TLY-02 |
| BR-13 | SR-06 | UC-07, UC-11 | TLY-06, TLY-16 |
| BR-14 | SR-07 | UC-01, UC-04, UC-10, UC-12, UC-14 | ADM-11, TLY-15 |

Notes:
- SR IDs originate from the revised project proposal.
- BR IDs originate from Functional Requirements.
- Test IDs reference the use-case specifications
  and the proposal security test plan.
- The mapping is preliminary and must be reviewed.
- Test references describe planned tests, not
  evidence of successful implementation.

---

## 2. Design Review Findings

### DR-01 - Credential Issuance Recovery

Priority: HIGH
Status: OPEN

Problem:
RA may successfully issue a blind signature,
but the Client may lose the response.

Risk:
A valid voter could permanently lose
the ability to cast a ballot.

Proposed direction:
Support idempotent retries of the exact
same blinded request, without authorizing
a second independent credential.

The recovery data must not reveal
the unblinded message, serial or vote choice.

Decision required:
Define request identity, retention,
atomic issuance and recovery behavior.

---

### DR-02 - Election State Consistency

Priority: HIGH
Status: OPEN

Problem:
RA and Voting must use a consistent election
state while remaining separate services.

Risk:
Voting may accept a ballot concurrently
with an election-closing operation.

Proposed direction:
Introduce an authoritative election-state
mechanism and transactional acceptance rules.

Voting acceptance and closing must have
a defined ordering.

Services must reject operations when
the trusted state cannot be verified.

Decision required:
Define state ownership, concurrency control
and communication between services.

---

### DR-03 - Receipt and Snapshot Integrity

Priority: HIGH
Status: OPEN

Problem:
A receipt alone cannot prove correct tallying.
A compromised server may alter or omit
records before publishing a snapshot.

Proposed direction:
Define deterministic receipt construction,
canonical snapshot serialization,
signed manifests and independent
preservation of published digests.

Decision required:
Define receipt format, publication timing,
snapshot signing and verification.

---

### DR-04 - Key Management

Priority: HIGH
Status: OPEN

Problem:
RA and Tally use separate private keys.
Tally must not expose its private key
to the online Voting Service.

Proposed direction:
Store private keys in separately protected
encrypted files for the local MVP.

Load the Tally key only inside an authorized
restricted process after election closure.

Decision required:
Define key generation, key identifiers,
passphrase handling, rotation and recovery.

---

### DR-05 - Privacy and Session Separation

Priority: HIGH
Status: OPEN

Problem:
The system must avoid directly linking
a voter identity with an encrypted ballot.

Risk:
Session cookies, IP addresses and timestamps
may weaken anonymity.

Proposed direction:
Separate RA and Voting authentication,
avoid shared identity cookies,
minimize request metadata and
prevent sensitive logging.

Decision required:
Define client session handling,
API separation and privacy logging rules.

---

## 3. Review Acceptance Criteria

- Every BR has a corresponding Use Case.
- Every critical BR has a planned test.
- Security Requirements are mapped.
- Conflicting workflows are identified.
- Open security decisions are documented.
- No unsupported security guarantees are claimed.
- Requirements are ready for workflow design.

## 4. Review Status

Overall: PENDING REVIEW

Next Phase:
P01.2 - Workflow and Sequence Design
