# RA Authentication & Session Authorization Boundary

Status: DRAFT - Not approved for production

## 1. Client Input

POST /api/v1/ra/auth/login

The client may submit authentication credentials only.
The client must not choose voter_id, auth_provider,
auth_subject, is_active, or session privileges.

## 2. Trusted Authentication Flow

1. CredentialVerifier validates credentials.
2. CredentialVerifier produces VerifiedIdentity.
3. VoterAccountReader resolves (provider, subject).
4. The mapped voter must be active.
5. RASessionIssuer generates a random token.
6. PostgreSQL stores the token digest.
7. Only the RA token is returned to the client.

## 3. Database Boundary

- Runtime has no direct DML on ra.ra_sessions.
- Session functions use SECURITY DEFINER.
- Function search_path is fixed.
- EXECUTE remains revoked from runtime and PUBLIC.
- A trusted session issuance mechanism is required
  before any runtime EXECUTE grant is introduced.
- Session creation must not rely on an untrusted
  voter_id supplied by a client.

## 4. Session Validation

- Validate canonical token encoding.
- Compare token digest with the stored digest.
- Reject expired or revoked sessions.
- Reject sessions whose voter is inactive.
- Database failures must never authenticate a user.

## 5. Privacy

- RA tokens must never be sent to Voting Service.
- Never log passwords, bearer tokens, or secrets.
- RA must not store ballot choices or ballot serials.

## 6. Pending Security Decisions

- Identity Provider and verification protocol
- Trusted issuance capability and runtime grants
- Login rate limiting and abuse protection
- Final session TTL and renewal policy
- Token transport and logout behavior
- Active-session validation across concurrent changes
- Real runtime-login integration tests

## 7. Production Gate

Do not expose a real login endpoint until authentication,
authorization, transport security, and integration tests
are reviewed and approved.
