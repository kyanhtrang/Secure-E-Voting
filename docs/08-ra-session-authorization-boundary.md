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
- General RA function EXECUTE remains revoked from runtime and PUBLIC.
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

## 8. Local-only demo authentication

The default `backend.main.app` never enables authentication, including when
demo environment variables are present. Its login, me, and logout endpoints
return HTTP 503. Only the separate, explicitly activated local launcher
composes real demo dependencies; see [demo provisioning](09-ra-demo-provisioning.md).

The launcher binds to 127.0.0.1:8000 with one worker, proxy-header trust and
access logging disabled. It rejects non-loopback peers, unexpected Host
headers, and foreign Origin headers. It installs no CORS middleware.
Both --enable-local-demo and --load-local-verifier are required before reading
the fixed LOCALAPPDATA verifier JSON. Only expected verifier fields are used;
enable/local settings and the fixed identity are validated before a non-echoing
database password prompt. Database passwords are never loaded from that file.

Runtime connections authenticate directly as `ra_auth_login` to `ra_db` on
127.0.0.1:5432. The factory checks both session_user and current_user before
returning each connection and sets bounded statement and lock timeouts.
No runtime role switching, privileged login, or Voting connection is used.

The sole configured identity is `demo-local / demo-voter-001`. The existing
credential verifier and authentication service are reused. Dedicated demo
adapters call only the four `ra_demo` functions. The new revision extends
`a9c31d5e8b72`; it does not modify general RA function or table privileges.

### Token compatibility

Both token formats require exactly 32 random bytes in canonical unpadded
base64url encoding (43 characters). The general session service continues
to use SHA256(decoded token bytes). The dedicated demo session service
validates with the same canonical-token rules, then uses the existing demo
issuer contract: SHA256(token ASCII). No alternate-format database lookup
or fallback is attempted. Only the digest reaches PostgreSQL.

The existing issuance wrapper retains database-assigned creation time and
a 15-minute TTL. Verification checks active voter status, expiry, and
revocation in PostgreSQL and reuses application session validation.

### HTTP contract

| Request | Result |
|---|---|
| POST /api/v1/ra/auth/login | Existing 200 access_token / token_type="Bearer" response |
| GET /api/v1/ra/auth/me | 200 with voter_id only |
| POST /api/v1/ra/auth/logout | 204 with an empty body after successful database commit |
| Invalid login input in the enabled demo | Sanitized 422; input values are never echoed |
| Incorrect credentials | Generic 401 |
| Missing, malformed, unknown, expired, or revoked token on me | Generic 401 with WWW-Authenticate: Bearer |
| Malformed/missing bearer token on logout | Generic 401 |
| Unknown, expired, or already revoked canonical token on logout | 204, without revealing session existence |
| Trusted dependency/database/commit failure | Sanitized 503; never successful logout |
| Failed-login limit reached | 429 with Retry-After |

Bearer tokens are accepted only in one Authorization header, never cookies
or query parameters. All auth responses include Cache-Control: no-store
and Pragma: no-cache, including validation, disabled, and routing errors.
Passwords, tokens, database credentials, and internal exception text are
not logged. RA tokens must not be sent to Voting.

Revocation checks digest and fixed demo-voter ownership in one UPDATE.
It cannot revoke a session belonging to a different voter, and concurrent
logout changes the record only once. Revocation uses the database clock
and permits clearing sessions after voter disablement or expiry. A request
already authorized before a concurrent committed revocation may finish;
subsequent verification rejects the token.

### Failed-login limit and remaining risks

Five failed credential attempts within 60 seconds block subsequent attempts
until the oldest failure expires. The limiter shares one bucket across all
usernames and peers, stores no credentials, uses a monotonic clock and a
lock, and serializes attempts to prevent concurrent bypass. Success does
not clear failures; dependency outages do not count as credential failures.

This is an in-memory, single-process demo control. Restart resets the limit,
and a local caller can temporarily deny login to other local callers.
Anyone holding the database login can bypass HTTP password verification
and issue a session for the fixed demo voter. This remains unsuitable for
production authentication. No ballot linkage or general RA authorization
capability is added.
