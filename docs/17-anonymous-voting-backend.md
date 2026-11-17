# Commit 6: anonymous ballot acceptance (human review)

This implements acceptance and protected receipt recovery, using the existing
Voting tables and the frozen [credential v2 verifier](../backend/crypto/credential_protocol.py).
It does not implement Tally, election administration, the public Board, or Voter
UI integration. No live election or results data is synthesized.

## Architecture and trust

The client retains its serial, envelope, prepared message and finalized signature
from the reviewed RFC 9474 flow. Voting receives only those anonymous objects.
The RA receives none of them through this service. Voting contains no BlindSign
operation, signing private key, RA session validation or RA routes.

The operator independently supplies a raw 32-byte Ed25519 **public** authority
pin. The signed manifest is read through a restricted Voting database function,
not accepted from the caller. Verification checks its signature, JCS bytes,
SHA-256 digest, authority fingerprint and election opening/closing times against
the database. The frozen verifier enforces RSA-3072/e=65537, SHA384,
MGF1-SHA384, PSS salt length 48, the exact 32-byte Prepare prefix, and the v2
message's election, serial, envelope/config hashes and RA key identifier.

The operator must install exactly the same independently authenticated frozen
manifest used for RA issuance in `voting.election_configs`, its digest in
`voting.elections`, and its exact UTC window in the election row. The existing
64-byte `config_signature` stores the detached manifest signature;
`config_signing_key_fingerprint` is SHA256(DER SubjectPublicKeyInfo of the Ed25519
authority public key), preserving the baseline metadata contract.
`config_signing_key_id` and `evidence_reference` remain operator evidence labels,
not trust anchors. No unsigned request key or API-supplied pin is trusted.
Configuration/key substitution fails closed. There is no key-rotation fallback;
new keys require a new reviewed frozen election, consistent with v2.

The older unimplemented configuration document describes an `EVOTE-CONFIG-v1`
signature and a different payload. This service deliberately accepts only the
already frozen v2 manifest contract (`EVOTE-MANIFEST-v1` signature context,
manifest version 1) in the baseline's byte/signature storage columns. It does not
reinterpret a legacy signature as a manifest signature. Future Board/Tally
integration must consume that same frozen manifest and digest.

Cryptographic verification is an application trust boundary. PostgreSQL does
not implement RSA-PSS or Ed25519. Possession of the Voting database credential
allows invocation of acceptance without the application verifier. This restricted
trusted service must therefore protect that credential; the function is not a
public database interface. A compromised Voting service/owner remains capable of
forging acceptance records. The client and future Board must independently check
credentials/receipts. This change does not claim malicious-server security.

## HTTP contract

`POST /api/v1/vote/ballots`, Content-Type exactly `application/json`:

```json
{
  "election_id": "canonical-lowercase-election-uuid",
  "credential": {
    "message": {
      "domain": "secure-evoting-blind-credential-v2",
      "version": 2,
      "election_id": "canonical-lowercase-election-uuid",
      "serial": "unpadded-canonical-base64url-of-32-bytes",
      "envelope_hash": "64-lowercase-hex-characters",
      "config_hash": "64-lowercase-hex-characters",
      "key_id": "verified-manifest-ra-key-id"
    },
    "prepared_msg": "canonical-base64url-of-prefix32-followed-by-exact-JCS-message",
    "signature": "canonical-base64url-of-384-byte-finalized-signature"
  },
  "envelope": {
    "schema_version": 1,
    "key_id": "verified-manifest-tally-key-id",
    "cipher_algorithm": "AES-256-GCM",
    "key_wrap_algorithm": "RSA-OAEP-SHA256",
    "nonce": "canonical-base64url-of-12-bytes",
    "ciphertext": "canonical-base64url-of-ciphertext-and-16-byte-tag",
    "encrypted_key": "canonical-base64url-of-384-byte-wrapped-key"
  }
}
```

The strings above are explanatory placeholders, not executable election data.
Every object's field set is exact. Duplicate JSON keys, invalid UTF-8, JSON
constants, padded/noncanonical base64url, noncanonical UUIDs and non-JCS signed
message bytes are rejected. Outer HTTP JSON may contain whitespace or reordered
fields; it is parsed strictly and the envelope is reconstructed with RFC 8785.
Only the signed canonical suffix and canonical binary encodings have a unique
wire representation. Envelope hash is SHA256(JCS(envelope)).

Limits: HTTP body 32768 bytes; canonical envelope 16384 bytes; decoded ciphertext
17..8192 bytes; prepared message at most 8192 bytes. These local-demo limits are
stricter than the existing storage ceiling. GCM-tag authenticity, OAEP
decryptability, plaintext schema and candidate validity are deferred to Tally.
A valid credential over structurally valid but undecryptable ciphertext may be
accepted and later classified invalid.

Requests with query parameters, Authorization/Proxy-Authorization, cookies or
the explicit voter/RA/username/request-ID headers are rejected before access to
the database. Unsupported body fields, including identity and issuance metadata,
are forbidden. Transport metadata cannot be exhaustively anonymized by a JSON
schema; clients must send none of it.

Responses (always `Cache-Control: no-store`, no input echo):

| Condition | HTTP | Body |
|---|---|---|
| New acceptance, after commit | 201 | `{"status":"accepted","receipt_hash":"<hex>"}` |
| Serial already accepted, including identical retry | 409 | Generic spent-credential error |
| Election not OPEN or outside DB time window | 409 | Generic election-not-open error |
| Invalid signature, binding, encoding or schema | 422 | Generic invalid-credential/ballot error |
| Identity headers/query metadata | 400 | Generic anonymous-request error |
| Oversized body / wrong Content-Type | 413 / 415 | Generic error |
| Disabled, unknown/unavailable election policy, DB/commit failure | 503 | Generic unavailable error |

`POST /api/v1/vote/ballots/receipt` takes the **same complete anonymous request**.
It revalidates the proof and envelope and returns HTTP 200 with the same receipt
only when the exact stored ballot exists. Missing or nonmatching record: 404.
Recovery works after election closing and never inserts a ballot. It is a
protected recovery operation, not a public Board/inclusion-proof API. No serial,
credential or receipt is placed in a URL. Dropped responses must not cause the
client to generate another serial or request another RA credential.

## Receipt and transaction boundary

The receipt follows [Document 08](08-encryption-ballot-submission.md), unchanged:

```text
receipt_object = {election_id, serial, envelope_hash, prepared_msg, signature}
receipt_hash = SHA256(UTF8("EVOTE-RECEIPT-v1") || 0x00 || JCS(receipt_object))
```

All receipt fields use fixed ASCII canonical encodings. Python and PostgreSQL
independently calculate the digest; PostgreSQL strips base64 line wrapping and
uses the exact JCS field order, without JSONB formatting. The integration harness
compares their output. The digest is not a signature or a proof of correct Tally.

After public cryptographic verification, the restricted acceptance function:

1. Locks the authoritative election row `FOR UPDATE`.
2. Locks its frozen configuration `FOR SHARE` and compares the verified digest.
3. Rejects a previously spent `(election_id, serial)`.
4. Reads `clock_timestamp()` **after the locks**, checks OPEN and
   `opens_at <= decision_time < closes_at`.
5. Inserts one existing `accepted_ballots` row and its deterministic receipt.
6. Returns internally; the psycopg connection context then commits. Only after
   context exit does the service return HTTP 201.

Lock order is election -> configuration -> accepted serial. The baseline's
`UNIQUE(election_id, serial)` and unique receipt constraint remain intact.
`accepted_at` retains its database-generated default. Failed transactions consume
no serial. Uncertain commit outcomes return 503 and require receipt recovery.
The decision deadline is not a promise that commit completed before closes_at.

Future election-closing code must lock/update the same election row. Closing
first rejects acceptance; acceptance first commits before closing can proceed.
The migration prevents updates to frozen configurations and changes to election
digest/window after DRAFT. No runtime can delete configurations; trusted owners
retain their existing fixture/deployment powers. Trusted owners must not reset a
live election to DRAFT, delete/reinsert its policy or reopen an election.
Administrative lifecycle authorization is still pending.

## Migration and least privileges

New [revision d8f27a4c610b](../migrations/voting/versions/d8f27a4c610b_anonymous_ballot_acceptance.py)
follows `b5bd58a07ceb`. No applied revision, table, constraint or RA schema is
modified. It creates five functions and two update guards; no duplicate ballot
table, custom crypto or PostgreSQL extension is introduced. Downgrade is refused.

Required pre-existing roles come from the baseline ACL and database design:
`voting_owner`, `voting_admin_service`, `voting_ballot_service`,
`voting_snapshot_worker`, `voting_tally_worker`, `voting_publication_service`,
`voting_board_reader`, `voting_audit_reader`. Owner and ballot group must be
NOLOGIN and must lack superuser/createdb/createrole/replication/bypassrls flags.
If the dedicated `voting_ballot_login` already exists, the preflight verifies it
too. This migration creates or alters no role.

Every function is owned by `voting_owner`, SECURITY DEFINER, with fixed
`search_path=pg_catalog,voting,pg_temp` and qualified object references. PUBLIC
and all baseline worker EXECUTE grants are explicitly revoked. Only these three
functions are granted to `voting_ballot_service`, plus schema USAGE:

| Function | Permission / operation |
|---|---|
| `ballot_policy(uuid)` | Read one public frozen manifest and its window |
| `accept_anonymous_ballot(uuid,bytea,bytea,bytea,bytea,bytea)` | Atomic acceptance |
| `recover_ballot_receipt(uuid,bytea,bytea,bytea,bytea,bytea)` | Exact-record receipt recovery |
| `_ballot_receipt(uuid,bytea,bytea,bytea,bytea)` | Internal owner-only helper |
| `guard_frozen_config()` | Internal owner-only trigger function |

Preflight rejects missing roles, unsafe memberships, schema CREATE, direct
table/column/sequence privileges, pre-existing runtime function access and wrong
table ownership. Postflight rejects unexpected function EXECUTE ACL entries.
It fails closed rather than silently repairing deployment permissions.

Provision the runtime login separately: restricted LOGIN with inherited ballot
group privileges, no other membership, no owner/migrator/RA access, no schema
CREATE or direct table privileges. Give it CONNECT only to the Voting database;
deny RA access via database ACLs and pg_hba. No generic RA function grants are
needed. Production role provisioning is outside this change.

## Explicit local deployment and UI integration

Default [backend.main.app](../backend/main.py) keeps RA auth disabled and exposes
Voting only through its unavailable dependency. Start the separate local process
only after a human approves deployment, installs the migration and provides
verified election configuration:

```powershell
python -m backend.voting.local_launcher --enable-local-voting --manifest-authority-pin C:/trusted/manifest-authority-public.bin
```

The only file read is the explicitly supplied **public** pin. The DB password is
prompted with non-echoing getpass, held in memory and never read from local secret
files, printed, logged or placed in shell arguments. Runtime is fixed to
`voting_ballot_login` on loopback `voting_db`; owner/migrator/superuser identities
are refused. Effective table privileges and unexpected memberships/functions are
checked. Uvicorn binds 127.0.0.1:8001 with proxy-header trust and access logging
disabled, one worker, no CORS middleware, no API docs, and strict local Host/
same-origin checks reused from the RA demo middleware. It has no RA endpoints.

Future UI work must use a **separate anonymous client**, `credentials: 'omit'`, no
Authorization header, no RA client interceptor, no identity/query metadata, and
retain the exact pending proof/envelope until receipt recovery succeeds. An
explicit same-origin development proxy can target the Voting process; do not
forward RA headers/cookies or weaken CORS. Browser integration is not implemented
here. UI must compare receipts locally using the existing definition.

## Disposable PostgreSQL tests (NOT EXECUTED)

[The harness](../scripts/voting_disposable_integration.py) refuses `ra_db`,
`voting_db`, wrong names and missing/mismatched independent database comments.
Every fixture, runtime and cleanup connection checks BOTH:

* A unique database name `voting_demo_test_<random_suffix>`.
* Its comment `secure-evoting-disposable:<independently-created-canonical-UUID>`.

Use a fresh isolated PostgreSQL 18 container with SCRAM host authentication, no
host data mounts, only a random 127.0.0.1 port, generated test passwords and no
real keys/data. Provision the eight NOLOGIN roles above, a restricted
`voting_migrator_login` with SET-only owner membership, and a restricted
`voting_ballot_login` with INHERIT-only ballot membership. Allow at least 24 test
runtime connections for the 20-way test. Revoke PUBLIC database CONNECT/CREATE,
public-schema CREATE and generic worker rights; grant database CONNECT only to
the two test logins. Create schema `voting` owned by `voting_owner`. Install the
independent name/comment before running any helper. Keep bootstrap/fixture
credentials separate from the runtime password. Remove the entire owned
container/database after validation; never reuse the user's PostgreSQL instance.

The separately guarded [migration runner](../scripts/voting_disposable_migrate.py)
uses a [test-only Alembic environment](../scripts/ci_voting_migrations/env.py),
never the existing production environment hardcoded to `voting_db`. It applies
the real chain in order: `643decaa90ab` -> `b5bd58a07ceb` -> `d8f27a4c610b`.
It performs no role/database provisioning and accepts passwords only by prompt.

**Only after explicit human approval**, from the repository with the existing
locked Python application/crypto/psycopg/Alembic dependencies installed:

```powershell
python scripts/voting_disposable_migrate.py --allow-disposable-migrations --database voting_demo_test_REPLACE_WITH_LOWERCASE_SUFFIX --marker REPLACE_WITH_CANONICAL_UUID --port REPLACE_WITH_ISOLATED_LOOPBACK_PORT
python scripts/voting_disposable_integration.py --allow-disposable-database --database voting_demo_test_REPLACE_WITH_LOWERCASE_SUFFIX --marker REPLACE_WITH_CANONICAL_UUID --port REPLACE_WITH_ISOLATED_LOOPBACK_PORT
```

These placeholders deliberately fail designation checks until replaced. Do not
use the production Alembic configuration for disposable tests. No password goes
into these commands. No migration or PostgreSQL connection was executed during
implementation.

Prepared integration coverage: full HTTP acceptance, real SQL/Python receipts,
20 simultaneous same-serial requests (one 201, nineteen 409, one stored row),
exact duplicate retry, independent encryptions of identical choices, invalid
bindings, forced rollback, real committed-response-loss recovery, both election
lock orders, OPEN-but-expired/not-yet-open windows, PUBLIC/other-worker/helper
EXECUTE denial, actual runtime table access denial, immutable config updates,
and cleanup of only newly created fixture elections. Generated final-PSS test
fixtures validate acceptance, not blind issuance; unchanged Gate 1/Gate 2 remain
the evidence for actual RFC BlindSign and authorization.

The harness prints PASS only after its assertions execute; cleanup is scoped to
new random fixture election IDs and independently guarded again. It never edits
a voter, touches RA or deletes unrelated records. Failed cleanup makes the run
fail. Real concurrency, migration execution and effective ACL behavior remain
**pending**, and no new GitHub PostgreSQL run is claimed.

## Privacy and remaining limitations

No ballot contains voter identity or RA tokens. The launcher suppresses access
logs and errors are static. This does not hide IP addresses, network timing,
precise DB timestamps or operator-controlled proxy logs. Local co-location and
colluding RA/Voting observers may correlate issuance and submission. Sharing a
receipt can link a person to an encrypted ballot. No full anonymity, coercion
resistance, receipt freeness or full end-to-end verifiability is claimed.

Credential expiry is election-window expiry: frozen v2 has no independent expiry
field. Recovery after close is read-only and cannot extend voting. Denial of
service, key compromise, authority equivocation, protected key lifecycle and
production deployment/network hardening remain separate concerns. No decryption,
candidate-choice proof, tally, publication, election provisioning or public
receipt-inclusion proof is included. Real PostgreSQL validation is a required
next gate before live use.

## Actual local validation

Final complete database-free regression: **504 passed in 14.10 seconds** (original
424 plus 80 new tests), including the real TypeScript client/RFC-vector tests.
Commands executed from this branch's worktree:

```text
npm --prefix crypto_interop ci --ignore-scripts
npm --prefix crypto_interop run build
python -m pytest tests/ crypto_interop/ -q
python -m compileall -q backend/voting scripts/voting_disposable_integration.py scripts/voting_disposable_migrate.py scripts/ci_voting_migrations migrations/voting/versions/d8f27a4c610b_anonymous_ballot_acceptance.py
git diff --check
```

`EVOTE_TEST_NODE` selected the existing Node 24.22.3 executable; Python was
3.11.9 with the existing locked application and crypto dependencies. The
TypeScript locked install/build and Python compilation passed. SQL contracts,
actual revision-chain inspection and migration SQL capture are database-free;
they do not establish that PostgreSQL accepts or executes the new SQL.

Existing tests/assertions, RA authentication, frontend, applied migrations,
dependency locks and frozen cryptographic sources were compared with HEAD and
remain unchanged. Source review and a changed-file secret/whitespace scan found
no embedded credentials, private keys or generated test secrets. No PostgreSQL
connection, migration, native Go execution, commit, push or merge occurred in
this task. Frontend/browser tests were not rerun because no frontend changed.
Previous Gate 1/Gate 2 CI passes are supplied context, not new execution evidence.

## Files changed

One existing file modified; fourteen files added:

| Area | Files |
|---|---|
| Disabled default integration | [backend/main.py](../backend/main.py) |
| Anonymous API and verification | [ballot_router.py](../backend/voting/ballot_router.py), [ballot_service.py](../backend/voting/ballot_service.py) |
| Restricted store and local launcher | [postgres_ballot_store.py](../backend/voting/postgres_ballot_store.py), [local_launcher.py](../backend/voting/local_launcher.py) |
| Forward migration | [d8f27a4c610b_anonymous_ballot_acceptance.py](../migrations/voting/versions/d8f27a4c610b_anonymous_ballot_acceptance.py) |
| Guarded real integration | [voting_disposable_integration.py](../scripts/voting_disposable_integration.py) |
| Guarded test migration entrypoints | [voting_disposable_migrate.py](../scripts/voting_disposable_migrate.py), [env.py](../scripts/ci_voting_migrations/env.py) |
| HTTP, crypto, store, runtime and safety tests | [test_voting_ballots.py](../tests/test_voting_ballots.py), [test_voting_store_runtime.py](../tests/test_voting_store_runtime.py), [test_voting_disposable_safety.py](../tests/test_voting_disposable_safety.py), [test_voting_migration.py](../tests/test_voting_migration.py), [voting_helpers.py](../tests/voting_helpers.py) |
| Architecture and validation report | [this document](17-anonymous-voting-backend.md) |

**Human approval gate:** review the new SQL, runtime trust boundary, deployment
role provisioning and disposable setup before authorizing migration execution.
Real PostgreSQL tests, election-policy installation and frontend/Board/Tally
integration remain pending. This implementation is not approved for live voting.
