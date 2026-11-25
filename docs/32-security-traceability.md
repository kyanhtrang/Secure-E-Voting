# Phase 11 security requirements traceability and residual risk

Scope: reviewed source at main `9ce5571` plus the new **offline** local-demo
preparation. IMPLEMENTED means a control exists in source; TESTED means evidence
is identified in the scope column, not every possible environment is secure.
PARTIAL denotes a bounded demo control or unverified deployment prerequisite.
MISSING means no implemented guarantee is claimed. Hosted PASS is reported in
the supplied project context; this task does not independently inspect remote
run logs or claim a newly executed Windows/VM election.

| Requirement/control | Classification | Evidence and practical boundary |
|---|---|---|
| Default API auth and privileged services fail closed | TESTED | Existing default-app and explicit launcher tests; separate Admin/Tally/Publisher activation. No launcher/default-app edits in this phase. |
| Local deployment activation/approval | PARTIAL | New CLI can only create/check a public plan. Database provisioning, live collector and runtime adapter are MISSING; execution_ready is always false. |
| Configuration and source binding | TESTED | New strict plan/type/duplicate-field checks, environment rejection, source/lock/migration fingerprint and fixed diagnostics, offline only. Fingerprints are not attestation or signatures. |
| Offline review automation | IMPLEMENTED | New scoped Ubuntu workflow uses the standard-library CLI and policy/lifecycle tests only. No Docker/SQL/deletion commands; the new workflow itself has not run on Actions. |
| Signed election lifecycle and immutable configuration | TESTED | Existing Admin, RA publication, Tally and Board migrations/services; original hosted full-election gates retained. Admin cannot edit signed parameters after finalization. |
| Cross-database OPEN/CLOSE consistency | TESTED | Existing reconciliation/readiness and injected-permission-failure tests. Separate commits, not cross-database atomicity. A local adapter must retain these checks. |
| Two synthetic local voters | MISSING | Production demo SQL is single-subject. Hosted-only two-voter RPCs/session adapter are tested; guarded local installer/composition has not been implemented. |
| Voter/Admin/Tally password verification | TESTED | Existing DemoCredentialVerifier uses scrypt with per-verifier salt, separate verifiers and role/session checks. Not production identity proofing or MFA. |
| Failed-login abuse protection | PARTIAL | Existing five-failures/60-second process-local limiter and regression tests. No distributed/durable rate limit or internet abuse defense. |
| Canonical bearer digests and revocation | TESTED | RA SHA256(ASCII token) with canonical random token; separate adm1/tly1 domain-separated digests. DB-controlled 15-minute sessions, ownership/active/expiry/revocation checks. Memory-only browser tokens. |
| Publication enrollment/authorization | TESTED | Existing active Admin session plus explicit Publisher enrollment; Voter/Tally denied; 401/403/409/503 sanitized; UI confirmation is not authorization. |
| Restricted PostgreSQL authorization | TESTED | Applied SECURITY DEFINER ownership/fixed search_path/PUBLIC revocation and exact runtime capabilities, no general table DML. Prior real PG CI passed per context. Local live ACL validation remains pending. |
| Runtime login vs owner/migrator separation | TESTED | Existing role provisioning and real-gate checks. Ballot login legitimately inherits only ballot-service capability with SET=false/ADMIN=false; other extended runtime roles NOINHERIT/no memberships. New offline identity/binding tests reject owner/superuser/migrator substitution. |
| Legacy RA local factory depth | PARTIAL | Fixed DB/session/current-role checks exist, but the RA factories do not independently repeat owner/marker/version/effective-ACL checks per connection. Hosted guard wrappers provide stronger checks; new local adapters remain required. |
| Unsafe user DB rejection | PARTIAL | New contract requires generated local-only DB names, independent markers, owners and PG18 identity. Pure observation tests pass. No live collector/connection guard exists for this new local profile yet. |
| Runtime key/credential distribution | TESTED | New offline service-asset allowlists reject cross-service keys/roles; actual service boundaries already tested hosted. New VM filesystem/UID controls are not established. |
| Encrypted anonymous ballot storage | TESTED | Existing browser AES-256-GCM with RSA-OAEP-SHA256 wrapping, exact frozen envelope/hash/key binding and regression tests. Plaintext candidate validation occurs only in Tally. |
| RA credential cryptography | TESTED | Frozen RFC 9474 RSABSSA-SHA384-PSS-Randomized, RSA-3072/e65537, SHA384/MGF1, salt48/Prepare32; reviewed TS/CIRCL/Python vectors and hosted gates. Original blinded bytes, never their hash, reach BlindSign. No custom algorithm introduced. |
| Auth-to-ballot separation | TESTED | Existing typed payload, anonymous fetch credentials:omit, no bearer/cookies/identity fields on Voting or Board; real-gate passive assertions. Does not hide timing/IP metadata. |
| One credential per voter/election and exact retry | TESTED | Durable committed reservation before signer; DB uniqueness and locks, equality hash of original blinded bytes, successful issuance recovery, retained tombstones. Deadline expiry does not restore eligibility. |
| Recovery confidentiality/integrity | TESTED | Existing AES-256-GCM server recovery with context AAD; encrypted protected browser pending state. Local operator vault/restart custody is PARTIAL and needs approval. |
| Double voting and closing races | TESTED | Existing atomic acceptance, election lock, DB time, UNIQUE(election_id,serial), concurrency/rollback/closing tests and prior real PG gate. No duplicate-ballot insertion on recovery. |
| Receipts and uncertain HTTP outcomes | TESTED | Existing deterministic receipt/recovery, UI local recomputation, no automatic new serial/package after unknown outcome. Acceptance/inclusion does not prove counting correctness. |
| Closed-election Tally and explicit invalid counts | TESTED | Existing restricted Tally verifies stored proofs/config/envelopes, decrypts original matching key, classifies invalid reasons, accepted=valid+invalid and counted=sum(candidate counts). Key mismatch is integrity failure, not silently invalid ballot. |
| Tally idempotency/rollback/fencing | TESTED | Existing durable job/snapshot/report lifecycle, five-minute lease/fencing and concurrency tests. Retain original evidence/key through recovery. |
| Publication integrity and terminal state | TESTED | Existing TALLIED -> PUBLISHED transaction/row lock, exact stored Tally/snapshot/config/signatures, immutable audit/evidence, idempotent retry/concurrency. File/database partial failure fails closed. |
| Independent public verification | TESTED | Existing separate trust pins, JCS/hash/signature chain, full snapshot/receipt recomputation, unknown receipt classification and tampering/wrong-pin tests. No authority key fetched from Board establishes its own trust. |
| TLS / mTLS | MISSING | Existing local APIs use HTTP. No TLS certificate/CA/client-auth lifecycle or termination has been implemented. Do not call loopback HTTP encrypted transport. |
| Windows-to-VM communication | PARTIAL | Proposed host-key-pinned, demo-key-only SSH local forwarding; not installed/tested. Does not add internal service TLS or protect browser-to-local-forward plaintext from host compromise. |
| DB transport at rest/over loopback | PARTIAL | PG SCRAM and loopback/name/marker policies exist in reviewed CI. No local profile executed. Storage volume encryption/full-disk/VM encryption is not verified; never assume BitLocker. |
| Private-key at-rest loading | TESTED | Existing encrypted PKCS8 loaders and expected public-key matching. Only separate processes receive corresponding keys. No private key belongs in UI/Board/Voting. |
| Production key isolation and zeroization | MISSING | Local signer is not HSM/sandbox; keys/unlocks live in process memory. Same OS user/root can inspect them; Python/JS do not guarantee zeroization. |
| Key rotation, compromise and historical trust retention | PARTIAL | Key IDs/fingerprints and immutable election policy exist. No automated rotation/revocation/HSM ceremony. Retain old public trust for historical verification; do not replace keys mid-election. |
| Public privacy and correlation | PARTIAL | Board delays exposure until PUBLISHED and omits identity/precise acceptance time. Existing receipt contract needs encrypted envelopes, serials and proofs; small cohorts, traffic timing, shared recovery artifacts and later key compromise can correlate or disclose choices. |
| Full anonymity/coercion resistance | MISSING | No mixnet, anonymous network, coercion-resistant protocol or proof of unlinkability against a shared trusted operator. Do not claim these properties. |
| Complete E2E tally correctness | MISSING | Signed aggregate/receipt evidence is not a publicly verifiable proof of correct decryption/classification. No ZK decryption proof or individual plaintext is published. |
| Durable application audit | TESTED | Existing typed lifecycle, issuance, Tally and publication actor events and immutable normal-runtime restrictions. DB owner/root is still trusted; not independent WORM/global non-equivocation. |
| Secret-safe errors/logging | PARTIAL | Existing sanitized HTTP/gate diagnostics, no sensitive payload logging and no-store tests; new CLI emits fixed codes only. OS tracing, compromised dependencies and operators remain trusted. No new artifacts contain private data. |
| Dependency/image reproducibility | TESTED | Existing Python/npm/Go locks and fixed PG18 digest; source fingerprint includes locks. No dependency changes. Actual local image build/provenance/patch deployment remain pending. |
| Vulnerability/patch lifecycle | PARTIAL | Pinning and available dependency checks do not prove absence of CVEs, supply-chain compromise or need for reviewed updates. No new image scan/automatic update system. |
| Safe stop/rollback policy | TESTED | New pure ledger checks reverse startup order, one VM boot, non-root UID, PID/start ticks and unknown/refused resources. It sends no signals. Physical process/UID/registry handling remains MISSING for this profile. |
| Non-destructive DB stop and removal boundaries | PARTIAL | Proposed labeled named volumes preserve data on stop, unlike hosted tmpfs fixtures. New ownership/removal-review predicates tested offline; no delete/cleanup entrypoint or live remover. |
| Windows/VM OS and service isolation | MISSING | Dedicated VM, no shares/agent/Docker socket to apps and service UID/permission requirements are a reviewed design only. Existing hosted separate-process/database-role tests are not a Windows sandbox test. |
| Full local election operation | MISSING | Core real journey tested hosted per user context; new local adapter, installer, native runtime proof and physical cleanup/restart tests not executed. This is a review package, not a deployed demo. |

## Threats requiring deployment review

1. Wrong endpoint or stale ownership record: require both fresh engine identity and
   DB identity/independent marker on every actual connection, never trust a saved
   inspect file or user-supplied JSON as live proof. A compromised Docker daemon,
   VM root or controller is outside these guards' trust model.
2. Accidental destructive cleanup: keep stop separate from deletion. Preserve DB
   volumes, keys, private evidence, issuance tombstones and browser recovery data.
   A future cleanup tool must recheck every exact owned target and refuse unknown
   resources; no prune/wildcards or computed recursive deletes.
3. Privileged bootstrap leakage: retire/close migrator/superuser connections before
   runtime and never include their credentials in service pipes/configs. Runtime
   role flags, membership options and effective grants must be observed, not just
   inferred from role names. Never auto-grant to repair failed assertions.
4. Token/key confusion: separate Admin/Tally/voter sessions and verifiers, bind RA
   A/B to exact different voters, keep expected Tally RSA key stable after voting,
   and distribute all three Ed25519 public pins independently of APIs.
5. Restart errors: no new signing/recovery key or credential serial to compensate
   for missing state. Fail closed on missing artifacts/keys, preserve unknown
   outcomes and recover the exact committed issuance/receipt/report/publication.
6. Operator data leakage: synthetic-only usernames, IDs, candidates and keys;
   separate browser profiles; no private/credential artifacts, request body dumps,
   environment dumps or screenshots containing recovery material. Public export is
   explicit and still contains correlatable encrypted records/proofs.

The [startup/review guide](./31-safe-local-demo.md) distinguishes executable
offline checks, separately approved future actions and unimplemented prerequisites.
No production deployment, TLS, HSM, formal anonymity or complete E2E verifiability
claim follows from the classifications above.
