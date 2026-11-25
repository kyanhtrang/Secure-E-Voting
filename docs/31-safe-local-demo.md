# Phase 11 — safe local-demo preparation and human review

Branch `feat/security-local-demo`, base `9ce5571`. This package is **offline
preparation**, not an installed or runnable local election deployment. The public
plan, validators and lifecycle ledger perform no PostgreSQL, Docker, network,
process-start/stop, key-generation or deletion operations. Separate approval is
still required before any local database action.

The supplied project context reports passing hosted real E2E gates, including
Admin UI publication. Those results support the existing application components;
they do not establish Windows/VM deployment safety. This task does not rerun or
reinterpret historical reports as new local integration PASS.

## Audited compatibility and architecture

The source audit found these constraints:

| Component | Existing behavior | Consequence for this profile |
|---|---|---|
| RA authentication/issuance launchers | Fixed 127.0.0.1:5432/ra_db; explicit private prompts; production demo SQL permits only demo-voter-001. | Never point them at a user DB or relax their checks. A separately reviewed local adapter and guarded two-subject installer are prerequisites. |
| Voting launcher | Fixed voting_db:5432, ballot role/ACL checks, no RA auth. | Needs an injected, locally owned disposable destination, not a port/name substitution in the old launcher. |
| Admin launcher | Fixed RA/Voting DB-role map, interactive verifiers/authority key; both DBs at localhost:5432. | Cannot directly address two isolated instances with generated DB names. Compose the existing service with guarded factories in a new adapter. |
| Tally / Publisher / Board | Fixed voting_db:5432 and restricted separate logins; Tally/Publisher private prompts, independent public pins. | Keep factories and key boundaries; do not widen accepted destinations in these launchers. |
| Native CIRCL | Reviewed RSA-3072/e65537 BlindSign on original 384 blinded bytes, private stdin configuration. | Build/run native Linux helper inside the dedicated VM, without changing Windows Application Control. |
| Vite | Binds loopback; exact Publisher proxy, separate anonymous Board/Voting requests, no broad CORS or Origin rewrite. | Run unchanged loopback Vite instances in the VM. Tunnel the same UI ports to Windows. |
| Hosted coordinators | Explicitly require GitHub-hosted Linux, owned PG18 markers and automatic disposal. | Do not impersonate Actions, call them as local deployers or remove their guards. Extract reusable provisioning/composition behind a new reviewed local entrypoint later. |

Historical [RA provisioning instructions](./09-ra-demo-provisioning.md) target
ra_db and an older single-voter milestone. They are not this deployment recipe.
Applied migration history, existing launchers, protocols and CI gates remain
unchanged by this package. The RA local connection factories currently check the
fixed database/session/current role, but do not repeat the full owner/marker/
version/effective-ACL checks used by guarded hosted coordinators. They are not a
sufficient destination guard for this new deployment.

Proposed boundary: **Windows 11 browser -> explicit SSH local forward -> a
dedicated Ubuntu 24.04 VM -> loopback Vite/services -> two owned PostgreSQL 18
containers**. VM creation, hypervisor availability, SSH configuration and local
runtime adapters are not implemented or verified here. The profile chooses this
boundary to separate Linux loopback from Windows' existing PostgreSQL sockets
and run the already reviewed native Linux signer. It is an explicit design
assumption for review, not a claim that a VM already exists.

No host shares, host DB forwarding, personal SSH keys/agent, Docker socket mounts
to applications, host networking or broad filesystem mounts are permitted in the
proposed profile. A future installer must establish/verify these properties; a
boolean in a JSON plan does not establish OS isolation.

## Executable offline commands — safe to review now

The CLI has only `new` and `check`. It uses the Python standard library and reads
only explicitly listed repository source/migration/lock files and the explicitly
named public plan. It never discovers dotenv, LOCALAPPDATA verifier files,
database credentials or user key material. It rejects ambient PG, Docker and
application-demo configuration rather than silently inheriting it.

From a clean terminal and this checkout:

```powershell
python -I -S scripts/local_demo_preflight.py check `
  --public-plan deployment/evote-local-demo-plan.json
```

Expected successful status is `OFFLINE_VALIDATED_NOT_DEPLOYED`, with
`execution_ready:false` and a public plan digest. For a new proposed deployment,
generate fresh public IDs in a new **public-only** review directory:

```powershell
$reviewDirectory = Join-Path $env:TEMP ('evote-review-' + [guid]::NewGuid())
New-Item -ItemType Directory -Path $reviewDirectory
python -I -S scripts/local_demo_preflight.py new |
  Set-Content -LiteralPath (Join-Path $reviewDirectory 'evote-local-demo-plan.json') -Encoding utf8
python -I -S scripts/local_demo_preflight.py check `
  --public-plan (Join-Path $reviewDirectory 'evote-local-demo-plan.json')
```

If preflight refuses inherited configuration, use a separate clean terminal;
do not print or copy environment values. A plan check refuses other filenames
before opening them, rejects symlinks/reparse points, bounds JSON to 32 KiB and
rejects duplicate/unexpected fields. Refusals output fixed codes only. Source
fingerprints normalize CRLF for cross-platform comparison and bind selected
public sources plus all 21 reviewed migrations and dependency locks. They are
review fingerprints, not signatures, live attestation or permission to deploy.

Do not put passwords, tokens, verifier contents or keys in the public plan. Its
IDs identify **proposed synthetic fixtures**, not existing voter records. The
checked-in plan is an unprovisioned example/review artifact; create a fresh plan
for an approved deployment. Changing a target, role, key boundary, source or
execution flag fails the exact contract. There is no start/migrate/cleanup CLI.

## Deployment configuration inventory

| Item | Required value/source | Status |
|---|---|---|
| Deployment/profile ID | Fresh UUID4; source-bound public plan. | Offline generated/tested. |
| RA DB | ra_demo_local_ plus profile hex; ra_owner; VM loopback port 55432; independent UUID comment marker. | Proposed; not created. |
| Voting DB | voting_demo_local_ plus profile hex; voting_owner; VM loopback port 55433; a different marker. | Proposed; not created. |
| PG containers/image | Exact generated names/IDs, purpose/profile/kind/marker labels; immutable PG18 image read from reviewed CI source. | Predicate tests only; no inspect/pull/run performed. |
| PG volumes/network | Dedicated labeled local-driver named volumes without host device options; isolated labeled bridge; no auto-remove. | Proposed; no resources exist. |
| Runtime adapters | Existing app/service factories with new verified local connection factories, no general URL parameters or environment fallback. | **MISSING; must be reviewed before startup.** |
| Two voters | Generated distinct IDs, active=true, demo-local/demo-voter-001 and demo-voter-002; separate RA processes/verifiers and Chromium profiles. | **Local installer MISSING.** Existing hosted fixture semantics reviewed. |
| Admin/Tally/Publisher | Fresh separate operator/verifier data; explicit Publisher enrollment of the synthetic Admin, inactive by default otherwise. | Trusted fixture provisioning pending approval. |
| Private RSA keys | Fresh RA signing and Tally decryption keys, RSA-3072/e65537, encrypted PKCS8; retain the exact Tally key signed into the manifest. | Generate once only after approval. |
| Ed25519 keys | Three distinct fresh authorities: manifest, snapshot/report, publication. Independent public pin distribution. | Generate once only after approval. |
| Recovery material | Persistent RA AES recovery key in an encrypted operator-managed vault; browser encrypted pending-state files/passphrases kept separate per synthetic voter. | Operator custody/restart handling pending review. No new encryption format invented. |
| UI ports | Admin/Tally/Public 5173, Voter A 5174, Voter B 5175; matching same-port Windows loopback forwards. | Proposed; availability untested. |
| Service ports | RA A 8000, RA B 8003, Voting 8001, Admin 8002, Tally 8005, Board 8006, Publisher 8007; all VM loopback. | Proposed; no listeners started. |

Runtime role/key capabilities are encoded in the public plan and
[policy](../deployment/local_demo_policy.py). Admin gets voting_admin_login and
ra_election_publisher_login plus the manifest authority; RA A/B get only auth and
issuance logins plus RA signing/recovery material; Voting gets ballot login and no
private keys; Tally gets tally login plus decryption/evidence keys; Publisher gets
publication login/key and **read-only** original evidence; Board gets board login
and public pins only. Vite gets public origins/pins, no DB/key assets. Runtime
must never receive postgres, owner or migrator credentials. Provisioning/migration
credentials are confined to a separate trusted one-time phase, then closed.

The exception to NOINHERIT is the existing ballot login's exact capability
membership: voting_ballot_service, ADMIN=false, INHERIT=true, SET=false. Preserve
the reviewed full-gate role/ACL assertions; do not repeat the previously corrected
blanket no-membership assertion. PUBLIC EXECUTE remains revoked, fixed safe
SECURITY DEFINER search paths/owners and no runtime table DML remain required.

## Approval gates and startup prerequisites

1. Review this profile and the [traceability assessment](./32-security-traceability.md).
   A digest identifies reviewed public contents; it is not a secret authorization
   token. Approval to review is not approval to provision.
2. Separately approve a dedicated VM and demo-only SSH credentials/host pin. Do
   not use default personal key discovery, agent forwarding, host shared folders
   or expose the VM services on a LAN interface. The future tunnel configuration
   must use explicit demo identity/known-host files, strict host-key checking,
   ExitOnForwardFailure and 127.0.0.1 same-port forwards for the three UI ports.
   TLS is not implemented by this design; a verified SSH tunnel is a distinct,
   still-unimplemented transport control.
3. Review/implement the local controller, **before approving database actions**.
   It must validate the actual VM/engine, fresh owned container IDs, image digest,
   independent marker, owner, current DB/session/current role and PG18 on every
   connection. The pure observation validators here do not collect/authenticate
   that evidence. Their normalized projections must retain all mounts and every
   explicit environment override relative to the inspected pinned image; they
   are not raw Docker inspect parsers. Runtime effective ACL checks must reuse
   reviewed SQL semantics and fail closed on unknown observations.
4. Separately approve isolated PostgreSQL creation, role setup and migration
   execution. Require an initially fresh target, not merely a matching name.
   Apply RA's 14 baseline revisions through c84e13b9702d plus Admin RA
   bf932d0f8702 (15 total); Voting 643decaa90ab -> b5bd58a07ceb -> d8f27a4c610b ->
   Admin af821c9e7601 -> Tally e6a90c72b541 -> Board f8b31c2d970a (6 total).
   No applied revision is edited. A new guarded local Alembic environment is
   required; the hosted CI environments/entrypoints must not be bypassed.
5. The local two-voter installer must reuse the reviewed hosted DDL/session
   semantics only inside this newly verified RA database, after checking exact
   voter/provider/subject mappings and RA head. Never replace ra_demo functions.
   Grant only the four existing test RPC capabilities to ra_auth_login, fixed
   search_path/ra_owner ownership, PUBLIC revoked, no tables/general RA RPCs.
   Verify cross-voter/third-subject/expired/revoked denials and original demo SQL
   unchanged. Do not run hosted install() locally by spoofing its guards.
6. Generate fresh keys, verifiers and distinct service credentials privately
   after approval. Use encrypted key files outside Git, Linux-private directories,
   private prompts/pipes and no secret environment/argv. Keep the original keys
   across stops/retries; losing recovery state cannot reset eligibility. Build
   native CIRCL inside the VM with the existing pinned Go module/locks. Verify
   runtime binary provenance, independent public pins and key fingerprints before
   enabling services. Windows Application Control stays unchanged.

Steps 2–6 are **not performed or implemented by the offline CLI**. No misleading
`docker compose up` or local migration command is supplied. The deployment is
blocked until the controller/collector/runtime adapters/two-voter installer and
their real isolated integration tests are reviewed. A one-command local demo is
not delivered or claimed in this phase.

## Reproducible election procedure after those gates pass

1. Verify owned DBs/volumes/markers and stored keyset; start only Voting, Admin,
   Tally, Publisher, Board and Admin Vite, checking each before the next. The
   [ledger](../deployment/local_demo_lifecycle.py) models this order. On failure,
   collect stop intents only for already recorded, freshly matched process refs.
2. Open Windows loopback Admin UI through the approved tunnel; authenticate the
   synthetic Admin. Create a real draft, two explicitly synthetic candidates A/B,
   and a short future voting window; use the approved public keyset. Keep the
   window long enough for two voters, not dependent on a race with a deadline.
3. Finalize in the actual Admin UI. Verify the signed manifest/config hash and
   key fingerprints. Capture the real election UUID; do not invent election rows.
4. A separately trusted fixture action binds only the two synthetic voters to
   that election via the existing eligibility-management function. Explicitly
   active voter fixtures only; no updates to a pre-existing voter or election.
5. Start the two bound RA processes/native signers and their Vite origins using
   the exact frozen election and persistent recovery key. Open/reconcile the
   election through Admin. Do not proceed while RA readiness is false.
6. In a fresh browser profile for A, use Voter A's loopback port and credentials;
   select A, encrypt/prepare, protect pending state, request blind signing,
   finalize/verify and submit anonymously. Record/verify receipt locally.
7. Repeat independently as B at Voter B's origin/profile, selecting B. Verify
   distinct receipts and exactly one authorized credential per voter/election.
   Do not reset fixtures or seed accepted ballots as a shortcut.
8. Confirm both acceptance receipts; verify duplicate 409 and unknown-response
   recovery through the same credential, never a new serial. No RA bearer/cookie
   goes to Voting. Do not claim acceptance proves counting.
9. Close/reconcile through Admin. Failed reconciliation stays fail closed. Sign
   in as the separate Tally operator, run the real restricted service, verify
   accepted=valid=counted=2, invalid=0 and A=1/B=1 plus snapshot/report signatures.
   An invalid ballot must remain explicitly invalid, not silently dropped.
10. Sign back into Admin Publication as the explicitly enrolled synthetic Admin.
    Confirm publish. Observe authoritative PUBLISHED after refresh, not just a
    successful transport response. No Tally/private publication key enters UI.
11. Open public results with no Admin session; independently verify the evidence
    using separately installed public pins and both receipts. Unknown receipt is
    NOT_FOUND only after verifying the whole snapshot. Retain public evidence if
    desired; do not export tokens, private keys or individual selections.
12. Log out roles, close browser contexts and tunnel. Stop owned runtime services
    in reverse order after fresh boot ID/PID/start-tick/registry/OS-owner checks.
    Stop the owned PG containers explicitly only when intended: dedicated named
    volumes preserve DB state. Never automatically remove containers, volumes,
    key material, tombstones or evidence on success, failure or Ctrl+C.

No demo above has executed locally. These acceptance steps must be exercised in
the approved new isolated local runtime before calling the guide operational.

## Shutdown, removal and incident handling

The ledger models stop intents, not OS signals. It requires non-root runtime
UIDs and one VM boot per ledger. It refuses changed boot IDs,
reused PIDs/start ticks, wrong profile and missing observations; unknown resources
are preserved and reported. It has no database entries. A real adapter must
record creation before readiness checks, handle failure during creation, verify
the OS owner/private registry and use a stable OS process handle (such as a
verified Linux pidfd) before any stop. A /proc check followed by kill(pid) alone
has a PID-reuse race. Those
physical guarantees remain unimplemented. No Windows taskkill/delete pipeline,
Docker prune, compose down -v or recursive deletion is part of this package.

Container stop is distinct from removal. The removal-review function requires a
separate exact confirmation bound to the public plan digest and both container
and volume proofs. It returns identifiers only; it executes nothing. A future
remover still needs fresh live proof and separate interactive human approval.
Do not delete on stale inspect files or user-supplied JSON; verify that no
unrelated resource is attached to a volume before any removal. The network and
private key/evidence stores need their own ownership review and removal approval;
they are not included in that function's result. If uncertain, stop preparation
and preserve resources for review, not broad cleanup.

On interrupted issuance retain the exact protected client request/inverse/prefix,
server recovery key and reservation tombstones. On interrupted voting recover the
same receipt. On interrupted Tally retain key/snapshot/report evidence and fencing
state. On interrupted publication refresh authoritative status and reuse only the
same immutable package. Missing/compromised keys or conflicting evidence fail
closed; do not replace signed parameters to force a successful demo. Suspected
key compromise requires halting and a separately reviewed new synthetic deployment,
not resetting this election's eligibility or rewriting evidence.

## Human-review deliverables and actual validation

New files only (nine):

- [Offline policy and inventory](../deployment/local_demo_policy.py).
- [Pure startup/stop ledger](../deployment/local_demo_lifecycle.py).
- [Public-only CLI](../scripts/local_demo_preflight.py).
- [Unprovisioned public review plan](../deployment/evote-local-demo-plan.json).
- [Policy/preflight tests](../tests/test_local_demo_policy.py).
- [Lifecycle tests](../tests/test_local_demo_lifecycle.py).
- [Scoped offline CI contract](../.github/workflows/local-demo-preflight.yml).
- [This guide/review report](./31-safe-local-demo.md).
- [Security requirements matrix](./32-security-traceability.md).

The new CI job checks only the offline public plan and policy/lifecycle tests on
Ubuntu, with pinned Actions/Python, contents:read, existing locked dependencies,
no repository secrets/artifact upload and no Docker/SQL/cleanup command. It runs
on push only to this feature branch plus manual dispatch. Existing workflows are
untouched. It has not executed; it does not claim Windows VM integration.

Actual checks on this checkout (not combined counts from older branches):

| Check | Result |
|---|---|
| Complete backend/crypto pytest | 1,086 passed, including 67 new policy/lifecycle/CLI regressions. |
| Frontend unit/component/crypto | 167 passed, 12 files. |
| Authentication / Voting / Admin / Tally / Board browser suites | 7 / 7 / 4 / 2 / 3 passed (23 total), existing synthetic-service suites. |
| TypeScript frontend checks + production build | PASS. |
| Crypto TypeScript build + recovery tests | PASS, 2 recovery tests passed. |
| Standard-library-only preflight | `python -I -S` check returned OFFLINE_VALIDATED_NOT_DEPLOYED / execution_ready=false. Stale source-bound plan correctly refused; regenerated public example validates. |
| Dependency integrity | Both locked npm installs/trees, pip check and reviewed backend version checks PASS; no dependency/lock edits. |
| Syntax and graphs | 170 Python, 8 JSON, 12 YAML and 81 Bash scripts/bodies parsed; unchanged RA 15 and Voting/Board 6 revisions. |
| Existing tracked files and gates | Unchanged; only nine new files. |
| Changed-source secret scan / diff whitespace | PASS; no detected embedded credentials/key material. |
| Native Go, actual VM/Docker/PG provisioning, migrations and physical process cleanup | NOT RUN; no such local operation authorized. |
| New offline Actions workflow | NOT RUN; requires human-reviewed publication of the branch. |

Local toolchain: Python 3.11.9, Node 24.22.3, npm 11.19.1. Existing browser
configuration used Windows Edge; the new policy CI job targets Ubuntu and does
not provision the proposed VM. Python regression imports used the existing
supported PSYCOPG_IMPL=python/libpq18 path under Windows Application Control;
loading a client library is not a database connection. No security setting was
changed. The existing Vite blindrsa browser-externalization notice remains; the
unchanged frontend tests/build pass. Existing crypto tests use generated test
material only; the new preflight never generates/loads private keys.

No election has been created, credential consumed or user voter modified here.
No PostgreSQL/Docker operation, migration, real credential/private-key access,
commit/push/merge, stash or worktree removal was performed. The local runtime
adapter, guarded installer, live ownership/ACL verification, key custody and
physical shutdown implementation remain the explicit blockers to an operational
demo. This package completes offline preparation/review, not deployment.
