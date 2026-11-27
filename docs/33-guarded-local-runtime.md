# Phase 11B.1 — guarded local runtime review

Branch: `feat/guarded-local-runtime`; inspected base: `bd15d7d`.

**Code implemented; local VM deployment NOT RUN.** No VM, Docker daemon,
PostgreSQL connection, migration, deployment key generation or SSH session was
started during implementation. Hosted CI results for this new code are pending.
Prior full-election and Admin Publication UI passes are historical evidence from
the supplied project context, not a new deployment result.

## Architecture and approval boundary

Windows browser → explicitly pinned, dedicated SSH local forwards → dedicated
Ubuntu 24.04 VM → loopback-only Vite/API processes → two isolated PostgreSQL 18
containers. The existing production/demo launchers and hosted guards are unchanged.
The old public plan remains review-only: changing `execution_ready` is not a way
to activate this controller.

[The controller](../scripts/local_demo_runtime.py) is a trusted root operator
process, explicitly invoked in the approved VM. It owns provisioning credentials,
the encrypted custody vault, container inspection and the private creation journal.
Each service runs with its own non-root UID/GID, no supplementary groups, no
Docker socket access and no setup credentials. Source, dependencies and executables
must be root-owned and unwritable by those accounts. This is a privileged local
controller, not a network administration API or production isolation claim.

An inherited Unix socketpair lets each child ask its controller to re-inspect only
the database container kinds permitted to that service. It exposes no Docker
socket, general commands, database credentials or inspection rows. Broker failure
refuses subsequent connections. Every actual runtime SQL connection also verifies
database name, session/current role, owner, independent comment marker and PG18,
then exact effective role/schema/function/table/column/sequence privileges. There
is no selectable DSN, fallback DB or inherited PG configuration. libpq service
and password-file discovery are explicitly disabled.

| Service | Runtime DB capability | Private material |
|---|---|---|
| RA A / RA B | `ra_auth_login`, `ra_issuance_login` | RA RSA key, persistent recovery key, its own verifier |
| Voting | `voting_ballot_login` | None |
| Admin | `voting_admin_login`, `ra_election_publisher_login` | Manifest Ed25519 key, Admin verifier |
| Tally | `voting_tally_login` | Original Tally RSA key, evidence Ed25519 key, Tally verifier |
| Publisher | `voting_publication_login` | Publication Ed25519 key; read-only evidence mirror |
| Public Board | `voting_board_login` | None; public trust pins only |
| Three Vite processes | None | Public pins and fixed loopback origins only |

The ballot login retains exactly its reviewed inherited capability membership:
`voting_ballot_service`, ADMIN=false, INHERIT=true, SET=false. Other runtime roles
must be NOINHERIT and have no memberships in either direction. The guard checks
exact function signatures, SECURITY DEFINER, owner and each function's actual
applied search path; it does not impose an invented universal search path.
PUBLIC EXECUTE, CREATE/TEMP, unexpected schema USAGE, direct tables/columns and
sequences all fail closed. Mixed relation types use CASE-guarded privilege calls.

## Public configuration contract

First generate/review a **fresh** source-bound public plan using the existing
[offline CLI](../scripts/local_demo_preflight.py). The checked-in plan remains an
unprovisioned example; its reviewed base and public source digest were refreshed. Runtime
sources, guarded migration environment and new CI workflow are now included in
the source fingerprint. Do not reuse an earlier plan by editing arbitrary fields.

The separate absolute public file `evote-local-runtime.json` has exactly:

| Field | Required contents |
|---|---|
| `approval` | `plan_digest`, `machine_id` (32 lower-case hex), `product_uuid`, `boot_id`, `host_review` |
| `approval.host_review` | Exact reviewed acknowledgement: `APPROVED dedicated VM; no shares; no host DB forwarding; dedicated pinned SSH` |
| `containers` | Exact `ra` / `voting` creation IDs (64 lower-case hex), copied from this controller's create operation/journal; never adopted by name |
| `accounts` | All ten service names from the plan, each `[uid,gid]`; unique non-root UIDs, nonzero matching primary GIDs, dedicated `evote_<service>` accounts, nologin/false shell, /nonexistent or /var/empty home, no Docker/sudo/adm membership |
| `custody_directory` | New root-private absolute directory outside Git, named `evote-local-` plus profile hex; created once by key initialization |
| `registry_directory` | Precreated root-owned 0700 directory; creation journal, controller lock and append-only process observations |
| `tally_evidence` | Precreated Tally-owned 0700 evidence directory outside Git |
| `publisher_evidence` | Separate precreated root-owned 0750 mirror, Publisher primary group; files root-owned 0640 |
| `python`, `python_digest` | Absolute approved root-owned Python executable and SHA-256 |
| `node`, `node_digest` | Absolute approved root-owned Node executable and SHA-256 |
| `signer`, `signer_digest` | Absolute approved root-owned native Linux CIRCL runtime signer and SHA-256 |

No passwords, verifier digests, private keys, bearer tokens or connection strings
belong in either public file. Before creation, `containers` can contain null
values only for `generate-keys` / `create-containers`; every operation needing an
existing container rejects missing or malformed IDs. Update the two public IDs
from the actual create result, retain the creation journal, then review again.
The runtime contract and all its parents must be root-owned and unwritable by
other accounts; it is not accepted as an untrusted upload or live attestation.

Generated DBs are exclusively `ra_demo_local_<profilehex>` at 127.0.0.1:55432 and
`voting_demo_local_<profilehex>` at 127.0.0.1:55433, owned by their respective
NOLOGIN owners. Independent UUID markers are not derived from DB names. Containers
use the existing immutable PG18 image pin, exact labels, isolated internal bridge,
named data volumes, tmpfs bootstrap secret staging, SCRAM, no secret environment
values and suppressed SQL/parameter error logging. Raw inspection retains all
mounts and environment overrides; unknown mounts/overrides/networks are rejected.
Default Docker credential/config discovery is disabled for the local controller.

## Two-voter and setup review

[The local installer](../deployment/local_runtime_voters.py) has its own explicit
plan-bound approval and live local boundary. It does not call the hosted install
entrypoint or spoof GitHub variables. It reuses the exact reviewed DDL and bound
session adapters from [the hosted two-voter module](../scripts/voting_tally_auth.py).

Precisely two generated UUIDs map to `demo-local/demo-voter-001` and
`demo-local/demo-voter-002`. Both inserts explicitly set active=true. The fresh RA
DB must have no existing voter rows; any conflicting fixture is refused. The
test-only `ra_e2e_auth` schema has four ra_owner SECURITY DEFINER RPCs, fixed
`pg_catalog,ra_e2e_auth,ra,pg_temp`, PUBLIC revoked, auth-only USAGE/EXECUTE and no
runtime table access. Existing single-subject ra_demo SQL is untouched.

Session tokens still use canonical SHA256(token ASCII), DB-controlled 15-minute
TTL and atomic voter-bound lookup/revocation. Each RA process has only its own
verifier and expected voter UUID; cross-voter session substitution and a third
subject are denied. Issuance remains the existing durable unique reservation per
voter/election, exact blinded-request retries and recovery deadline/tombstones.
No serial or choice reaches RA; original blinded bytes reach native CIRCL.

Installation is one transaction: verify destination/head, SET LOCAL owner under
the separately held migrator login, advisory lock then voter table lock, reject
conflicts, insert exact identities, create RPCs and verify ACLs, commit. A restart
only checks exact existing identities and function ACLs. It never replaces an
inactive voter, clears sessions, resets eligibility, removes a reservation or
releases a completed authorization.

[Trusted setup](../deployment/local_runtime_setup.py) separately provisions fresh
clusters/roles and explicitly enrolls the generated Admin, Tally operator and
Publisher. Runtime packages never contain postgres, owner or migrator credentials.
Eligibility uses the existing audited `ra.set_voter_eligibility`, after matching
the Admin-finalized signed bundle against the immutable RA publication. Elections
and accepted ballots are never seeded to replace the real UI journey.

## Keys, custody and restart

[Custody](../deployment/local_runtime_custody.py) generates keys only after explicit
interactive approval: RSA-3072/e65537 for RA and Tally, three independent Ed25519
authorities and a persistent random AES recovery key. It uses the established
cryptography implementations, encrypted PKCS8 for private keys, and a bounded
operator vault using scrypt (N=32768,r=8,p=1, 16-byte salt) / AES-256-GCM (12-byte
nonce), authenticated to the public plan digest. This is a deployment storage
format, not a modification of the frozen credential/ballot/evidence protocols.

The root-only vault also retains distinct runtime/setup DB passwords and scrypt
verifiers for four separately entered synthetic passwords. No plaintext user
password is stored. The controller sends only each service's allowlisted subset
over a private pipe. Setup credentials are discarded before running services and
unlocked separately for the explicit eligibility operation. Python memory is not
guaranteed to be zeroized, and the root controller remains trusted.

Initialization uses exclusive creation and refuses an existing directory; an
interrupted vault write remains for review. There is no regenerate-on-error,
overwrite, rotation or destructive repair path. Restart decrypts and validates
the same private/public fingerprints and recovery material. Retain the original
Tally key signed into the manifest. Loss of a key or client pending state never
restores issuance eligibility. Source/plan changes require a separately reviewed
vault upgrade/rewrap ceremony; none is silently performed here.

## Startup / stop / future approved commands

These commands are an inventory for a **later approved dedicated VM**, not
instructions to execute on Windows or a user DB. VM creation, dedicated accounts,
root-owned checkout/toolchain installation (a `venv --copies` Python executable,
not a symlink), directory ownership, independent host
inspection and pinned SSH key ceremony are prerequisites. Do not run the local
controller through `sudo -E` or in a personal checkout writable by service UIDs.

Use the approved root-owned Python and absolute public paths, conceptually:

```text
<approved-python> scripts/local_demo_runtime.py <action> \
  --public-plan /var/lib/evote/review/evote-local-demo-plan.json \
  --public-runtime /var/lib/evote/review/evote-local-runtime.json
```

Every mutation asks for an exact action plus public plan digest, and private
credentials/passphrases only through non-echoing interactive prompts. Order:

1. `generate-keys` — create encrypted custody once; no Docker/SQL operation.
   Separately `export-public-pins` writes only public trust/fingerprints to two
   fixed immutable files in the private registry directory. Review/distribute
   those public files independently of Board; no private payload is exported.
2. `create-containers` — create only fresh owned named resources, journal IDs
   before readiness, inject bootstrap secrets through private stdin. No SQL yet.
   Interrupted creation is preserved; no automatic removal/recreation.
3. Review recorded IDs, then `inspect` — freshly verify VM, raw containers,
   image/volume/network/port boundaries. A successful inspect is not host attestation.
4. `bootstrap-ra`, `bootstrap-voting` — explicit fresh-cluster-only role/DB setup.
   Existing user DBs/roles cause refusal. Partial DDL is preserved, never retried
   through a destructive reset. Retain setup custody separately from runtime.
5. `migrate-ra`, `migrate-voting` — injected-connection-only guarded Alembic env;
   RA 15 revisions through bf932d0f8702; Voting 6 through f8b31c2d970a.
6. `install-voters`, `install-operators` — exact fresh synthetic fixtures and
   explicit Publisher enrollment. No real user identities or pre-existing voter.
7. `run` — start Voting → Admin → Tally → Publisher → Board → Admin Vite, each
   DB/ACL checked before socket readiness. Use Admin UI to create two candidates
   and finalize. Save its real public signed bundle as `local-election-bundle.json`;
   the controller verifies pin/key binding and RA publication before eligibility.
   Then start RA A/B and their separate Vite origins. Open/reconcile via Admin UI.
8. Cast A/B ballots in separate Windows browser profiles at ports 5174/5175,
   verify two receipts, close/reconcile, run Tally and verify A=1/B=1 through the
   existing actual APIs/UI. No synthetic success state replaces these operations.
9. After committed Tally, enter `sync-evidence` in the controller. It copies only
   immutable encrypted/signed artifact files to Publisher's read-only mirror;
   conflicting files fail closed. Publish through the existing confirmed Admin
   UI → Publisher endpoint, then verify public evidence/receipts with independent pins.
10. Enter `stop` (or interrupt the controller) to stop owned applications in
    reverse order. A stable pidfd plus boot/PID/start ticks/UID is required before
    SIGTERM. CIRCL cleanup unwinds through the worker's signal handler. There is
    no process-group kill or automatic SIGKILL. Slow/mismatched processes survive
    and produce refusal for operator review.
11. Separately `stop-containers` only after application listeners have disappeared.
    `start-containers` re-verifies exact retained IDs/volumes and reinjects the same
    tmpfs bootstrap secret; then `run` reuses custody, evidence and DB tombstones.
    VM reboot requires freshly reviewed boot identity. No resource is adopted by name.

An exclusive controller lock prevents competing mutation/start/stop operations.
Process journals are exclusive per run, flushed before readiness, and retained.
Container journals also survive partial startup. Stopping preserves containers,
named volumes, keys, sessions/reservation tombstones and all evidence. There is
**no local remove/prune/reset command**; removal remains a separate human task.
Unexpected processes, retained PID identities and partial resources are not
silently killed/adopted or rewritten.

## VM / transport evidence still required

The live guest collector checks Ubuntu24.04, pinned machine/product/boot IDs,
actual VM virtualization, initial network namespace, known host-share mount types,
and listeners. Only SSH may bind outside loopback; application/DB ports must be
loopback. Unknown listeners, including a forwarded host DB on 5432, refuse startup.
A stock VM may require separately reviewed removal of unrelated listeners; the
controller does not change system services to force a pass.

These checks cannot prove Windows/hypervisor integrity, absence of unmounted host
shares or a malicious SSH proxy outside the guest. Independently inspect the
hypervisor VM identity/ownership, dedicated host-only/NAT exposure, no host shares,
no host DB forwarding, no host agent forwarding and exact known-host fingerprint.
Record approval only after that live evidence. A matching JSON acknowledgement is
not evidence. No such host evidence has been collected in this task.

[The SSH argv builder](../deployment/local_runtime_boundary.py) supplies only
explicit identity/known-host files, strict host-key verification, no agent/config/
ProxyCommand/ProxyJump discovery and three exact same-port 127.0.0.1 forwards.
It does not generate/read a personal key or start SSH. Use newly created dedicated
demo SSH material and compare the VM host public fingerprint out of band before
installing its known-host file. Dedicated key freshness and Windows file ACLs
remain operator/hypervisor prerequisites, not automated guarantees.

## New hosted gate and evidence gaps

[The workflow](../.github/workflows/guarded-local-runtime.yml) triggers only pushes
to feat/guarded-local-runtime plus manual dispatch. Ubuntu24.04, pinned Actions,
Python3.11.9, Node24.22.3, Go1.25.14, contents:read, existing locked dependencies,
no repository secrets, no artifact uploads and no continue-on-error.

[Its coordinator](../scripts/guarded_local_runtime_ci.py) creates two fresh CI-owned
containers/volumes with local-profile names/ports/markers; provisions restricted
roles; applies the unchanged 15/6 migration chains through the new guarded env;
installs/rechecks two voters and operators; exercises all runtime factories;
authenticates distinct voters through actual routers/PG sessions; rejects cross
identity and third subject; performs native CIRCL/TS/Python issuance and exact
replay including concurrent identical requests; rebuilds the service for response
recovery; checks two durable authorizations; revokes sessions; tests 42501 table
denials and removes only resources whose creation identity still matches.

Expected fixed checkpoints: containers, bootstrap, migrations, voters, runtime_acl,
authentication, issuance, restart, denials, cleanup. Failure emits only an allowed
stage/category/SQLSTATE. Cleanup preserves the original failure stage. The CI-only
cleanup code is never used by the local controller. Existing hosted gates remain
unchanged. This gate has **not run** and does not claim real VM/SSH/process-account
deployment or a new full-election browser PASS.

## Security limitations and review gate

Root/hypervisor/Windows operator and installed dependencies remain trusted. No
HSM, guaranteed zeroization, internal TLS/mTLS, verified volume/VM encryption,
coercion resistance, network anonymity or complete E2E tally proof is delivered.
Loopback HTTP is not TLS; pinned SSH is the separate Windows-to-VM transport.
Two voters/small cohorts, shared operator observation, public encrypted ballots
and later Tally-key compromise retain the documented correlation/privacy risks.
Receipt inclusion does not prove a candidate was counted correctly.

RA A/B have distinct OS accounts, verifiers, voters and sessions, but intentionally
share the reviewed RA SQL capability identities and signing/recovery material.
The SQL allowlist contains both voters; process-bound authentication prevents HTTP
substitution. This does not isolate voter B against compromise of the trusted RA
authentication runtime itself. It is a synthetic two-voter demo boundary.

No applied migration, existing launcher, frozen protocol, frontend or dependency
lock is changed. Review the controller's root privilege, software vault format,
live Docker projection, worker signal handling and read-only evidence mirror
before deployment approval. Hosted adapter SQL/CIRCL and Linux pidfd tests must
pass first, followed by a separately approved real VM startup/stop/restart and
full two-browser election rehearsal. This package does not authorize those runs.
The profile supplies one per-election keyset and is intended for one synthetic
election. A new independent election needs a separately reviewed fresh profile
and keys; do not work around the database's unique key-policy restrictions.

The final measured validation and exact file inventory are recorded in
[the review report](./34-local-runtime-validation.md).
