# Guarded runtime CI Run #1 — container inspection correction

Branch: `feat/guarded-local-runtime`; inspected HEAD:
`5caa4b7ed5d5cc2b78b65c86d6d7f03dc3e639df`. Changes remain uncommitted.

## Finding and limits of the evidence

**Confirmed code defect:** [OwnedContainers.verify_container](../deployment/local_runtime_boundary.py)
required `len(actual['Mounts']) == 2` and then a tmpfs entry at
`/run/evote-secrets` in that list. The actual provisioning uses `--mount` for the
named data volume and the distinct legacy `--tmpfs` flag for the secret directory.

Moby's [mount registration](https://github.com/moby/moby/blob/v28.5.2/daemon/volumes.go#L126-L278)
handles HostConfig.Mounts separately from HostConfig.Tmpfs. Its
[TmpfsMounts / GetMountPoints implementation](https://github.com/moby/moby/blob/v28.5.2/container/container_unix.go#L370-L411)
keeps the legacy tmpfs map separate, while
[ContainerInspect](https://github.com/moby/moby/blob/v28.5.2/daemon/inspect.go#L36-L89)
returns GetMountPoints as Mounts. Thus this profile's single named volume belongs
in Mounts; the legacy secret tmpfs belongs in HostConfig.Tmpfs. A second Mounts
entry is not proof of the approved legacy tmpfs. The previous positive test
fixture incorrectly invented that entry and hid the compatibility defect.

The user-reported Run #1 log proves failure somewhere in `containers` and
successful owned cleanup, but provides no finer operation/predicate evidence.
It cannot rule out an earlier image/network/start/injection failure. The incorrect
mount predicate is proven from source and reproduced offline; identifying it as
Run #1's *first observed failure* remains unverified until the instrumented Ubuntu
rerun. No local Docker/PG operation was used to claim otherwise.

## Minimal functional correction and retained security

- Mounts must contain **exactly one** writable approved named volume at
  `/var/lib/postgresql`. All entries are retained for validation; extra volumes,
  bind mounts, socket mounts and tmpfs entries in that list fail.
- HostConfig.Tmpfs must contain **exactly** `/run/evote-secrets`, with the unchanged
  `rw,noexec,nosuid,nodev,mode=0755` option set. Missing/extra/unsafe tmpfs fails.
- For a running, fully verified owned container, fixed read-only commands inspect
  its own `/proc/self/mountinfo` and require one exact secret mount of type tmpfs,
  effectively rw/noexec/nosuid/nodev. Metadata-only stat checks require directory
  mode 0755 and a regular, single-link, postgres-owned/group-owned 0600 bootstrap
  file of bounded nonempty credential length. **The credential file is never read.**
- Those exec probes occur only after every existing identity, privilege, image,
  label, environment, persistent-volume, network and port check has passed.
  Stopped inspection checks configured metadata without inventing live evidence.
- The original pure policy is unchanged: exact container creation ID/name/image
  reference, immutable image ID, labels including pinned-image defaults, exact
  environment overrides, non-privileged mode, no host binds/capabilities/devices,
  network identity/attachment, named-volume driver/options/ownership labels,
  configured/live loopback ports and non-autoremove all remain enforced.

The correction does not switch mount mechanisms, relax a privilege, change the
container isolation model, alter a password, modify an applied migration or touch
frozen cryptography. The additional live checks are fail-closed controller-side
reads. Runtime services receive no new Docker capability or endpoint.

## Fixed diagnostics

[The coordinator](../scripts/guarded_local_runtime_ci.py) now records each operation
before executing it and prints PASS only after it completes. Expected successful
container prefix:

```text
PASS guarded_local_runtime checkpoint=container_image
PASS guarded_local_runtime checkpoint=container_network
PASS guarded_local_runtime checkpoint=container_ra_created
PASS guarded_local_runtime checkpoint=container_ra_secret
PASS guarded_local_runtime checkpoint=container_voting_created
PASS guarded_local_runtime checkpoint=container_voting_secret
PASS guarded_local_runtime checkpoint=container_ra_inspect
PASS guarded_local_runtime checkpoint=container_voting_inspect
PASS guarded_local_runtime checkpoint=containers
```

The remaining existing bootstrap/migration/ACL/authentication/issuance/restart
steps can run only after that prefix succeeds. A representative failure is:

```text
PASS guarded_local_runtime checkpoint=cleanup
FAIL guarded_local_runtime stage=container_ra_inspect predicate=secret_filesystem category=assertion_error
```

The finally block completes cleanup before main formats the preserved original
failure. Predicates/categories/stages are fixed allowlists; unknown diagnostic
attributes become `unavailable`. Nested checks retain the original exception and
most specific allowed predicate. No raw inspect JSON, environment, file content,
SQL/parameters, arbitrary exception text or traceback is emitted. Existing
sanitized SQLSTATE handling for later database stages remains unchanged.

## Changed files (six)

| File | Change |
|---|---|
| [Boundary adapter](../deployment/local_runtime_boundary.py) | Correct mount model, live read-only filesystem/readiness checks and fixed predicate annotations. |
| [CI coordinator](../scripts/guarded_local_runtime_ci.py) | Nine allowlisted container checkpoints and sanitized failure formatter; original cleanup/identity rules retained. |
| [Existing guard tests](../tests/test_guarded_local_runtime.py) | Correct raw Docker fixture to one volume; provide realistic metadata responses for the new read-only checks. Existing negative assertions retained. |
| [New container regressions](../tests/test_guarded_local_runtime_containers.py) | 48 cases covering approved shape, mount/ownership/isolation mutations, effective filesystem/readiness, sanitization and all eight pre-containers failure/cleanup paths. No Docker/PG calls. |
| [Public example plan](../deployment/evote-local-demo-plan.json) | Refresh only source_digest because guarded source changed; same IDs/targets/roles and execution_ready=false. |
| [This report](./35-guarded-runtime-ci-mount-fix.md) | Evidence, correction, security review, measured validation and pending CI steps. |

[The existing workflow](../.github/workflows/guarded-local-runtime.yml) and
[local container provisioning](../deployment/local_runtime_containers.py) were
inspected and remain unchanged. No new privilege, workflow trigger, dependency,
lockfile, production launcher or migration change is necessary.

## Actual validation

| Check | Result |
|---|---|
| Complete backend/crypto pytest | **1,205 passed, 2 skipped**. The unchanged Linux-only pidfd/listener tests cannot run on Windows and remain enabled in Ubuntu. |
| Focused guard/policy/lifecycle/container tests | **186 passed, 2 skipped**, included in the complete result, not added to it. |
| Frontend unit/component/crypto | **167 passed**, 12 files. |
| Authentication / Voting / Admin / Tally / Board browsers | **7 / 7 / 4 / 2 / 3 passed**, 23 total; existing synthetic-service suites on Windows Edge. |
| Frontend TypeScript + production build | **PASS**; existing browser-externalization notice unchanged. |
| Crypto TypeScript build + recovery | **PASS**, 2 recovery tests. |
| Dependency checks | pip check, reviewed backend version assertions and both locked npm dependency trees **PASS**; no lock changes. |
| Syntax | **185 Python, 8 JSON, 13 YAML, 84 Bash scripts/workflow bodies** parsed. |
| Migration graphs | Unchanged RA bf932d0f8702 (15 revisions), Voting/Board f8b31c2d970a (6). Graph inspection only. |
| Public plan preflight | **PASS**, OFFLINE_VALIDATED_NOT_DEPLOYED / execution_ready=false. |
| Changed-source secret patterns, manual command/data-flow review, whitespace | **PASS**; git diff --check and explicit new-file checks. Pattern checks are not an exhaustive secret-detection guarantee. |
| Real Docker / PostgreSQL / local VM | **NOT RUN**. The corrected real gate requires an actual hosted rerun. |

The first complete Python attempt had 1,204 pass / 1 fail / 2 skip because the
unchanged RFC test's urllib download timed out. The published v1.6.5 gzip fixture
was then downloaded to a temporary directory with certificate verification and
verified against the existing SHA-256
`374ba388a53cd9017aecff92afd2174188c7d5c7e8f0947d8af466043f134ff7`.
The full suite passed using its existing EVOTE_TEST_RFC_VECTOR option; the loader
still verifies that exact digest. No test/protocol change, assertion removal or
new skip was used to address the network failure. Public test-vector contents
are outside Git and are not logged or uploaded.

Local validation used Python3.11.9 / Node24.22.3 / npm11.19.1 and the existing
PSYCOPG_IMPL=python/libpq18 import configuration. Importing libpq is not a database
connection. No Windows security policy was changed.

## Human-review gate and remaining limitations

The existing feature-branch push/manual workflow is ready for a human-approved
rerun. **This correction has not executed in GitHub Actions.** Require successful
image/network/start/injection/inspect checkpoints, then the real migration,
runtime ACL, two-voter authentication, native CIRCL issuance, replay/restart and
cleanup checks. No downstream stage from Run #1 is credited as PASS.

The source-based mount model and offline regressions are not captured engine
evidence. Actual mountinfo/stat output in the pinned image and hosted runner
must still pass. If engine representation or provisioning differs, the fixed
predicate will identify the failure without dumping sensitive observations.
The dedicated VM/hypervisor/SSH approval and all previously documented software
custody/privacy limitations remain outstanding. No deployment security claim is
expanded by this change.

No local Docker/PostgreSQL, user DB, production credential/key, migration execution,
commit/push/merge, stash removal or worktree removal occurred. Stop for human review.
