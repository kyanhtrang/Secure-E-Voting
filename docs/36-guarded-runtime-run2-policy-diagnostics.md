# Guarded Local Runtime Run #2 — precise policy diagnostics

Branch `feat/guarded-local-runtime`, inspected HEAD
`983cfdb0a74dee0256a36a9313daf5d9b76b99f6`. Changes remain uncommitted.

## Result and root-cause evidence

The coarse `container_policy` failure is now split into eighteen fixed,
allowlisted policy predicates. All existing acceptance conditions remain intact.
This is a **diagnostic/security-preserving change**, not a claim that the real
integration gate has passed or that its network topology has been repaired.

The reported Run #2 evidence proves image/network/container creation and secret
injection passed for both containers, then RA inspection failed inside the pure
policy group. It does not identify which conjunct or its observed value.
Later volume/network inspection, live secret metadata, bootstrap, migration,
authentication and issuance results are not inferred as PASS.

Source review identified a concrete configuration/readiness conflict:

- The coordinator creates an **internal** bridge network and requests Docker
  publishing on VM loopback ports 55432/55433.
- The policy requires both the requested HostConfig.PortBindings and the actual
  NetworkSettings.Ports to equal those mappings.
- Moby's [buildPortsRelatedCreateEndpointOptions](https://github.com/moby/moby/blob/v28.5.2/daemon/network.go#L868-L935)
  returns without installing port-mapping endpoint options for internal networks.
  Its [endpoint join path](https://github.com/moby/moby/blob/v28.5.2/libnetwork/endpoint.go#L661-L670)
  also skips external-connectivity programming there. The
  [daemon port-map inspection](https://github.com/moby/moby/blob/v28.5.2/daemon/network.go#L936-L988)
  reads programmed endpoint mappings, not merely the requested configuration.

Consequently requested bindings do not prove effective loopback publication.
This upstream source behavior makes `policy_effective_ports` the leading Run #2
diagnosis. **The actual Run #2 field and runner engine version were not captured**;
the next hosted run must identify the precise predicate before calling this the
observed historical cause. No local Docker observation was fabricated.

A missing effective mapping is a real readiness failure for these host-side
connection factories, not a harmless JSON representation difference. Accepting
an empty/null map, copying requested bindings into running observations, removing
`--internal`, adding an external network, or bypassing this assertion would not
be a safe one-predicate fix. None of those changes is made here. The previous
legacy tmpfs correction and live ownership/filesystem checks remain intact.

## Diagnostic contract

[The pure policy](../deployment/local_demo_policy.py) remains stdlib-only and
performs no collection or execution. Each check retains its exact security
condition and reports only its fixed predicate identifier:

| Predicate | Retained invariant |
|---|---|
| policy_kind | Only RA or Voting resource kinds. |
| policy_created_id | Canonical full container creation ID. |
| policy_database_spec | Exact generated database, owner, port, volume and marker contract. |
| policy_observation | Required config/host observation shape. |
| policy_network_name | Exact profile-derived network name. |
| policy_container_id | Observed ID equals recorded creation ID. |
| policy_container_name | Exact approved container name. |
| policy_image_reference | Exact immutable pinned image reference. |
| policy_labels | Exact approved ownership/marker labels. |
| policy_privileged | Privileged=false. |
| policy_network_mode | Exact owned network mode. |
| policy_pid_namespace | Host PID namespace forbidden. |
| policy_ipc_namespace | Host IPC namespace forbidden. |
| policy_autoremove | AutoRemove=false; persistent resources survive stop. |
| policy_configured_ports | Exactly the approved loopback publishing request. |
| policy_effective_ports | Exactly the approved actual publishing map. |
| policy_persistent_mount | Exactly the approved writable named data volume. |
| policy_environment | Exactly the approved non-secret environment overrides. |

[The collector](../deployment/local_runtime_boundary.py) imports this fixed set
into its existing allowlist. Its outer container_policy context preserves the
more precise nested label. Stopped-container port metadata has the separate
`container_stopped_ports` predicate; normalization of a stopped projection never
counts as live readiness. Missing/malformed fields still fail closed, with a
sanitized ReviewRefused and the precise field-group identifier.

[The existing CI formatter](../scripts/guarded_local_runtime_ci.py) already reads
this allowlist, so it needs no modification. A possible next failure is:

```text
PASS guarded_local_runtime checkpoint=container_voting_secret
PASS guarded_local_runtime checkpoint=cleanup
FAIL guarded_local_runtime stage=container_ra_inspect predicate=policy_effective_ports category=assertion_error
```

This is an expected diagnostic example, **not an executed hosted result**.
Cleanup precedes main's failure formatting and preserves the original stage.
No actual map, address, inspect JSON, environment, SQL parameter, arbitrary
exception text, token, password or key is added to diagnostics. The existing
database-stage SQLSTATE sanitization is unchanged.

## Exact changed-file inventory (five)

| File | Change |
|---|---|
| [local_demo_policy.py](../deployment/local_demo_policy.py) | Eighteen allowlisted per-check diagnostics; same security conditions, no new IO. |
| [local_runtime_boundary.py](../deployment/local_runtime_boundary.py) | Merge policy identifiers into the existing allowlist; label invalid stopped-port metadata separately. |
| [test_guarded_local_runtime_containers.py](../tests/test_guarded_local_runtime_containers.py) | Keep existing negative assertions, update expected precise IDs and add 34 focused cases. |
| [evote-local-demo-plan.json](../deployment/evote-local-demo-plan.json) | Refresh only source_digest; no IDs, destinations, roles or activation flags changed. |
| [This report](./36-guarded-runtime-run2-policy-diagnostics.md) | Diagnosis, validation, explicit uncertainty and remaining review gate. |

The coordinator, workflow, local provisioner, production launchers, authentication,
frozen crypto, dependency locks and applied migrations are unchanged. No database
privilege or Docker network option is changed.

## Focused coverage and actual validation

New cases exercise each of the eighteen policy identifiers, nested preservation
through the collector/formatter, a positive abstract policy observation, missing
inspect fields, invalid stopped-port metadata, and empty/null/incorrect effective
maps despite correct requested bindings. Both RA/Voting coordinator failure paths
also prove cleanup retains `policy_effective_ports` without attempting PostgreSQL.

The positive observation is a policy-contract fixture, not proof that Docker can
satisfy this proposed internal-network/published-port combination. Missing real
port publication remains a required failure; no mock is promoted to real CI PASS.

| Check on this checkout | Actual result |
|---|---|
| Complete Python backend/crypto suite | **1,239 passed, 2 skipped**. Existing Linux-only pidfd/listener tests remain enabled on Ubuntu and cannot execute on Windows. |
| Focused policy/lifecycle/runtime/container suites | **220 passed, 2 skipped**, included in the full count. |
| Frontend unit/component/crypto | **167 passed**, 12 files. |
| Authentication / Voting / Admin / Tally / Board browser suites | **7 / 7 / 4 / 2 / 3 passed**, 23 total; synthetic-service fixtures on Windows Edge, not real PostgreSQL. |
| Frontend TypeScript + production build | **PASS**; existing blindrsa browser-externalization notice unchanged. |
| Crypto TypeScript build and recovery | **PASS**, 2 recovery tests. |
| Dependencies | pip check, existing pinned backend version checks and both locked npm trees **PASS**; no dependency/lock changes. |
| Static syntax | **185 Python, 8 JSON, 13 YAML, 84 Bash scripts/workflow bodies** parsed. |
| Migration graph | Unchanged RA bf932d0f8702 (15 revisions); Voting/Board f8b31c2d970a (6). Graph reads only. |
| Offline public-plan preflight | **PASS**, OFFLINE_VALIDATED_NOT_DEPLOYED, execution_ready=false. |
| Changed-source secret-pattern/manual review and whitespace | **PASS**; git diff --check plus explicit new-file whitespace checks. Pattern checks are not an exhaustive secret-detection guarantee. |
| New hosted diagnostic run / actual Docker and PostgreSQL | **NOT RUN**. |

Python3.11.9, Node24.22.3 and npm11.19.1 were used. The complete Python run used
the existing supported EVOTE_TEST_RFC_VECTOR option with the same public RFC gzip
fixture, verified against the unchanged pinned SHA-256 before testing. Windows
imports used the existing PSYCOPG_IMPL=python/libpq18 configuration; this loads a
client library and does not connect to PostgreSQL. No test assertion was removed
and no new skip, timeout adjustment or cryptographic substitution was introduced.

## Remaining CI and topology review

The existing Ubuntu job is **ready for precise diagnostic rerun**, not certified
to complete successfully. Require the next actual predicate result. If effective
port publication is missing, the guard must continue refusing bootstrap and
runtime access. A diagnostic rerun is not an election deployment approval.

An isolation-preserving transport proposal for separate review is a narrowly
owned VM loopback relay to the exact container IP on the retained internal bridge.
Docker documents that [the host can reach internal-network container IPs directly](https://docs.docker.com/reference/cli/docker/network/create/#network-internal-mode---internal).
Such a design would require an explicit new transport contract: verify the
relay's process/socket identity and destination against live container/network
ownership; keep fixed loopback listeners, no external container network, no
general targets, and repeat the existing DB identity/marker/role/ACL checks.
It must have its own failure/restart/CI coverage before replacing Docker-port
publication evidence. This proposal is **not implemented or approved here**.

There is no safe claim of a complete connectivity repair from the available
Run #2 log alone. No isolation or readiness assertion has been weakened to obtain
a green test. No local Docker/PostgreSQL, production credential/key access,
migration execution, commit/push/merge, stash or worktree removal occurred.
Stop for human review.
