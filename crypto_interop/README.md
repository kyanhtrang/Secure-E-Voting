# Crypto interoperability gate (test-only)

Protocol: [frozen credential v2](../docs/13-credential-protocol-v2.md).
No API/database/authentication changes. Use only test environments; no production
private-key file is accepted or needed. No generated key or secret is written
inside the repository. RFC private test components live only in OS temp.

## Prerequisites and locks

Check `node --version`, `npm --version`, `go version`, `python --version` first.
Node >=24 and Go >=1.25 are required by the pinned libraries. Use a separate
Python environment (Python 3.11 was tested). Do not downgrade profiles/libraries
or bypass application-control policies when a tool cannot execute.

Tested toolchains: Node 24.22.3, npm 11.19.1, Go 1.25.14, Python 3.11.9 on
Windows amd64. They were absent from PATH initially; official Node/Go portable
archives were SHA256 checked and extracted to OS temp, not installed globally.

NPM lock pins @cloudflare/blindrsa-ts 0.4.6, canonicalize 5.1.0, TypeScript 7.0.2,
and @types/node 24.19.2. Go module/sum pins CIRCL v1.6.5. The dedicated Python
lock pins cryptography 50.0.2, rfc8785 0.1.4, pytest 9.2.0 and transitive packages.
The repository's existing authentication environment/lock is unchanged.

## Reproduce on an approved execution host

From repository root, with an isolated Python environment activated:

```text
python -m pip install -r crypto_interop/requirements.lock.txt
npm --prefix crypto_interop ci --ignore-scripts
npm --prefix crypto_interop run build
```

Build the test signer outside the repository, then run it through the gate.
PowerShell example with Node and Go already on PATH:

```powershell
$gateOutput = Join-Path $env:TEMP 'evote-crypto-test-signer.exe'
Push-Location crypto_interop/signer
go mod verify
go test -v ./...
go test -v github.com/cloudflare/circl/blindsign/blindrsa -run '^TestVectors$'
go build -o $gateOutput .
Pop-Location
python crypto_interop/gate.py --node (Get-Command node).Source --signer $gateOutput
```

The gate downloads a hash-pinned public RFC fixture. An offline copy can be
supplied with `--rfc-vector-gzip`; it must match the same SHA256. It will not
silently substitute a fixture or mock signer. Output is PASS labels or sanitized
failure labels, not private keys, inverse values, tokens, or full requests.

Run Python/real-TypeScript checks separately:

```powershell
$env:EVOTE_TEST_NODE = (Get-Command node).Source
python -m pytest crypto_interop/ -q
```

That suite tests RFC client Prepare/Blind/Finalize against the published
blind_sig, Python verification, canonicalization, and manifest rejection.
It cannot establish Go interoperability. An optional EVOTE_TEST_RFC_VECTOR
points to the same hash-checked compressed public fixture for offline tests.

Run the original database-free suite in its existing Python environment:

```text
python -m pytest tests/ -q
git diff --check
```

## Current evidence

- TypeScript compilation: PASS.
- Python/TypeScript protocol tests: 40 passed in 1.82s.
- Original tests: 279 passed in 11.12s, unchanged.
- Go build: PASS (source compiled); **execution is blocked by Windows Application Control**.
- Native Go tests and full gate: **NOT PASS**; the OS blocked the test binary/signer.
- gofmt and vet were also blocked. No application-control policy was changed.

Actual full-gate output on this host:

```text
CRYPTO INTEROPERABILITY GATE: FAIL: CIRCL signer cannot execute; check toolchain and application-control policy
```

Actual native test outcome (also tried without optional vet):

```text
crypto-test-signer.test.exe: An Application Control policy has blocked this file.
FAIL secure-evoting/crypto-test-signer
```

The full driver includes generated RSA-3072 interop and rejection of modified
election, serial, envelope/config hash, key ID, signature, wrong key, valid
zero-salt PSS signature, 31/33-byte prefix, noncanonical encoding, modified/wrongly
signed manifests, configuration substitution, and identity-bearing fields.
Those Go-dependent checks require successful execution on an approved host.
Until then, do not treat this gate as approved for database or API development.

## GitHub-hosted Ubuntu validation

The [RSABSSA interoperability workflow](../.github/workflows/rsabssa-interop.yml)
runs on pushes to feat/blind-credential-anonymous-voting using ubuntu-24.04.
Official setup/checkout actions are pinned to commit hashes. Toolchains are
Node 24.22.3, Go 1.25.14, and Python 3.11.9. Job permissions are contents: read;
checkout credentials are not persisted. No repository secrets, database services,
private election keys, artifact uploads, or dependency-cache uploads are used.

The bash steps fail on errors, unset variables, or failed pipelines. Python
dependencies use the fully pinned lock with --no-deps and pip check. NPM uses
ci --ignore-scripts. Go uses GOTOOLCHAIN=local, GOFLAGS=-mod=readonly and
GOWORK=off; the workflow fails if installation/build modifies dependency locks.
Native Go tests retain their default vet check and run with -count=1.

The required order is client compilation, Python/TypeScript crypto tests,
native signer tests, upstream TestVectors, test-signer build in RUNNER_TEMP,
then the existing full gate with --node and --signer. The gate includes both
RFC A.1 and generated RSA-3072 execution and all its negative cases. No fixture
signature is substituted for CIRCL in the full-gate step. Private generated
keys remain in memory; the public RFC test-key fixture is managed in OS temp.
Do not enable shell tracing or upload that temporary directory.

This workflow is prepared for review, not a recorded Ubuntu PASS. After a
human-reviewed commit and push, inspect [workflow runs](https://github.com/kyanhtrang/Secure-E-Voting/actions/workflows/rsabssa-interop.yml).
Require every step to pass, especially the upstream vector step and the final
full gate. Confirm the run's commit SHA matches the reviewed commit. Until that
execution succeeds, the complete Go interoperability gate remains unverified.
