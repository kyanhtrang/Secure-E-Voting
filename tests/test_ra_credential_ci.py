"""Offline CI coverage checks; these never execute Go or claim a remote PASS."""
from pathlib import Path

import yaml


ROOT=Path(__file__).resolve().parents[1]


def test_ubuntu_gate_covers_runtime_signer_on_gate2_branch():
    source=(ROOT/".github/workflows/rsabssa-interop.yml").read_text(encoding="utf8")
    workflow=yaml.safe_load(source)
    assert "feat/ra-credential-issuance-recovery" in workflow["on"]["push"]["branches"]
    assert workflow["permissions"]=={"contents":"read"}
    job=workflow["jobs"]["crypto-interop"]
    assert job["runs-on"]=="ubuntu-24.04"
    assert job["env"]["GOFLAGS"]=="-mod=readonly"
    steps=job["steps"]
    assert any(step.get("run")=="go test -count=1 -v ./..." and
               step.get("working-directory")=="crypto_interop/signer" for step in steps)
    assert any(step.get("run")== 'go build -o "$RUNNER_TEMP/ra-credential-signer" ./cmd/ra-credential-signer'
               for step in steps)
    assert any(step.get("with",{}).get("go-version")=="1.25.14" for step in steps)
    assert all(step.get("continue-on-error",False) is False for step in steps)
    assert "secrets." not in source and "services" not in job
    assert not any("upload-artifact" in step.get("uses","") for step in steps)
    test_source=(ROOT/"crypto_interop/signer/cmd/ra-credential-signer/main_test.go").read_text(encoding="utf8")
    assert "rsa.GenerateKey(rand.Reader,3072)" in test_source
    assert "ReadFile" not in test_source
