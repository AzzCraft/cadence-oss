from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
CORE_ROOT = ROOT / "cadence-core"
POLICY_PACKS_ROOT = ROOT / "cadence-policy-packs"
FIXTURES = CORE_ROOT / "tests" / "fixtures" / "cad005"


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))




def test_cad_005_trusted_registry_fixture_resolves_only_active_trusted_entries() -> None:
    index = _load_json(FIXTURES / "registry" / "trusted-index.json")

    assert index["task"] == "CAD-005"
    assert index["registryId"] == "cadence-local-test"
    active = [entry for entry in index["entries"] if entry["status"] == "active"]
    assert active
    assert all(entry["trusted"] is True for entry in active)
    assert all(entry["signer"] == "azzcraft-release" for entry in active)
    assert all(entry["sha256"].startswith("sha256:") for entry in active)
    assert index["expectedResolution"]["ok"] is True
    assert index["expectedResolution"]["activeIds"] == ["cadence-plugin-python", "core-v140-baseline"]



def test_cad_005_revoked_hash_mismatch_and_policy_pack_failures_name_item() -> None:
    revoked = _load_json(FIXTURES / "registry" / "revoked-plugin.json")
    mismatch = _load_json(FIXTURES / "registry" / "hash-mismatch.json")
    compatible_pack = (FIXTURES / "policy-packs" / "compatible-pack.yaml").read_text(encoding="utf-8")
    incompatible = _load_json(FIXTURES / "policy-packs" / "incompatible-pack.expected.json")

    assert revoked["expectedFailure"]["task"] == "CAD-005"
    assert revoked["expectedFailure"]["code"] == "registry.revoked"
    assert revoked["expectedFailure"]["item"] == "malicious-plugin"
    assert "CAD-005" in revoked["expectedFailure"]["message"]
    assert "malicious-plugin" in revoked["expectedFailure"]["message"]

    assert mismatch["expectedFailure"]["task"] == "CAD-005"
    assert mismatch["expectedFailure"]["code"] == "registry.hash.mismatch"
    assert mismatch["expectedFailure"]["item"] == "cadence-plugin-python"
    assert "CAD-005" in mismatch["expectedFailure"]["message"]

    for required in ("schemaVersion:", "channel:", "runtimeCompatibility:", "cadenceCore:", "protocol:"):
        assert required in compatible_pack
    assert incompatible["expectedFailure"]["task"] == "CAD-005"
    assert incompatible["expectedFailure"]["code"] == "policy.runtime.incompatible"
    assert incompatible["expectedFailure"]["item"] == "legacy-v1-pack"
    assert "CAD-005" in incompatible["expectedFailure"]["message"]

    pack_verify = (POLICY_PACKS_ROOT / "scripts" / "verify").read_text(encoding="utf-8")
    assert "runtimeCompatibility" in pack_verify
