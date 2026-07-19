from __future__ import annotations

import hashlib
import json
from pathlib import Path


CORE_ROOT = Path(__file__).resolve().parents[2]
FIXTURES = CORE_ROOT / "tests" / "fixtures" / "cad002"


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _canonical_step_hash(step: dict) -> str:
    hashed_fields = {
        "inputHash": step["inputHash"],
        "outputHash": step["outputHash"],
        "pluginRef": step["pluginRef"],
        "policyRef": step["policyRef"],
        "previousHash": step["previousHash"],
        "stepId": step["stepId"],
        "stepIndex": step["stepIndex"],
    }
    encoded = json.dumps(hashed_fields, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def test_cad_002_sources_expose_verifier_contract() -> None:
    canonical_go = (CORE_ROOT / "internal" / "canonicaljson" / "sha.go").read_text(encoding="utf-8")
    hashchain_go = (CORE_ROOT / "internal" / "evidence" / "hashchain.go").read_text(encoding="utf-8")
    cli_go = (CORE_ROOT / "cmd" / "evidence-verify" / "main.go").read_text(encoding="utf-8")

    assert "CAD-002" in canonical_go
    assert "func CanonicalHash" in canonical_go
    assert "CAD-002" in hashchain_go
    assert "type Step" in hashchain_go
    assert "PolicyRef" in hashchain_go
    assert "PluginRef" in hashchain_go
    assert "EvidencePath" in hashchain_go
    assert "func VerifyStepChain" in hashchain_go
    assert "CAD-002" in cli_go
    assert "--bundle" in cli_go
    assert "HASH_CHAIN_TAMPERED" in cli_go


def test_cad_002_valid_fixture_uses_canonical_json_step_hashes() -> None:
    bundle = _load_json(FIXTURES / "valid" / "evidence-bundle.json")
    chain = _load_json(FIXTURES / "valid" / "step-hash-chain.json")

    assert bundle["task"] == "CAD-002"
    assert bundle["chainRef"] == "step-hash-chain.json"
    assert chain["task"] == "CAD-002"
    assert [step["stepIndex"] for step in chain["steps"]] == [0, 1, 2]

    previous_hash = "sha256:" + ("0" * 64)
    for step in chain["steps"]:
        assert step["previousHash"] == previous_hash
        assert step["chainHash"] == _canonical_step_hash(step)
        previous_hash = step["chainHash"]

    reordered = dict(reversed(list(chain["steps"][1].items())))
    assert _canonical_step_hash(reordered) == chain["steps"][1]["chainHash"]

    hashchain_go = (CORE_ROOT / "internal" / "evidence" / "hashchain.go").read_text(encoding="utf-8")
    assert "VerifyStepChain" in hashchain_go


def test_cad_002_tampered_fixture_reports_task_step_and_path() -> None:
    bundle = _load_json(FIXTURES / "tampered-output" / "evidence-bundle.json")
    chain = _load_json(FIXTURES / "tampered-output" / "step-hash-chain.json")
    failure = bundle["expectedFailure"]
    tampered_step = chain["steps"][failure["stepIndex"]]

    assert bundle["task"] == "CAD-002"
    assert failure["task"] == "CAD-002"
    assert failure["code"] == "HASH_CHAIN_TAMPERED"
    assert failure["stepIndex"] == 1
    assert failure["evidencePath"].endswith("tampered-output/step-hash-chain.json#/steps/1")
    assert tampered_step["chainHash"] != _canonical_step_hash(tampered_step)
    assert "CAD-002" in failure["message"]
    assert "stepIndex=1" in failure["message"]
    assert "tampered-output/step-hash-chain.json#/steps/1" in failure["message"]

    cli_go = (CORE_ROOT / "cmd" / "evidence-verify" / "main.go").read_text(encoding="utf-8")
    assert "CAD-002" in cli_go
    assert "stepIndex" in cli_go
    assert "evidencePath" in cli_go
