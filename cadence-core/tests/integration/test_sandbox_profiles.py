from __future__ import annotations

import json
from pathlib import Path


CORE_ROOT = Path(__file__).resolve().parents[2]
FIXTURES = CORE_ROOT / "tests" / "fixtures" / "cad004"


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_cad_004_sources_expose_sandbox_policy_contract() -> None:
    sandbox_go = (CORE_ROOT / "internal" / "sandbox" / "sandbox.go").read_text(encoding="utf-8")
    plugins_go = (CORE_ROOT / "internal" / "plugins" / "plugins.go").read_text(encoding="utf-8")
    assert "CAD-004" in sandbox_go
    assert "type CapabilityPolicy" in sandbox_go
    assert "func DenyUndeclaredCapability" in sandbox_go
    assert "sandbox.network.denied" in sandbox_go
    assert "sandbox.filesystem.denied" in sandbox_go
    assert "sandbox.env.denied" in sandbox_go
    assert "CAD-004" in plugins_go
    assert "SandboxProfile" in plugins_go
    assert "func BindPluginProfile" in plugins_go


def test_cad_004_allowed_plugin_declares_profile_and_permissions() -> None:
    manifest = _load_json(FIXTURES / "allowed-plugin" / "manifest.json")
    result = _load_json(FIXTURES / "allowed-plugin" / "audit-result.json")

    assert manifest["task"] == "CAD-004"
    assert manifest["pluginId"] == "cadence-plugin-python"
    assert manifest["sandboxProfile"] == "readonly-no-network"
    assert manifest["permissions"]["network"] is False
    assert manifest["permissions"]["filesystem"]["write"] == ["out/**"]
    assert manifest["permissions"]["envRead"] == ["PATH", "TMPDIR"]
    assert result["status"] == "ok"
    assert result["audit"]["pluginId"] == manifest["pluginId"]
    assert result["audit"]["profile"] == manifest["sandboxProfile"]
    assert result["audit"]["denied"] == []

    plugins_go = (CORE_ROOT / "internal" / "plugins" / "plugins.go").read_text(encoding="utf-8")
    assert "SandboxProfile" in plugins_go


def test_cad_004_undeclared_capabilities_fail_closed_with_audit() -> None:
    denied = [
        ("network", "sandbox.network.denied"),
        ("file-write", "sandbox.filesystem.denied"),
        ("env-read", "sandbox.env.denied"),
    ]
    for fixture_name, code in denied:
        result = _load_json(FIXTURES / "denied-permissions" / f"{fixture_name}.json")
        assert result["task"] == "CAD-004"
        assert result["status"] == "denied"
        assert result["code"] == code
        assert result["audit"]["pluginId"].startswith("malicious-")
        assert result["audit"]["profile"] == "readonly-no-network"
        assert result["audit"]["denied"][0]["code"] == code
        assert result["audit"]["denied"][0]["capability"]
        assert "CAD-004" in result["message"]
        assert code in result["message"]

    sandbox_go = (CORE_ROOT / "internal" / "sandbox" / "sandbox.go").read_text(encoding="utf-8")
    assert "DenyUndeclaredCapability" in sandbox_go
