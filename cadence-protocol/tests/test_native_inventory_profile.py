"""Schema-only diagnostics cannot silently replace a stronger requested profile."""
import json
import runpy
from pathlib import Path

import pytest
from jsonschema import ValidationError

TOOLS = Path(__file__).resolve().parents[1] / "tools"


def entry(monkeypatch):
    monkeypatch.syspath_prepend(str(TOOLS))
    return runpy.run_path(str(TOOLS / "validate_artifacts.py"))["main"]


def inventory(version):
    result = {
        "schemaVersion": "1.0.0", "audit": {"bundleId": "synthetic", "timestamp": "2026-10-19T00:00:00Z"},
        "runManifestRef": "run-manifest.json", "pipelineResultRef": "pipeline-result.json",
        "artifactPaths": ["run-manifest.json"], "bundleHash": "sha256:" + "0" * 64,
    }
    if version == "v2":
        result.update(schemaVersion="cadence-evidence-bundle/v2", chainProfile="cadence-run/v1",
                      artifactHashes={"run-manifest.json": "sha256:" + "0" * 64})
    return result


@pytest.mark.parametrize("version", ["v1", "v2"])
def test_explicit_native_inventory_profile(tmp_path, monkeypatch, capsys, version):
    (tmp_path / "evidence-bundle.json").write_text(json.dumps(inventory(version)))
    main = entry(monkeypatch)
    assert main(["check", "--profile", "native-inventory/" + version, str(tmp_path)]) == 0
    assert "schema only" in capsys.readouterr().out
    other = "v1" if version == "v2" else "v2"
    with pytest.raises(ValidationError):
        main(["check", "--profile", "native-inventory/" + other, str(tmp_path)])


def test_default_protocol_does_not_fall_back_to_inventory(tmp_path, monkeypatch):
    (tmp_path / "evidence-bundle.json").write_text(json.dumps(inventory("v2")))
    (tmp_path / "run-manifest.json").write_text("{}")
    with pytest.raises(ValueError, match="missing required field"):
        entry(monkeypatch)(["check", str(tmp_path)])


def test_unknown_profile_is_refused(tmp_path, monkeypatch):
    with pytest.raises(SystemExit) as error:
        entry(monkeypatch)(["check", "--profile", "unknown", str(tmp_path)])
    assert error.value.code == 2
