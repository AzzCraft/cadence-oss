#!/usr/bin/env python3
"""Smoke test: validate all plugin manifests conform to protocol contract."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
manifests_dir = ROOT / "manifests"

REQUIRED_KEYS = ["schemaVersion", "pluginId", "capabilities"]

manifests = sorted(manifests_dir.glob("*.json"))
assert manifests, f"no manifests found in {manifests_dir}"

for mp in manifests:
    data = json.loads(mp.read_text(encoding="utf-8"))
    for k in REQUIRED_KEYS:
        assert k in data, f"{mp.name}: missing required key '{k}'"
    assert isinstance(data["capabilities"], list), f"{mp.name}: capabilities must be list"
    assert len(data["capabilities"]) > 0, f"{mp.name}: capabilities must be non-empty"
    assert isinstance(data["pluginId"], str) and data["pluginId"], f"{mp.name}: pluginId must be non-empty string"
    # entrypoint may use either casing convention
    has_entry = ("entryPoint" in data) or ("entrypoint" in data)
    assert has_entry, f"{mp.name}: entryPoint or entrypoint must be present"
    print(f"OK: {mp.name}")

print(f"[cadence-plugins] {len(manifests)} manifests validated")
