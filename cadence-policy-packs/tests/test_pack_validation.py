#!/usr/bin/env python3
"""Smoke test: validate all OSS policy pack YAMLs have required structure."""
import yaml  # noqa: F401 — fallback below if unavailable
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
packs_dir = ROOT / "packs"

REQUIRED_KEYS = ["id", "version"]

# Try yaml, fall back to basic text validation
try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

pack_files = sorted(packs_dir.rglob("pack.yaml"))
assert pack_files, f"no pack.yaml files found in {packs_dir}"

for pf in pack_files:
    text = pf.read_text(encoding="utf-8")
    assert text.strip(), f"{pf}: empty file"

    if HAS_YAML:
        data = yaml.safe_load(text)
        assert isinstance(data, dict), f"{pf}: pack.yaml must be a mapping"
        for k in REQUIRED_KEYS:
            assert k in data, f"{pf}: missing required key '{k}'"
        assert isinstance(data["id"], str) and data["id"], f"{pf}: id must be non-empty string"
    else:
        # Minimal text check: required keys must appear as YAML keys
        for k in REQUIRED_KEYS:
            assert f"{k}:" in text, f"{pf}: missing required key '{k}'"

    print(f"OK: {pf.relative_to(ROOT)}")

print(f"[cadence-policy-packs] {len(pack_files)} packs validated")
