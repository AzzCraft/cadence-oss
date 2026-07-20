#!/usr/bin/env python3
"""Smoke test: contracts-hub-template self-consistency.

Validates that:
- Every contract has a schema, semantics doc, and valid+invalid fixtures.
- All IDs files are non-empty JSON arrays.
- Schema files are parseable JSON with required structural keys.
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
contracts_dir = ROOT / "contracts"
schemas_dir = contracts_dir / "schemas"
fixtures_dir = contracts_dir / "fixtures"
semantics_dir = contracts_dir / "semantics"
ids_dir = contracts_dir / "ids"

GOVERNED_CONTRACTS = ["run_manifest", "pipeline_result", "job_envelope", "payment"]

errors = []

# Every governed contract must have schema, semantics, and fixtures
for name in GOVERNED_CONTRACTS:
    schema = schemas_dir / f"{name}.schema.json"
    if not schema.exists():
        errors.append(f"missing schema: {schema.name}")
    else:
        data = json.loads(schema.read_text(encoding="utf-8"))
        if "type" not in data and "$schema" not in data:
            errors.append(f"{schema.name}: missing type or $schema")

    sem = semantics_dir / f"{name}.md"
    if not sem.exists():
        errors.append(f"missing semantics: {name}.md")

    valid_dir = fixtures_dir / name / "valid"
    invalid_dir = fixtures_dir / name / "invalid"
    if not valid_dir.is_dir() or not list(valid_dir.glob("*.json")):
        errors.append(f"no valid fixtures for {name}")
    if not invalid_dir.is_dir() or not list(invalid_dir.glob("*.json")):
        errors.append(f"no invalid fixtures for {name}")

    # Valid fixtures must be parseable JSON
    if valid_dir.is_dir():
        for fp in valid_dir.glob("*.json"):
            try:
                json.loads(fp.read_text(encoding="utf-8"))
            except json.JSONDecodeError as e:
                errors.append(f"invalid JSON in {fp}: {e}")

# IDs files
for fn in ("error_codes.json", "job_types.json", "stage_ids.json"):
    p = ids_dir / fn
    if not p.exists():
        errors.append(f"missing ids file: {fn}")
    else:
        arr = json.loads(p.read_text(encoding="utf-8"))
        if not isinstance(arr, list) or not arr:
            errors.append(f"{fn}: must be non-empty array")

if errors:
    for e in errors:
        print(f"FAIL: {e}")
    raise SystemExit(1)

print(f"[contracts-hub-template] OK: {len(GOVERNED_CONTRACTS)} contracts self-consistent")
