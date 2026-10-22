#!/usr/bin/env python3
"""Small migration helpers for cadence-protocol compatibility fixtures."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def migrate_legacy_run_manifest(payload: dict) -> dict:
    migrated = dict(payload)
    migrated.pop("manifestHash", None)
    version = payload.get('schemaVersion')
    if version not in (None, '0.9.0', '1.0.0'):
        raise ValueError('unsupported migration source schemaVersion')
    migrated['schemaVersion'] = '1.0.0'
    return migrated


def migrate_legacy_pipeline_result(payload: dict) -> dict:
    migrated = dict(payload)
    version = payload.get('schemaVersion')
    if version not in ('0.9.0', '1.0.0'):
        raise ValueError('unsupported migration source schemaVersion')
    migrated['schemaVersion'] = '1.0.0'
    return migrated


def migrate_legacy_job_envelope(payload: dict) -> dict:
    migrated = dict(payload)
    version = payload.get('schemaVersion')
    if version not in ('0.9.0', '1.0.0'):
        raise ValueError('unsupported migration source schemaVersion')
    migrated['schemaVersion'] = '1.0.0'
    return migrated


def migrate_legacy_evidence_bundle(payload: dict) -> dict:
    migrated = dict(payload)
    version = payload.get('schemaVersion')
    if version not in ('0.9.0', '1.0.0'):
        raise ValueError('unsupported migration source schemaVersion')
    migrated['schemaVersion'] = '1.0.0'
    return migrated


MIGRATION_REGISTRY: dict[str, callable] = {
    "legacy-run-manifest": migrate_legacy_run_manifest,
    "legacy-pipeline-result": migrate_legacy_pipeline_result,
    "legacy-job-envelope": migrate_legacy_job_envelope,
    "legacy-evidence-bundle": migrate_legacy_evidence_bundle,
}


def main() -> int:
    parser = argparse.ArgumentParser(prog="migrate.py")
    parser.add_argument("--kind", required=True)
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    data = json.loads(Path(args.input).read_text(encoding="utf-8"))
    fn = MIGRATION_REGISTRY.get(args.kind)
    if fn is None:
        raise SystemExit(f"unsupported migration kind: {args.kind} (known: {', '.join(sorted(MIGRATION_REGISTRY))})")
    migrated = fn(data)
    import validate
    validator = getattr(validate, {'legacy-run-manifest':'validate_run_manifest',
        'legacy-pipeline-result':'validate_pipeline_result', 'legacy-job-envelope':'validate_job_envelope',
        'legacy-evidence-bundle':'validate_evidence_bundle'}[args.kind])
    validator(migrated)

    Path(args.output).write_text(json.dumps(migrated, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
