#!/usr/bin/env python3
"""Small migration helpers for cadence-protocol compatibility fixtures."""

from __future__ import annotations

import argparse
import json
import os
import stat
import tempfile
from copy import deepcopy
from decimal import Decimal
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
    migrated = deepcopy(payload)
    version = payload.get('schemaVersion')
    if version not in ('0.9.0', '1.0.0'):
        raise ValueError('unsupported migration source schemaVersion')
    migrated['schemaVersion'] = '1.0.0'
    if not isinstance(migrated.get('runs'), list):
        raise ValueError('JobEnvelope runs must be a list')
    for run in migrated['runs']:
        if not isinstance(run, dict) or not isinstance(run.get('result'), dict):
            raise ValueError('JobEnvelope runs[].result must be an object')
        run['result'] = migrate_legacy_pipeline_result(run['result'])
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


def lossless_json(value):
    """Emit parsed legacy numbers without routing them through binary64/JCS."""
    if isinstance(value, Decimal):
        if not value.is_finite(): raise ValueError('nonfinite migration number')
        return str(value)
    if isinstance(value, dict):
        return '{' + ','.join(json.dumps(key) + ':' + lossless_json(child) for key, child in sorted(value.items())) + '}'
    if isinstance(value, list):
        return '[' + ','.join(lossless_json(child) for child in value) + ']'
    return json.dumps(value, allow_nan=False)


def main() -> int:
    parser = argparse.ArgumentParser(prog="migrate.py")
    parser.add_argument("--kind", required=True)
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    input_path, output_path = Path(args.input), Path(args.output)
    if (output_path.resolve() == input_path.resolve()
            or output_path.exists() and output_path.samefile(input_path)):
        raise ValueError('migration output must differ from the input file')
    if output_path.is_symlink() or output_path.exists() and not output_path.is_file():
        raise ValueError('migration output must be a regular file, not a link or directory')
    import exact_json
    data = exact_json.parse(input_path.read_bytes())
    if not isinstance(data, dict): raise ValueError("migration requires an object")
    fn = MIGRATION_REGISTRY.get(args.kind)
    if fn is None:
        raise SystemExit(f"unsupported migration kind: {args.kind} (known: {', '.join(sorted(MIGRATION_REGISTRY))})")
    migrated = fn(data)
    import validate
    validator = getattr(validate, {'legacy-run-manifest':'validate_run_manifest',
        'legacy-pipeline-result':'validate_pipeline_result', 'legacy-job-envelope':'validate_job_envelope',
        'legacy-evidence-bundle':'validate_evidence_bundle'}[args.kind])
    validator(migrated)

    content = lossless_json(migrated) + "\n"
    mode = stat.S_IMODE(output_path.stat().st_mode) if output_path.exists() else 0o600
    fd, name = tempfile.mkstemp(prefix='.cadence-migrate-', dir=output_path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            stream.write(content)
            os.fchmod(stream.fileno(), mode)
        os.replace(name, output_path)
    finally:
        Path(name).unlink(missing_ok=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
