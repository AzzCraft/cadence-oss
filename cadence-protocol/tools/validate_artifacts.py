#!/usr/bin/env python3
"""Validate Cadence evidence artifacts in a directory (stdlib-only)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from validate import validate_run_manifest, validate_pipeline_result, validate_job_envelope


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print('usage: validate_artifacts.py <evidence_dir>', file=sys.stderr)
        return 2
    d = Path(argv[1]).resolve()
    rm = json.loads((d / 'run-manifest.json').read_text(encoding='utf-8'))
    pr = json.loads((d / 'pipeline-result.json').read_text(encoding='utf-8'))
    je = json.loads((d / 'job-envelope.json').read_text(encoding='utf-8'))
    validate_run_manifest(rm)
    validate_pipeline_result(pr)
    validate_job_envelope(je)
    print('OK: evidence validated', d.name)
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv))
