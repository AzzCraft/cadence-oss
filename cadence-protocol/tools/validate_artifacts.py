#!/usr/bin/env python3
"""Check the selected protocol structure or native inventory schema.

Native inventory schema checks do not replace evidence-verify's file/chain
integrity checks. Historical protocol objects retain their original contract.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from exact_json import parse as parse_exact
from validate import validate_run_manifest, validate_pipeline_result, validate_job_envelope


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile', choices=('protocol/v1', 'native-inventory/v1', 'native-inventory/v2'), default='protocol/v1')
    parser.add_argument('evidence_dir', type=Path)
    args = parser.parse_args(argv[1:])
    d = args.evidence_dir.resolve()
    if args.profile == 'protocol/v1':
        validate_run_manifest(parse_exact((d / 'run-manifest.json').read_bytes()))
        validate_pipeline_result(parse_exact((d / 'pipeline-result.json').read_bytes()))
        validate_job_envelope(parse_exact((d / 'job-envelope.json').read_bytes()))
        print('OK: historical protocol structure validated', d.name)
        return 0
    inventory = parse_exact((d / 'evidence-bundle.json').read_bytes())
    from jsonschema import Draft202012Validator, FormatChecker
    schemas = Path(__file__).resolve().parents[1] / 'schemas'
    schema_name = {'native-inventory/v1': 'native_evidence_bundle_v1.schema.json',
                   'native-inventory/v2': 'native_evidence_bundle_v2.schema.json'}[args.profile]
    schema = json.loads((schemas / schema_name).read_text())
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(inventory)
    print('OK: native inventory schema only; use evidence-verify for integrity', d.name)
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv))
