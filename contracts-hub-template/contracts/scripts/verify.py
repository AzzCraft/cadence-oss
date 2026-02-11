#!/usr/bin/env python3
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
proto_tools = (ROOT.parents[1] / 'cadence-protocol' / 'tools').resolve()
sys.path.insert(0, str(proto_tools))

from validate import validate_run_manifest, validate_pipeline_result, validate_job_envelope, validate_payment  # type: ignore

fixtures = ROOT / 'fixtures'
semantics = ROOT / 'semantics'
ids_dir = ROOT / 'ids'

pairs = [
  ('run_manifest', validate_run_manifest),
  ('pipeline_result', validate_pipeline_result),
  ('job_envelope', validate_job_envelope),
  ('payment', validate_payment),
]

tot_v = tot_i = 0
for name, fn in pairs:
    assert (semantics / f'{name}.md').exists(), f'missing semantics: {name}.md'
    vdir = fixtures / name / 'valid'
    idir = fixtures / name / 'invalid'
    val = sorted(vdir.glob('*.json'))
    inv = sorted(idir.glob('*.json'))
    assert val and inv, f'fixtures incomplete for {name}'
    for fp in val:
        inst = json.loads(fp.read_text(encoding='utf-8'))
        fn(inst)
    for fp in inv:
        inst = json.loads(fp.read_text(encoding='utf-8'))
        ok = True
        try:
            fn(inst)
        except Exception:
            ok = False
        if ok:
            raise SystemExit(f'invalid fixture unexpectedly valid: {fp}')
    tot_v += len(val)
    tot_i += len(inv)

for fn in ('error_codes.json','job_types.json','stage_ids.json'):
    p = ids_dir / fn
    assert p.exists(), f'missing ids file: {p}'
    arr = json.loads(p.read_text(encoding='utf-8'))
    assert isinstance(arr, list) and arr

print(f'OK: valid_fixtures={tot_v} invalid_fixtures={tot_i}')
