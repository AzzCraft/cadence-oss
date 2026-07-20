#!/usr/bin/env python3
import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
proto_tools = (ROOT.parents[1] / 'cadence-protocol' / 'tools').resolve()
REQUIRED_VALIDATORS = (
    'validate_run_manifest',
    'validate_pipeline_result',
    'validate_job_envelope',
    'validate_payment',
)


def _load_protocol_validators():
    candidate = proto_tools / 'validate.py'
    if not candidate.is_file():
        return None
    spec = importlib.util.spec_from_file_location('cadence_protocol_validate', candidate)
    if spec is None or spec.loader is None:
        return None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if not all(hasattr(module, name) for name in REQUIRED_VALIDATORS):
        return None
    return tuple(getattr(module, name) for name in REQUIRED_VALIDATORS)


_loaded = _load_protocol_validators()

if _loaded is None:
    def _require(obj, key):
        if key not in obj:
            raise ValueError(f"missing required field: {key}")
        return obj[key]

    def _require_obj(obj, key):
        value = _require(obj, key)
        if not isinstance(value, dict):
            raise ValueError(f"{key} must be object")
        return value

    def validate_run_manifest(m):
        _require(m, "schemaVersion")
        _require(m, "runId")
        _require_obj(m, "pipeline")
        _require_obj(m, "config")
        _require_obj(m, "inputRef")

    def validate_pipeline_result(r):
        _require(r, "schemaVersion")
        _require(r, "runId")
        _require_obj(r, "pipeline")
        status = _require(r, "status")
        _require_obj(r, "manifestRef")
        if status in {"error", "cancelled"} and not r.get("error"):
            raise ValueError("PipelineResult status implies error must be present")

    def validate_job_envelope(j):
        _require(j, "schemaVersion")
        _require(j, "jobId")
        runs = _require(j, "runs")
        if not isinstance(runs, list):
            raise ValueError("runs must be list")
        for run in runs:
            manifest_ref = run.get("manifestRef", {})
            result_ref = run.get("result", {}).get("manifestRef", {})
            if (
                isinstance(manifest_ref, dict)
                and isinstance(result_ref, dict)
                and manifest_ref.get("manifestHash")
                and result_ref.get("manifestHash")
                and manifest_ref["manifestHash"] != result_ref["manifestHash"]
            ):
                raise ValueError("JobEnvelope manifest refs must match")

    def validate_payment(p):
        _require(p, "schemaVersion")
        _require(p, "paymentId")
        currency = _require(p, "currency")
        if not isinstance(currency, str) or currency != currency.upper() or len(currency) != 3:
            raise ValueError("currency must be 3-letter uppercase")
else:
    (
        validate_run_manifest,
        validate_pipeline_result,
        validate_job_envelope,
        validate_payment,
    ) = _loaded

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
