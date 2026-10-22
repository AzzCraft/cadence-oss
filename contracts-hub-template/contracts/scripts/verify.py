#!/usr/bin/env python3
"""Standalone, offline validation of the contracts delivered in this template."""
import json
from pathlib import Path
from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parents[1]
schemas = {}
resources = []
for path in sorted((ROOT / "schemas").glob("*.schema.json")):
    schema = json.loads(path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    resource = Resource.from_contents(schema)
    resources.extend([(schema["$id"], resource), (path.resolve().as_uri(), resource)])
    schemas[path.stem.removesuffix(".schema")] = schema
registry = Registry().with_resources(resources)


def validate(name, value):
    Draft202012Validator(schemas[name], registry=registry, format_checker=FormatChecker()).validate(value)
    if name == "pipeline_result" and value["status"] in {"error", "cancelled"} and not value.get("error"):
        raise ValueError("PipelineResult status implies error must be present")
    if name == "job_envelope":
        for run in value["runs"]:
            validate("pipeline_result", run["result"])
            if run["manifestRef"] != run["result"]["manifestRef"]:
                raise ValueError("JobEnvelope manifest refs must match")
    if name == "payment" and (len(value["currency"]) != 3 or not value["currency"].isascii() or not value["currency"].isalpha() or value["currency"] != value["currency"].upper()):
        raise ValueError("currency must be 3-letter uppercase")


def validate_run_manifest(value): return validate("run_manifest", value)
def validate_pipeline_result(value): return validate("pipeline_result", value)
def validate_job_envelope(value): return validate("job_envelope", value)
def validate_payment(value): return validate("payment", value)

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
    if not (semantics / f'{name}.md').is_file(): raise SystemExit(f'missing semantics: {name}.md')
    vdir = fixtures / name / 'valid'
    idir = fixtures / name / 'invalid'
    val = sorted(vdir.glob('*.json'))
    inv = sorted(idir.glob('*.json'))
    if not val or not inv: raise SystemExit(f'fixtures incomplete for {name}')
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
    if not p.is_file(): raise SystemExit(f'missing ids file: {p}')
    arr = json.loads(p.read_text(encoding='utf-8'))
    if not isinstance(arr, list) or not arr: raise SystemExit(f"invalid ids file: {p}")

print(f'OK: valid_fixtures={tot_v} invalid_fixtures={tot_i}')
