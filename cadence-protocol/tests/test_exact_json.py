import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("cadence_exact_json", ROOT / "tools/exact_json.py")
codec = importlib.util.module_from_spec(spec)
spec.loader.exec_module(codec)
VECTORS = json.loads((ROOT / "fixtures/das_v1_5/exact_json_vectors.json").read_text())["cases"]


@pytest.mark.parametrize("case", VECTORS, ids=lambda case: case["id"])
def test_independent_vectors(case):
    if case["reject"]:
        with pytest.raises(codec.ExactJsonError):
            codec.canonical(codec.parse(case["input"].encode()))
    else:
        assert codec.canonical(codec.parse(case["input"].encode())) == case["canonical"].encode()


@pytest.mark.parametrize("text", ["1", "1.0", "1e0", "-0", "9007199254740991.0"])
def test_exact_integer_lexemes(text):
    codec.safe_integer(codec.parse(text.encode()))


@pytest.mark.parametrize("text", ["0.00000000000000000001", "9007199254740991.1", "9007199254740993", "1e10000", "true", "null", '"1"'])
def test_inexact_integer_rejected(text):
    with pytest.raises(codec.ExactJsonError):
        codec.safe_integer(codec.parse(text.encode()))


@pytest.mark.parametrize("data", [b'"\xff"', b"\xef\xbb\xbf0", b"[" * 65 + b"0" + b"]" * 65, b" " * (codec.MAX_BYTES + 1)])
def test_encoding_and_limits(data):
    with pytest.raises(codec.ExactJsonError):
        codec.parse(data)


def test_exact_closed_keys_and_legacy_identity():
    codec.closed_object(codec.parse(b'{"name":null}'), ["name"])
    for data in (b'{"Name":1}', b'{"name":1,"critical":true}', b'{}'):
        with pytest.raises(codec.ExactJsonError):
            codec.closed_object(codec.parse(data), ["name"])
    assert codec.canonical({"name": "<value>"}) == b'{"name":"<value>"}'
    assert not codec.canonical({"name": "<value>"}).endswith(b"\n")


def test_catalog_budget_keeps_generic_bounds_and_identical_small_digests():
    value = [None] * codec.MAX_NODES  # Root plus children exceed the old limit.
    raw = json.dumps(value).encode()
    with pytest.raises(codec.ExactJsonError): codec.parse(raw)
    with pytest.raises(codec.ExactJsonError): codec.canonical(value)
    assert codec.parse_catalog(raw) == value
    assert codec.canonical_catalog(value) == b'[' + b'null,' * (len(value) - 1) + b'null]'
    too_many = [None] * codec.MAX_CATALOG_NODES
    with pytest.raises(codec.ExactJsonError): codec.parse_catalog(json.dumps(too_many).encode())
    with pytest.raises(codec.ExactJsonError): codec.canonical_catalog(too_many)
    sample = {'a': ['<value>', 1, True, None]}
    assert codec.canonical_catalog(sample) == codec.canonical(sample)
    assert codec.digest_catalog(sample) == codec.digest(sample)


@pytest.mark.parametrize('data', [b'{"a":1,"a":2}', b'"\\ud800"', b'1e10000',
                                 b'[' * 65 + b'0' + b']' * 65,
                                 b' ' * (codec.MAX_BYTES + 1)])
def test_catalog_budget_does_not_relax_encoding_depth_or_numeric_domains(data):
    with pytest.raises(codec.ExactJsonError): codec.parse_catalog(data)


@pytest.mark.parametrize('field,value,valid', [
    ('budget',108.5,True),('budget',True,False),('budget',None,False),
    ('budget','108.5',False),('stage',31.5,True),('stage',False,False),
    ('seed',123456.0,True),('seed',1e3,True),('seed',1.5,False),('seed',True,False),
])
def test_protocol_cli_accepts_exact_numbers_without_accepting_booleans(tmp_path,field,value,valid):
    import subprocess
    import sys
    for stem in ('run_manifest','pipeline_result','job_envelope'):
        data=json.loads((ROOT/'examples'/f'{stem}.example.json').read_text())
        if stem=='run_manifest':
            if field=='budget':data['budget']['consumed']['timeMs']=value
            elif field=='seed':data['determinism']['seed']=value
            else:data['stageSummaries'][0]['timeMs']=value
        (tmp_path/(stem.replace('_','-')+'.json')).write_text(json.dumps(data))
    proc=subprocess.run([sys.executable,'-B',str(ROOT/'tools/validate_artifacts.py'),'--profile','protocol/v1',str(tmp_path)],capture_output=True,text=True)
    assert (proc.returncode==0) is valid,proc.stdout+proc.stderr

@pytest.mark.parametrize("text", ["1e3", "1e16", "9007199254740992.0", "1e21", "-1e16", "-9007199254740992", "9007199254740991", "295147905179352830000"])
def test_canonical_number_round_trip(text):
    first = codec.canonical(codec.parse(text.encode()))
    assert codec.canonical(codec.parse(first)) == first
