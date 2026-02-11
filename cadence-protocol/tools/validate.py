"""Cadence protocol validators (stdlib-only).

This repo pack intentionally avoids pip/npm installs.
These validators provide lightweight structural checks; they are not a full JSON Schema implementation.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Dict

_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

def _is_iso_datetime(s: str) -> bool:
    if not isinstance(s, str):
        return False
    try:
        if s.endswith('Z'):
            s = s[:-1] + '+00:00'
        datetime.fromisoformat(s)
        return True
    except Exception:
        return False


def _require(obj: Dict[str, Any], key: str, typ=None) -> Any:
    if key not in obj:
        raise ValueError(f"missing required field: {key}")
    val = obj[key]
    if typ is not None and not isinstance(val, typ):
        raise ValueError(f"field {key} must be {typ.__name__}")
    return val


def _require_str(obj: Dict[str, Any], key: str) -> str:
    return _require(obj, key, str)


def _require_obj(obj: Dict[str, Any], key: str) -> Dict[str, Any]:
    return _require(obj, key, dict)


def _require_list(obj: Dict[str, Any], key: str) -> list:
    return _require(obj, key, list)


def _require_enum(val: Any, allowed: tuple[str, ...], field: str) -> None:
    if val not in allowed:
        raise ValueError(f"{field} must be one of {allowed}, got {val!r}")


def _require_sha256(s: str, field: str) -> None:
    if not isinstance(s, str) or not _SHA256_RE.match(s):
        raise ValueError(f"{field} must be sha256:<64hex>")


def validate_budget(b: Dict[str, Any]) -> None:
    _require_str(b, 'scope')
    for k in ('allocated', 'consumed', 'remaining'):
        d = _require(b, k, dict)
        for kk, vv in d.items():
            if not isinstance(vv, (int, float)):
                raise ValueError(f"budget.{k}.{kk} must be number")
    term = _require_obj(b, 'termination')
    _require_enum(_require_str(term, 'code'),
                  ('ok', 'tokens_exhausted', 'time_exhausted', 'external_calls_exhausted', 'cancelled'),
                  'budget.termination.code')
    children = _require_list(b, 'children')
    for c in children:
        if not isinstance(c, dict):
            raise ValueError('budget.children must be objects')
        validate_budget(c)


def validate_stage_summaries(arr: Any) -> None:
    if not isinstance(arr, list):
        raise ValueError('stageSummaries must be list')
    for s in arr:
        if not isinstance(s, dict):
            raise ValueError('stageSummary must be object')
        _require_str(s, 'stageId')
        _require_str(s, 'status')
        if 'timeMs' in s and not isinstance(s['timeMs'], (int, float)):
            raise ValueError('stageSummary.timeMs must be number')
        if 'codes' in s and not isinstance(s['codes'], list):
            raise ValueError('stageSummary.codes must be list')


def validate_diagnostics(d: Any) -> None:
    if not isinstance(d, dict):
        raise ValueError('diagnostics must be object')
    codes = d.get('codes', [])
    if not isinstance(codes, list) or any(not isinstance(x, str) for x in codes):
        raise ValueError('diagnostics.codes must be list[str]')
    for k in ('kv', 'counters'):
        if k in d and not isinstance(d[k], dict):
            raise ValueError(f'diagnostics.{k} must be object')
    if 'notes' in d and not isinstance(d['notes'], list):
        raise ValueError('diagnostics.notes must be list')


def validate_run_manifest(m: Dict[str, Any]) -> None:
    if 'manifestHash' in m:
        raise ValueError('RunManifest MUST NOT embed manifestHash inside payload')

    _require_str(m, 'schemaVersion')
    _require_str(m, 'runId')
    created = _require_str(m, 'createdAt')
    if not _is_iso_datetime(created):
        raise ValueError('createdAt must be ISO-8601 date-time')

    pipeline = _require_obj(m, 'pipeline')
    _require_str(pipeline, 'id')

    algo = _require_obj(m, 'algorithm')
    _require_str(algo, 'version')

    contracts = _require(m, 'contracts', dict)
    for k, v in contracts.items():
        if not isinstance(k, str) or not isinstance(v, str):
            raise ValueError('contracts must be map[string]string')

    cfg = _require_obj(m, 'config')
    _require_str(cfg, 'profileId')
    if 'configId' not in cfg and 'configHash' not in cfg:
        raise ValueError('config must have configId or configHash')
    if 'configHash' in cfg:
        _require_sha256(cfg['configHash'], 'config.configHash')

    inp = _require_obj(m, 'inputRef')
    _require_str(inp, 'rawInputId')
    if 'inputHash' not in inp and 'snapshotId' not in inp:
        raise ValueError('inputRef must have inputHash or snapshotId')
    if 'inputHash' in inp:
        _require_sha256(inp['inputHash'], 'inputRef.inputHash')

    _require_enum(_require_str(m, 'sideEffectsMode'), ('dryRun', 'sandbox', 'live'), 'sideEffectsMode')

    det = _require_obj(m, 'determinism')
    _require_enum(_require_str(det, 'tier'), ('tier0', 'tier1', 'tier2'), 'determinism.tier')
    if 'seed' in det and not isinstance(det['seed'], int):
        raise ValueError('determinism.seed must be int')

    budget = _require_obj(m, 'budget')
    validate_budget(budget)

    if 'stageSummaries' in m:
        validate_stage_summaries(m['stageSummaries'])
    if 'diagnostics' in m:
        validate_diagnostics(m['diagnostics'])


def validate_pipeline_result(r: Dict[str, Any]) -> None:
    _require_str(r, 'schemaVersion')
    _require_str(r, 'runId')

    pipe = _require_obj(r, 'pipeline')
    _require_str(pipe, 'id')

    status = _require_str(r, 'status')
    # tolerate forward-compatible additions
    if status in ('ok', 'error', 'cancelled'):
        pass

    _require(r, 'output', dict)
    # warnings are optional
    if 'warnings' in r:
        _require(r, 'warnings', list)

    if 'stageSummaries' in r:
        validate_stage_summaries(r['stageSummaries'])

    budget = _require_obj(r, 'budget')
    validate_budget(budget)

    if 'diagnostics' in r:
        validate_diagnostics(r['diagnostics'])

    mr = _require_obj(r, 'manifestRef')
    _require_str(mr, 'runId')
    _require_sha256(_require_str(mr, 'manifestHash'), 'manifestRef.manifestHash')

    # semantic invariant: failure implies error object
    if status in ('error', 'cancelled') and not r.get('error'):
        raise ValueError('PipelineResult: status implies error must be present')


def validate_job_envelope(j: Dict[str, Any]) -> None:
    _require_str(j, 'schemaVersion')
    _require_str(j, 'jobId')
    _require_str(j, 'jobType')
    _require_str(j, 'status')

    for t in ('createdAt', 'updatedAt'):
        if t in j and not _is_iso_datetime(j[t]):
            raise ValueError(f'{t} must be ISO date-time')

    runs = _require(j, 'runs', list)
    for run in runs:
        if not isinstance(run, dict):
            raise ValueError('runs[] must be object')
        mr = run.get('manifestRef') or {}
        res = run.get('result') or {}
        if isinstance(mr, dict) and isinstance(res, dict):
            rr = (res.get('manifestRef') or {})
            if isinstance(rr, dict) and mr.get('manifestHash') and rr.get('manifestHash') and mr['manifestHash'] != rr['manifestHash']:
                raise ValueError('JobEnvelope: runs[].manifestRef must match runs[].result.manifestRef')


def validate_payment(p: Dict[str, Any]) -> None:
    _require_str(p, 'schemaVersion')
    _require_str(p, 'paymentId')
    amt = _require(p, 'amountCents', int)
    if amt < 0:
        raise ValueError('amountCents must be non-negative')

    cur = _require_str(p, 'currency')
    if cur != cur.upper() or len(cur) != 3:
        raise ValueError('currency must be 3-letter uppercase')

    created = _require_str(p, 'createdAt')
    if not _is_iso_datetime(created):
        raise ValueError('createdAt must be ISO date-time')

    _require_str(p, 'status')
def validate_dataset_manifest(m: Dict[str, Any]) -> None:
    """Lightweight DatasetManifest validator (stdlib-only).

    This is NOT full JSON Schema validation. It enforces the key invariants used
    by this repo pack's verify scripts and demo governance flows.
    """
    _require_str(m, 'schemaVersion')
    _require_str(m, 'datasetId')
    _require_str(m, 'datasetVersion')
    _require_str(m, 'owner')
    _require_str(m, 'pointOfContact')

    iu = _require_obj(m, 'intendedUse')
    _require_str(iu, 'purpose')
    restr = _require_list(iu, 'restrictions')
    for r in restr:
        if not isinstance(r, str):
            raise ValueError('intendedUse.restrictions must be string[]')

    prov = _require_obj(m, 'provenance')
    _require_str(prov, 'source')
    _require_str(prov, 'collectionMethod')
    # generatedAt / generatedBy optional

    lic = _require_obj(m, 'license')
    _require_str(lic, 'terms')
    lrest = _require_list(lic, 'restrictions')
    for r in lrest:
        if not isinstance(r, str):
            raise ValueError('license.restrictions must be string[]')

    sens = _require_obj(m, 'sensitivity')
    _require_str(sens, 'pii')
    _require_str(sens, 'accessLevel')

    _require_str(m, 'schemaRef')

    splits = _require_obj(m, 'splits')
    if not splits:
        raise ValueError('splits must be non-empty')
    for name, s in splits.items():
        if not isinstance(name, str) or not name:
            raise ValueError('splits keys must be non-empty strings')
        if not isinstance(s, dict):
            raise ValueError('splits values must be objects')
        cnt = s.get('count')
        if not isinstance(cnt, int) or cnt < 0:
            raise ValueError(f'splits.{name}.count must be non-negative integer')

    # content hash OR snapshot id is required
    has_hash = 'contentHash' in m
    has_snap = 'snapshotId' in m
    if not (has_hash or has_snap):
        raise ValueError('either contentHash or snapshotId is required')
    if has_hash:
        _require_str(m, 'contentHashMethod')
        _require_sha256(_require_str(m, 'contentHash'), 'contentHash')

    ar = _require_obj(m, 'artifactRefs')
    if not ar:
        raise ValueError('artifactRefs must be non-empty')
    for k, v in ar.items():
        if not isinstance(k, str) or not k:
            raise ValueError('artifactRefs keys must be non-empty strings')
        if not isinstance(v, dict):
            raise ValueError(f'artifactRefs[{k}] must be object')
        uri = v.get('uri')
        if not isinstance(uri, str) or not uri:
            raise ValueError(f'artifactRefs[{k}].uri must be string')

    ret = _require_obj(m, 'retention')
    wd = ret.get('windowDays')
    if not isinstance(wd, int) or wd <= 0:
        raise ValueError('retention.windowDays must be positive integer')
    _require_str(ret, 'deletionOwner')


def validate_eval_report(e: Dict[str, Any]) -> None:
    """Lightweight EvalReport validator (stdlib-only)."""
    _require_str(e, 'schemaVersion')
    _require_str(e, 'evalId')
    run_at = _require_str(e, 'runAt')
    if not _is_iso_datetime(run_at):
        raise ValueError('runAt must be ISO date-time')

    ds = _require_obj(e, 'dataset')
    _require_str(ds, 'datasetId')
    _require_str(ds, 'datasetVersion')

    metrics = _require_obj(e, 'metrics')
    if not metrics:
        raise ValueError('metrics must be non-empty')
    for k, v in metrics.items():
        if not isinstance(k, str) or not k:
            raise ValueError('metrics keys must be non-empty strings')
        if not isinstance(v, (int, float)):
            raise ValueError(f'metrics[{k}] must be number')

    status = _require_str(e, 'status')
    _require_enum(status, ('pass', 'fail'), 'status')

    # thresholds optional (numbers)
    if 'thresholds' in e:
        thr = _require_obj(e, 'thresholds')
        for k, v in thr.items():
            if not isinstance(v, (int, float)):
                raise ValueError(f'thresholds[{k}] must be number')
