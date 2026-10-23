"""Offline Cadence protocol validators.

Dependencies are declared by the repository verification requirements.
Current core objects use the delivered offline schemas plus semantic checks.
Known 0.9 inputs use the explicit migration helpers, not implicit current decoding.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Dict

_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

from decimal import Decimal
import math


def _is_number(value):
    if type(value) is int:
        return True
    if type(value) is Decimal:
        return value.is_finite()
    return type(value) is float and math.isfinite(value)


def _is_integer(value):
    return _is_number(value) and value == int(value)


def _protocol_version(obj):
    version = _require_str(obj, 'schemaVersion')
    if not re.fullmatch(r'1\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:[-+][0-9A-Za-z.-]+)?', version):
        raise ValueError('unsupported protocol schemaVersion')
    return version


def _schema(name, obj):
    from pathlib import Path
    import json
    from jsonschema import Draft202012Validator, FormatChecker, ValidationError, validators
    from referencing import Registry, Resource
    root = Path(__file__).resolve().parents[1] / 'schemas'
    resources = []
    selected = None
    for path in root.glob('*.schema.json'):
        value = json.loads(path.read_text())
        resources.append((value['$id'], Resource.from_contents(value)))
        if path.name == name + '.schema.json': selected = value
    cls = validators.extend(Draft202012Validator, type_checker=Draft202012Validator.TYPE_CHECKER.redefine(
        'integer', lambda _, value: _is_integer(value)).redefine('number', lambda _, value: _is_number(value)))
    try:
        cls(selected, registry=Registry().with_resources(resources), format_checker=FormatChecker()).validate(obj)
    except ValidationError as exc:
        # Preserve the public validator API used by fixture and CLI consumers.
        # Only invalid instances are translated; schema/resolution errors remain errors.
        raise ValueError(f"{name}: {exc.message}") from exc


def _is_iso_datetime(s: str) -> bool:
    if not isinstance(s, str) or not re.fullmatch(r'\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[Zz]|[+-]\d{2}:\d{2})', s):
        return False
    try:
        if s.endswith(('Z', 'z')):
            s = s[:-1] + '+00:00'
        s = s[:10] + 'T' + s[11:]
        datetime.fromisoformat(s)
        return True
    except Exception:
        return False


def _require(obj: Dict[str, Any], key: str, typ=None) -> Any:
    if key not in obj:
        raise ValueError(f"missing required field: {key}")
    val = obj[key]
    if typ is not None and not (_is_integer(val) if typ is int else isinstance(val, typ)):
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


def _reject_unknown_keys(obj: Dict[str, Any], allowed: set[str], context: str) -> None:
    unexpected = sorted(set(obj) - allowed)
    if unexpected:
        raise ValueError(f"{context} has unsupported fields: {', '.join(unexpected)}")


def validate_budget(b: Dict[str, Any]) -> None:
    _require_str(b, 'scope')
    for k in ('allocated', 'consumed', 'remaining'):
        d = _require(b, k, dict)
        for kk, vv in d.items():
            if not _is_number(vv):
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
        if 'timeMs' in s and not _is_number(s['timeMs']):
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
    _protocol_version(m)
    _schema("run_manifest", m)
    if 'manifestHash' in m:
        raise ValueError('RunManifest MUST NOT embed manifestHash inside payload')

    _protocol_version(m)
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
    if 'seed' in det and not _is_integer(det['seed']):
        raise ValueError('determinism.seed must be int')

    budget = _require_obj(m, 'budget')
    validate_budget(budget)

    if 'stageSummaries' in m:
        validate_stage_summaries(m['stageSummaries'])
    if 'diagnostics' in m:
        validate_diagnostics(m['diagnostics'])


def validate_pipeline_result(r: Dict[str, Any]) -> None:
    _protocol_version(r)
    _schema("pipeline_result", r)
    _protocol_version(r)
    _require_str(r, 'runId')

    pipe = _require_obj(r, 'pipeline')
    _require_str(pipe, 'id')

    status = _require_str(r, 'status')
    _require_enum(status, ('ok', 'degraded', 'error', 'cancelled'), 'status')

    if 'output' in r:
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
    _protocol_version(j)
    _schema("job_envelope", j)
    _protocol_version(j)
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
        validate_pipeline_result(run['result'])
        mr = run.get('manifestRef') or {}
        res = run.get('result') or {}
        if isinstance(mr, dict) and isinstance(res, dict):
            rr = (res.get('manifestRef') or {})
            if isinstance(rr, dict) and mr != rr:
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
    _protocol_version(m)
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
        if not _is_integer(cnt) or cnt < 0:
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
    if not _is_integer(wd) or wd <= 0:
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
        if not _is_number(v):
            raise ValueError(f'metrics[{k}] must be number')

    status = _require_str(e, 'status')
    _require_enum(status, ('pass', 'fail'), 'status')

    # thresholds optional (numbers)
    if 'thresholds' in e:
        thr = _require_obj(e, 'thresholds')
        for k, v in thr.items():
            if not _is_number(v):
                raise ValueError(f'thresholds[{k}] must be number')
    if 'artifacts' in e:
        arts = _require_obj(e, 'artifacts')
        for k, v in arts.items():
            if not isinstance(v, str) or not v:
                raise ValueError(f'artifacts[{k}] must be string')
    if 'diagnostics' in e:
        validate_diagnostics(e['diagnostics'])


def validate_evidence_bundle(b: Dict[str, Any]) -> None:
    _protocol_version(b)
    _schema("evidence_bundle", b)
    _protocol_version(b)
    _require_str(b, 'evidenceId')
    for key in ('runManifestRef', 'pipelineResultRef', 'jobEnvelopeRef'):
        _require_str(b, key)


def validate_replay_package(b: Dict[str, Any]) -> None:
    _protocol_version(b)
    _require_str(b, 'replayId')
    for key in ('runManifestRef', 'pipelineResultRef', 'datasetRef'):
        _require_str(b, key)


def validate_replay_bundle(b: Dict[str, Any]) -> None:
    validate_replay_package(b)


def validate_signature(s: Dict[str, Any]) -> None:
    _require_str(s, 'schemaVersion')
    _require_str(s, 'signatureId')
    _require_str(s, 'algorithm')
    _require_str(s, 'signer')
    _require_sha256(_require_str(s, 'payloadHash'), 'payloadHash')
    _require_str(s, 'signature')


def validate_signature_envelope(s: Dict[str, Any]) -> None:
    validate_signature(s)


def validate_envelope(e: Dict[str, Any]) -> None:
    validate_signature(e)
    if 'envelopeId' in e:
        _require_str(e, 'envelopeId')
    if 'subjects' in e:
        subjects = _require_list(e, 'subjects')
        for item in subjects:
            if not isinstance(item, (str, dict)):
                raise ValueError('subjects must be string[] or object[]')


def validate_plugin_manifest(m: Dict[str, Any]) -> None:
    _protocol_version(m)
    _require_str(m, 'pluginId')
    _require_str(m, 'entryPoint')
    caps = _require_list(m, 'capabilities')
    for item in caps:
        if not isinstance(item, str) or not item:
            raise ValueError('capabilities must be string[]')


def validate_plugin_registry_index(r: Dict[str, Any]) -> None:
    _protocol_version(r)
    _require_str(r, 'registryId')
    entries = _require_list(r, 'entries')
    if not entries:
        raise ValueError('entries must be non-empty')
    for item in entries:
        if not isinstance(item, dict):
            raise ValueError('entries must be object[]')
        _require_str(item, 'kind')
        _require_str(item, 'id')
        _require_str(item, 'ref')


def validate_registry_entry(r: Dict[str, Any]) -> None:
    validate_plugin_registry_index(r)


def validate_sandbox_result(r: Dict[str, Any]) -> None:
    _reject_unknown_keys(
        r,
        {
            'schemaVersion',
            'profileId',
            'backend',
            'mode',
            'isolationLevel',
            'command',
            'workDir',
            'filesystem',
            'networkAccess',
            'readOnlyInputs',
            'writableOutputDir',
            'allowedMounts',
            'resourceLimits',
            'checks',
            'backendEvidence',
            'isolationProbeRef',
            'namespaceProofHash',
            'passed',
            'status',
            'exitCode',
            'stdoutHash',
            'stderrHash',
            'failureReasons',
        },
        'sandbox_result',
    )
    legacy_fields = [field for field in ('sandboxId', 'runId', 'details') if field in r]
    if legacy_fields:
        raise ValueError(
            'legacy abstract sandbox_result envelope is not supported; unexpected fields: '
            + ', '.join(sorted(legacy_fields))
        )
    _protocol_version(r)
    _require_str(r, 'profileId')
    _require_str(r, 'backend')
    _require_str(r, 'mode')
    _require_str(r, 'isolationLevel')
    command = _require_list(r, 'command')
    if any(not isinstance(item, str) for item in command):
        raise ValueError('command must be list[str]')
    _require_str(r, 'workDir')
    _require(r, 'networkAccess', bool)
    checks = _require_list(r, 'checks')
    if any(not isinstance(item, str) for item in checks):
        raise ValueError('checks must be list[str]')
    _require(r, 'passed', bool)
    _require_enum(_require_str(r, 'status'), ('ok', 'denied', 'timeout', 'execution_error'), 'status')
    for key in ('filesystem', 'writableOutputDir', 'isolationProbeRef', 'namespaceProofHash', 'stdoutHash', 'stderrHash'):
        if key in r and not isinstance(r[key], str):
            raise ValueError(f'{key} must be string')
    for key in ('readOnlyInputs',):
        if key in r and not isinstance(r[key], bool):
            raise ValueError(f'{key} must be bool')
    for key in ('allowedMounts', 'failureReasons'):
        if key in r:
            values = _require_list(r, key)
            if any(not isinstance(item, str) for item in values):
                raise ValueError(f'{key} must be list[str]')
    if 'exitCode' in r and not _is_integer(r['exitCode']):
        raise ValueError('exitCode must be int')
    if 'backendEvidence' in r and not isinstance(r['backendEvidence'], dict):
        raise ValueError('backendEvidence must be object')
    if 'resourceLimits' in r:
        limits = _require_obj(r, 'resourceLimits')
        for key in ('maxMemoryMb', 'maxCpuMs', 'maxDiskMb', 'cpuLimit', 'memoryLimitMB', 'pidsLimit', 'timeoutSeconds'):
            if key in limits and not _is_integer(limits[key]):
                raise ValueError(f'resourceLimits.{key} must be int')


def validate_waiver(w: Dict[str, Any]) -> None:
    _require_str(w, 'reason')
    _require_str(w, 'ticket')
    _require_str(w, 'owner')
    _require_str(w, 'approvedBy')
    if 'createdAt' in w and not _is_iso_datetime(_require_str(w, 'createdAt')):
        raise ValueError('createdAt must be ISO date-time')
    if 'expiresAt' in w and not _is_iso_datetime(_require_str(w, 'expiresAt')):
        raise ValueError('expiresAt must be ISO date-time')
    if not _is_iso_datetime(_require_str(w, 'referenceTime')):
        raise ValueError('referenceTime must be ISO date-time')
    _require_str(w, 'signature')
    if 'scope' in w:
        _require_enum(_require_str(w, 'scope'), ('check', 'policy-pack', 'profile'), 'scope')


def validate_waiver_file(wf: Dict[str, Any]) -> None:
    _require_str(wf, 'schemaVersion')
    waivers = _require_list(wf, 'waivers')
    if not waivers:
        raise ValueError('waivers must be non-empty')
    for record in waivers:
        if not isinstance(record, dict):
            raise ValueError('waivers entries must be objects')
        validate_waiver(record)


def validate_key_hierarchy(hierarchy: Dict[str, Any]) -> None:
    _require_str(hierarchy, 'schemaVersion')
    depth = _require(hierarchy, 'depth', int)
    if depth < 1:
        raise ValueError('depth must be >= 1')
    levels = _require_list(hierarchy, 'levels')
    if not levels:
        raise ValueError('levels must be non-empty')
    if depth != len(levels):
        raise ValueError('depth must match number of levels')
    for index, level in enumerate(levels):
        if not isinstance(level, dict):
            raise ValueError('levels entries must be objects')
        level_number = _require(level, 'level', int)
        if level_number != index:
            raise ValueError('levels[].level must be contiguous and zero-based')
        _require_str(level, 'role')
        _require_str(level, 'algorithm')
        _require_str(level, 'keyId')
        _require_str(level, 'anchor')
        if 'issuerKeyId' in level and not isinstance(level['issuerKeyId'], str):
            raise ValueError('issuerKeyId must be string')
    leaf_key_id = _require_str(hierarchy, 'leafKeyId')
    if leaf_key_id != levels[-1]['keyId']:
        raise ValueError('leafKeyId must match the final level keyId')
    _require_str(hierarchy, 'rootAnchor')


def validate_approval_chain(chain: Dict[str, Any]) -> None:
    _require_str(chain, 'waiverTicket')
    entries = _require_list(chain, 'entries')
    if len(entries) < 2:
        raise ValueError('entries must contain at least two approval levels')
    depth = _require(chain, 'depth', int)
    if depth < 2:
        raise ValueError('depth must be >= 2')
    if depth != len(entries):
        raise ValueError('depth must match number of entries')
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError('entries must be objects')
        _require_str(entry, 'role')
        _require_str(entry, 'identity')
        if not _is_iso_datetime(_require_str(entry, 'timestamp')):
            raise ValueError('entries[].timestamp must be ISO date-time')


def validate_isolation_probe(p: Dict[str, Any]) -> None:
    for field in ('pidNamespaced', 'mountNamespaced', 'netNamespaced', 'seccompActive', 'cgroupFenced', 'readonlyRoot'):
        _require(p, field, bool)
    _require_str(p, 'cgroupVersion')
    if 'namespaceProofHash' in p and not isinstance(p['namespaceProofHash'], str):
        raise ValueError('namespaceProofHash must be string')
    if 'namespaceProofs' in p:
        proofs = _require_list(p, 'namespaceProofs')
        for proof in proofs:
            if not isinstance(proof, dict):
                raise ValueError('namespaceProofs entries must be objects')
            _require_str(proof, 'namespace')
            _require(proof, 'matchesInit', bool)
            for key in ('selfDescriptor', 'initDescriptor'):
                if key in proof and not isinstance(proof[key], str):
                    raise ValueError(f'namespaceProofs.{key} must be string')


def validate_hsm_anchor(anchor: Dict[str, Any]) -> None:
    _require_str(anchor, 'schemaVersion')
    _require_str(anchor, 'anchorId')
    _require_str(anchor, 'provider')
    _require_str(anchor, 'keyUri')
    _require_str(anchor, 'attestation')
    _require(anchor, 'hardwareBacked', bool)
    _require_enum(_require_str(anchor, 'status'), ('active',), 'status')


def validate_waiver_audit_trail(trail: Dict[str, Any]) -> None:
    _require_str(trail, 'schemaVersion')
    ticket = _require_str(trail, 'ticket')
    _require_enum(_require_str(trail, 'scope'), ('check', 'policy-pack', 'profile'), 'scope')
    if not _is_iso_datetime(_require_str(trail, 'referenceTime')):
        raise ValueError('referenceTime must be ISO date-time')
    _require_enum(_require_str(trail, 'escalationLevel'), ('none', 'tier1', 'tier2'), 'escalationLevel')
    required_depth = _require(trail, 'requiredChainDepth', int)
    actual_depth = _require(trail, 'actualChainDepth', int)
    if required_depth < 1:
        raise ValueError('requiredChainDepth must be >= 1')
    if actual_depth < 0:
        raise ValueError('actualChainDepth must be >= 0')
    _require(trail, 'compliant', bool)

    approval_chain = _require_obj(trail, 'approvalChain')
    waiver_ticket = _require_str(approval_chain, 'waiverTicket')
    if waiver_ticket != ticket:
        raise ValueError('approvalChain.waiverTicket must match ticket')
    depth = _require(approval_chain, 'depth', int)
    if depth != actual_depth:
        raise ValueError('approvalChain.depth must match actualChainDepth')
    entries = _require_list(approval_chain, 'entries')
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError('approvalChain.entries must be objects')
        _require_str(entry, 'role')
        _require_str(entry, 'identity')
        if not _is_iso_datetime(_require_str(entry, 'timestamp')):
            raise ValueError('approvalChain.entries[].timestamp must be ISO date-time')

    decisions = _require_list(trail, 'decisions')
    if not decisions:
        raise ValueError('decisions must be non-empty')
    for decision in decisions:
        if not isinstance(decision, dict):
            raise ValueError('decisions entries must be objects')
        _require_str(decision, 'check')
        _require_enum(_require_str(decision, 'status'), ('pass', 'fail'), 'decisions.status')
        if 'message' in decision and not isinstance(decision['message'], str):
            raise ValueError('decisions.message must be string')
