import importlib.util
import json
from pathlib import Path
import sys
from copy import deepcopy
import socket
import shutil

import pytest
from jsonschema.exceptions import ValidationError

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
spec = importlib.util.spec_from_file_location("cadence_exact_contracts", ROOT / "tools/exact_contracts.py")
contracts = importlib.util.module_from_spec(spec)
spec.loader.exec_module(contracts)
VECTORS = json.loads((ROOT / "fixtures/das_v1_5/text_delta_vectors.json").read_text())["cases"]


@pytest.mark.parametrize("case", [case for case in VECTORS if not case["reject"]], ids=lambda case: case["id"])
def test_python_producer_go_consumer_contract_records(case):
    for record in case["records"]:
        encoded = contracts.codec.canonical(record)
        assert contracts.validate(encoded, record["contractIdentity"]) == record
    assert case["records"][-1]["finalDigest"] == contracts.codec.digest(case["final"])


@pytest.mark.parametrize("number", ["0.0000000000000000001", "9007199254740993", "9007199254740991.1"])
def test_exact_sequence_cannot_be_rounded_into_domain(number):
    record = dict(VECTORS[0]["records"][0])
    raw = json.dumps(record).replace('"seq": 0', '"seq": ' + number).encode()
    with pytest.raises((contracts.codec.ExactJsonError, ValidationError)):
        contracts.validate(raw, "das-text-delta/v1")


def test_legal_numeric_lexeme_no_default_case_folding_or_extension():
    record = dict(VECTORS[0]["records"][0])
    raw = json.dumps(record).replace('"seq": 0', '"seq": 0e0').encode()
    assert contracts.codec.safe_integer(contracts.validate(raw, "das-text-delta/v1")["seq"]) == 0
    for mutation in (b'{"ContractIdentity":"das-text-delta/v1"}', raw[:-1] + b',"approved":true}', raw[:-1] + b',"seq":0}', b'seq: 0'):
        with pytest.raises((contracts.codec.ExactJsonError, ValidationError)):
            contracts.validate(mutation, "das-text-delta/v1")


@pytest.mark.parametrize('mutation', ['remote-ref', 'redirect-ref', 'dialect', 'vocabulary'])
def test_installed_schema_profile_refuses_external_retrieval_and_unapproved_semantics(tmp_path,monkeypatch,mutation):
    """Actual offline validator, a live host control and isolated author copies."""
    identity='das-action-authorization/v1'
    original_root=contracts.ROOT
    raw=(original_root/'fixtures/das_v1_5/action_authorization_vector.json').read_bytes()
    payload=json.loads(raw)['payload']
    expected=contracts.codec.canonical(payload)
    assert contracts.validate(expected,identity)==payload
    target=tmp_path/'schemas/das_v1_5'
    shutil.copytree(original_root/'schemas/das_v1_5',target)
    author=target/contracts.SCHEMAS[identity]
    schema=json.loads(author.read_bytes())
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as listener:
        listener.bind(('127.0.0.1',0));listener.listen(1)
        address=listener.getsockname()
        # Prove the controlled endpoint exists and accepts ordinary host access.
        with socket.create_connection(address,timeout=1):
            connection,_=listener.accept();connection.close()
        if mutation in ('remote-ref','redirect-ref'):
            schema['$ref']='http://127.0.0.1:'+str(address[1])+('/redirect' if mutation=='redirect-ref' else '/schema')
        elif mutation=='dialect':schema['$schema']='http://127.0.0.1:'+str(address[1])+'/dialect'
        else:schema['$vocabulary']={'https://unapproved.invalid/required':True}
        author.write_text(json.dumps(schema))
        monkeypatch.setattr(contracts,'ROOT',tmp_path)
        if mutation in ('remote-ref','redirect-ref'):
            from referencing.exceptions import Unresolvable
            with pytest.raises(Unresolvable,match='Unresolvable'):
                contracts.validate(expected,identity)
        else:
            from referencing.jsonschema import UnknownDialect
            with pytest.raises((ValueError,UnknownDialect)):
                contracts.validate(expected,identity)
        listener.settimeout(.05)
        with pytest.raises(socket.timeout):listener.accept()
    # No defaults, conversion, permission inference or mutation of the input.
    assert contracts.codec.canonical(payload)==expected


@pytest.mark.parametrize('raw', [b'!!python/object/apply:os.system ["touch /tmp/DAS-unapproved"]',
                                b'action: complete\naction: apply\n',
                                b'&loop [*loop]',b'---\n{}\n---\n{}\n'])
def test_json_only_security_contract_does_not_enter_a_yaml_constructor(raw):
    with pytest.raises(contracts.codec.ExactJsonError):
        contracts.validate(raw,'das-action-authorization/v1')


def test_missing_security_field_is_not_filled_from_schema_default():
    value=json.loads((ROOT/'fixtures/das_v1_5/action_authorization_vector.json').read_bytes())['payload']
    valid=contracts.codec.canonical(value)
    assert contracts.validate(valid,'das-action-authorization/v1')==value
    del value['authorityEpoch']
    before=contracts.codec.canonical(value)
    with pytest.raises(ValidationError,match='authorityEpoch'):
        contracts.validate(before,'das-action-authorization/v1')
    assert contracts.codec.canonical(value)==before and 'authorityEpoch' not in value


def test_governed_exact_fixture_family_has_executed_positive_and_negative_cases():
    root = Path(__file__).resolve().parents[1] / 'fixtures/das_v1_5'
    assert contracts.validate((root / 'valid/text_delta.json').read_bytes(), 'das-text-delta/v1')
    with pytest.raises(ValidationError):
        contracts.validate((root / 'invalid/text_delta.json').read_bytes(), 'das-text-delta/v1')


@pytest.mark.parametrize('name', ['analysis_task_binding', 'analysis_verification_plan',
    'analysis_verification_evidence', 'analysis_action_decision', 'analysis_completion',
    'version_verification_plan', 'version_verification_evidence', 'version_action_decision'])
def test_analysis_reference_preserves_closed_shape_and_distinct_identity(name):
    root=ROOT/'fixtures/das_v1_5'; identity='das-'+name.replace('_','-')+'/v1'
    value=contracts.validate((root/'valid'/(name+'.json')).read_bytes(),identity)
    with pytest.raises(ValidationError):
        contracts.validate((root/'invalid'/(name+'.json')).read_bytes(),identity)
    with pytest.raises(ValidationError):
        contracts.validate(contracts.codec.canonical(dict(value,contractIdentity='das-completion/v1')),identity)


def test_independent_action_grant_vector_and_closed_payload():
    fixture = json.loads((ROOT / 'fixtures/das_v1_5/action_authorization_vector.json').read_text())
    payload = fixture['payload']
    identity = 'das-action-authorization/v1'
    assert contracts.validate(contracts.codec.canonical(payload), identity) == payload
    for name, value in [('approved', True), ('authorityEpoch', '1'), ('expiresAt', '2026-02-31T00:00:00Z')]:
        mutation = dict(payload, **{name: value})
        with pytest.raises(ValidationError):
            contracts.validate(contracts.codec.canonical(mutation), identity)


def test_missing_date_time_checker_refuses_even_a_valid_contract(monkeypatch):
    payload = json.loads((ROOT / 'fixtures/das_v1_5/action_authorization_vector.json').read_text())['payload']
    data = contracts.codec.canonical(payload)
    identity = 'das-action-authorization/v1'
    assert contracts.validate(data, identity) == payload
    monkeypatch.delitem(contracts.FormatChecker.checkers, 'date-time')
    with pytest.raises(ValueError, match='date-time validation requires rfc3339-validator'):
        contracts.validate(data, identity)


@pytest.mark.parametrize('name,identity', [('http_declaration','das-http-declaration/v1'),
                                        ('http_inventory','das-http-inventory/v1')])
def test_http_reference_contract_positive_negative_and_single_author_shape(name, identity):
    root = ROOT/'fixtures/das_v1_5'
    value = contracts.validate((root/'valid'/(name+'.json')).read_bytes(), identity)
    with pytest.raises(ValidationError):
        contracts.validate((root/'invalid'/(name+'.json')).read_bytes(), identity)
    with pytest.raises(ValidationError):
        contracts.validate(contracts.codec.canonical(dict(value, secondAuthor='candidate')), identity)


@pytest.mark.parametrize('name,identity', [('candidate_binding','das-candidate-binding/v1'),
    ('version_tree_plan','das-version-tree-plan/v1'), ('version_switch_receipt','das-version-switch-receipt/v1'),
    ('integration_plan','das-integration-plan/v1'), ('integration_receipt','das-integration-receipt/v1'),
    ('completion','das-completion/v1'), ('verification_plan','das-verification-plan/v1'),
    ('verification_evidence','das-verification-evidence/v1'), ('action_decision','das-action-decision/v1')])
def test_candidate_reference_contract_fixtures_and_exact_security_numbers(name,identity):
    root = ROOT / 'fixtures/das_v1_5'
    raw = (root / 'valid' / (name+'.json')).read_bytes()
    record = contracts.validate(raw,identity)
    with pytest.raises(ValidationError):
        contracts.validate((root / 'invalid' / (name+'.json')).read_bytes(),identity)
    field = 'afterGeneration' if name in ('version_switch_receipt','integration_receipt') else 'taskRevision'
    if name in ('verification_plan','verification_evidence','action_decision'):
        illegal=raw.replace(b'"taskRevision": 1',b'"taskRevision": 1.000000000000000001')
        with pytest.raises(ValidationError):contracts.validate(illegal,identity)
        record['bindings']['policyDigest']+='\n'
        with pytest.raises(ValidationError):contracts.validate(contracts.codec.canonical(record),identity)
        return
    illegal = raw.replace(('"'+field+'": '+str(record[field])).encode(),
                          ('"'+field+'": '+str(record[field])+'.000000000000000001').encode())
    assert illegal != raw
    with pytest.raises(ValidationError): contracts.validate(illegal,identity)
    field = 'obligationDigest' if name=='candidate_binding' else 'planDigest' if name in ('version_switch_receipt','integration_receipt') else 'policyDigest'
    record[field] += '\n'
    with pytest.raises(ValidationError): contracts.validate(contracts.codec.canonical(record),identity)


@pytest.mark.parametrize('name,identity', [('integration_plan','das-integration-plan/v1'),
    ('integration_receipt','das-integration-receipt/v1'), ('completion','das-completion/v1')])
def test_integration_native_semantic_preconditions_and_identifier_boundaries(name,identity):
    raw=(ROOT/'fixtures/das_v1_5/valid'/(name+'.json')).read_bytes()
    record=contracts.validate(raw,identity)
    for field,bad in [('policyDigest',record['policyDigest']+'\n'),
                      ('resourceId','bad\x00identity')]:
        value=dict(record,**{field:bad})
        with pytest.raises(ValidationError):contracts.validate(contracts.codec.canonical(value),identity)
    if name=='integration_plan':record['afterCandidateDigest']=record['beforeCandidateDigest']
    elif name=='integration_receipt':record['afterGeneration']=record['beforeGeneration']
    else:record['parentChange']['status']='closing'
    with pytest.raises(ValueError):contracts.validate(contracts.codec.canonical(record),identity)


def preview_v2():
    # Wire-shape fixture only. Actual supported catalogs and predicates are
    # exercised by Core and the pinned cross-component integration tests.
    zero = 'sha256:' + '0' * 64
    output = dict(contractIdentity='das-bundle-preview/v2', scope='wire-fixture',
        standardVersion='1.5.0-beta.1', policyDigest=zero, factsDigest=zero,
        catalogDigest=zero, requirementsCatalogDigest=zero,
        digestMethod=contracts.codec.DIGEST_METHOD, resolvedModules=[], unresolvedModules=[],
        factStates=[], ruleTrace=[], authorityVerified=False, qualificationEligible=False,
        leafMigrationComplete=False,
        limitations=['facts_are_unapproved_proposals','requirement_leaf_migration_incomplete','protected_resolution_not_enabled'],
        requirementTrace=[dict(requirementId=f'das.security-agent.wire-{i:02}',
                              ownerModule='das.security-agent', parentClause='cl-13.13', state='unknown') for i in range(31)])
    output['previewDigest'] = contracts.codec.digest(output)
    return output


def test_partial_leaf_preview_has_an_explicit_closed_wire_profile():
    output = preview_v2()
    assert contracts.validate(contracts.codec.canonical(output), 'das-bundle-preview/v2') == output
    with pytest.raises(ValidationError):
        contracts.validate(contracts.codec.canonical(output), 'das-bundle-preview/v1')
    input = dict(contractIdentity='das-bundle-preview-input/v2',scope='wire-fixture',
                 policyDigest='sha256:'+'0'*64,catalog={},requirementsCatalog={},facts=[])
    assert contracts.validate(contracts.codec.canonical(input), 'das-bundle-preview-input/v2') == input
    with pytest.raises(ValidationError):
        contracts.validate(contracts.codec.canonical(input), 'das-bundle-preview-input/v1')


def test_complete_mapping_is_versioned_without_promoting_public_authority():
    old = preview_v2()
    current = deepcopy(old)
    current.update(contractIdentity='das-bundle-preview/v3', leafMigrationComplete=True,
        limitations=['facts_are_unapproved_proposals', 'protected_resolution_not_enabled'])
    subject = dict(current); subject.pop('previewDigest')
    current['previewDigest'] = contracts.codec.digest(subject)
    assert contracts.validate(contracts.codec.canonical(current), current['contractIdentity']) == current
    assert contracts.validate(contracts.codec.canonical(old), old['contractIdentity']) == old
    for value, identity in ((current, old['contractIdentity']), (old, current['contractIdentity'])):
        with pytest.raises(ValidationError):
            contracts.validate(contracts.codec.canonical(value), identity)
    for field in ('authorityVerified', 'qualificationEligible'):
        with pytest.raises(ValidationError):
            contracts.validate(contracts.codec.canonical(dict(current, **{field: True})), current['contractIdentity'])


@pytest.mark.parametrize('fault', ['omitted-trace', 'empty-trace', 'state-pass', 'leaf-extension',
                                 'complete', 'authority', 'wrong-profile', 'missing-catalog-binding'])
def test_partial_leaf_wire_cannot_claim_completion_or_drop_critical_fields(fault):
    output = deepcopy(preview_v2())
    if fault == 'omitted-trace': del output['requirementTrace']
    elif fault == 'empty-trace': output['requirementTrace'].clear()
    elif fault == 'state-pass': output['requirementTrace'][0]['state'] = 'PASS'
    elif fault == 'leaf-extension': output['requirementTrace'][0]['passed'] = True
    elif fault == 'complete': output['leafMigrationComplete'] = True
    elif fault == 'authority': output['qualificationEligible'] = True
    elif fault == 'wrong-profile': output['contractIdentity'] = 'das-bundle-preview/v1'
    else: del output['requirementsCatalogDigest']
    with pytest.raises(ValidationError):
        contracts.validate(contracts.codec.canonical(output), 'das-bundle-preview/v2')


@pytest.mark.parametrize('analysis', [False, True], ids=['integration', 'analysis'])
@pytest.mark.parametrize('kind', ['verification_plan', 'verification_evidence', 'action_decision'])
def test_completed_work_audit_preserves_legacy_and_refuses_partial_or_mixed_purpose(analysis, kind):
    name = ('analysis_' if analysis else '') + kind
    old = json.loads((ROOT / 'fixtures/das_v1_5/valid' / (name + '.json')).read_bytes())
    identity = old['contractIdentity']
    assert contracts.validate(contracts.codec.canonical(old), identity) == old
    audit = deepcopy(old)
    audit['bindings'].update(completionDigest='sha256:' + '4' * 64,
                             verificationScopeDigest='sha256:' + '5' * 64)
    if kind == 'verification_plan':
        audit.update(actions=['audit'], requireOverallSuccessForActions=['audit'])
        for slot in audit['slots']:
            slot.update(requiredForActions=['audit'], observationSafeForActions=[])
    elif kind == 'action_decision':
        audit['action'] = 'audit'
    assert contracts.validate(contracts.codec.canonical(audit), identity) == audit
    for field in ('completionDigest', 'verificationScopeDigest'):
        corrupt = deepcopy(audit); del corrupt['bindings'][field]
        with pytest.raises(ValidationError):
            contracts.validate(contracts.codec.canonical(corrupt), identity)
    if kind != 'verification_evidence':
        corrupt = deepcopy(audit)
        if kind == 'verification_plan':
            corrupt['actions'].append('complete')
        else:
            corrupt['action'] = 'complete'
        with pytest.raises(ValidationError):
            contracts.validate(contracts.codec.canonical(corrupt), identity)


@pytest.mark.parametrize('action', ['audit', 'integrate', 'complete', 'apply', 'rollback'])
def test_zero_lease_grant_is_audit_only(action):
    value = json.loads((ROOT / 'fixtures/das_v1_5/action_authorization_vector.json').read_bytes())['payload']
    value.update(action=action, leaseGeneration=0)
    if action == 'audit':
        assert contracts.validate(contracts.codec.canonical(value), value['contractIdentity']) == value
    else:
        with pytest.raises(ValidationError):
            contracts.validate(contracts.codec.canonical(value), value['contractIdentity'])
