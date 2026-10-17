"""Closed reference contracts and authority separation, using independent wire fixtures."""
from copy import deepcopy
import json
from pathlib import Path

import pytest
from jsonschema.exceptions import ValidationError

from .test_exact_contracts import contracts, preview_v2


def records():
    zero = 'sha256:' + '0' * 64
    preview = preview_v2()
    refs = dict(envelopeDigest=zero, payloadBytesDigest=zero, payloadDigest=zero, approvedFactsDigest=zero, controlContextDigest=zero,
                principals=['TEST-independent-approver'], keyFingerprints=[zero])
    native = dict(contractIdentity='das-approved-facts-check/v1', preview=preview,
                  checkedRefs=refs, authority=False, qualification=False)
    policy = dict(policyId='TEST-policy', policyDigest=zero, policyGeneration=1, authorityEpoch=1)
    target = dict(candidateDigest=zero, deploymentBaselineDigest=zero)
    bundle = dict(contractIdentity='das-bundle-resolution/v1', scope=preview['scope'],
        standardVersion=preview['standardVersion'], policyRef=policy, target=target,
        factsRef=dict(factsId='TEST-facts', factsGeneration=1, **refs),
        current=dict(authorityDomain='TEST-domain', authorityEpoch=1, earliest='2026-10-06T00:00:00Z',
                     latest='2026-10-06T00:00:05Z', observedAt='2026-10-06T00:00:00Z'),
        resolver=dict(binarySha256=zero, releaseVersion='1.0.0'), resolution=preview,
        authorityVerified=True, qualificationEligible=False, status='migration_incomplete',
        digestMethod=contracts.codec.DIGEST_METHOD)
    derivation = {name: bundle[name] for name in ('contractIdentity','scope','standardVersion',
        'policyRef','target','resolver','resolution','status','digestMethod')}
    derivation.update(authorityDomain=bundle['current']['authorityDomain'],
        factsRef={name: bundle['factsRef'][name] for name in ('factsId','factsGeneration','approvedFactsDigest')})
    bundle['bundleDigest'] = contracts.codec.digest(derivation)
    bundle['recordDigest'] = contracts.codec.digest(bundle)
    ref = dict(path='modules/edition-1.5.md', startLine=1, endLine=1,
               startColumn=0, endColumn=4, textSha256='0' * 64)
    pack = dict(contractIdentity='das-context-pack/v1', scope=preview['scope'],
        standardVersion=preview['standardVersion'], bundleDigest=bundle['bundleDigest'],
        policyRef=policy, target=target, catalogDigest=zero, requirementsCatalogDigest=zero,
        resolvedModules=[], requirementTrace=preview['requirementTrace'],
        obligations=[dict(**row, strength='MUST', strengthRef=ref, bodyRefs=[ref],
                          contextRefs=[ref], conditionRefs=[]) for row in preview['requirementTrace']],
        status='migration_incomplete', authorityVerified=False, qualificationEligible=False,
        digestMethod=contracts.codec.DIGEST_METHOD)
    pack['contextPackDigest'] = contracts.codec.digest_catalog(pack)
    return native, bundle, pack


def test_public_probe_installed_facts_record_and_reading_view_have_distinct_contracts():
    for record in records():
        raw = contracts.codec.canonical_catalog(record)
        assert contracts.validate(raw, record['contractIdentity']) == record
    native, bundle, pack = records()
    assert native['authority'] is False and bundle['qualificationEligible'] is False
    assert pack['authorityVerified'] is False and pack['qualificationEligible'] is False


@pytest.mark.parametrize('fault', ['native-authority', 'native-empty-signers', 'native-duplicate-keys',
    'native-extension', 'bundle-qualification', 'bundle-partial-ready', 'bundle-scope',
    'bundle-policy', 'bundle-epoch', 'bundle-digest', 'bundle-resolution-digest', 'pack-authority', 'pack-qualification',
    'pack-empty-trace', 'pack-pass-state', 'pack-false-obligation', 'pack-lost-force',
    'pack-lost-context', 'pack-digest', 'pack-extension'])
def test_facts_bundle_and_context_wire_reject_unearned_authority_or_lost_context(fault):
    native, bundle, pack = deepcopy(records())
    selected = native if fault.startswith('native-') else bundle if fault.startswith('bundle-') else pack
    if fault == 'native-authority': selected['authority'] = True
    elif fault == 'native-empty-signers': selected['checkedRefs']['principals'] = []
    elif fault == 'native-duplicate-keys': selected['checkedRefs']['keyFingerprints'] *= 2
    elif fault == 'bundle-qualification': selected['qualificationEligible'] = True
    elif fault == 'bundle-partial-ready': selected['status'] = 'resolved'
    elif fault == 'bundle-scope': selected['scope'] = 'other-project'
    elif fault == 'bundle-policy': selected['policyRef']['policyDigest'] = 'sha256:' + '1' * 64
    elif fault == 'bundle-epoch': selected['current']['authorityEpoch'] = 2
    elif fault == 'bundle-resolution-digest': selected['resolution']['previewDigest'] = 'sha256:' + '1' * 64
    elif fault == 'pack-authority': selected['authorityVerified'] = True
    elif fault == 'pack-qualification': selected['qualificationEligible'] = True
    elif fault == 'pack-empty-trace': selected['requirementTrace'] = []
    elif fault == 'pack-pass-state': selected['requirementTrace'][0]['state'] = 'PASS'
    elif fault == 'pack-false-obligation': selected['obligations'][0]['state'] = 'false'
    elif fault == 'pack-lost-force': del selected['obligations'][0]['strengthRef']
    elif fault == 'pack-lost-context': selected['obligations'][0]['contextRefs'] = []
    elif fault.endswith('-extension'): selected['permission'] = 'allow'
    if 'bundleDigest' in selected and selected is bundle:
        derivation={name:selected[name] for name in ('contractIdentity','scope','standardVersion',
            'policyRef','target','resolver','resolution','status','digestMethod')}
        derivation.update(authorityDomain=selected['current']['authorityDomain'],
            factsRef={name:selected['factsRef'][name] for name in ('factsId','factsGeneration','approvedFactsDigest')})
        selected['bundleDigest'] = contracts.codec.digest(derivation)
        if fault == 'bundle-digest': selected['bundleDigest'] = 'sha256:' + 'a' * 64
        subject = dict(selected); subject.pop('recordDigest')
        selected['recordDigest'] = contracts.codec.digest(subject)
    if selected is pack:
        subject = dict(selected); subject.pop('contextPackDigest')
        selected['contextPackDigest'] = contracts.codec.digest_catalog(subject) if fault != 'pack-digest' else 'sha256:' + 'a' * 64
    with pytest.raises((ValidationError, ValueError)):
        contracts.validate(contracts.codec.canonical_catalog(selected), selected['contractIdentity'])


def test_new_contracts_keep_the_original_native_resolution_shape():
    root = Path(__file__).resolve().parents[1]/'schemas/das_v1_5'
    original = json.loads((root/'bundle_preview_v2.schema.json').read_bytes())
    for key in ('$schema', '$id', 'title', '$defs'):
        original.pop(key, None)
    for name in ('approved_facts_check', 'bundle_resolution'):
        schema = json.loads((root/(name+'.schema.json')).read_bytes())
        assert schema['$defs']['resolution'] == original


@pytest.mark.parametrize('fault', ['none', 'tamper', 'extra', 'missing-content'])
def test_physical_standard_reference_enters_stable_bundle_digest(fault):
    _, bundle, _ = records()
    zero = 'sha256:' + '0' * 64
    bundle['standardRef'] = dict(snapshotDigest=zero, contentDigest=zero)
    derivation = {name: bundle[name] for name in ('contractIdentity','scope','standardVersion',
        'policyRef','target','resolver','resolution','status','digestMethod','standardRef')}
    derivation.update(authorityDomain=bundle['current']['authorityDomain'],
        factsRef={name: bundle['factsRef'][name] for name in ('factsId','factsGeneration','approvedFactsDigest')})
    original = bundle['bundleDigest']
    bundle['bundleDigest'] = contracts.codec.digest(derivation)
    assert bundle['bundleDigest'] != original
    if fault == 'tamper': bundle['standardRef']['contentDigest'] = 'sha256:' + '1' * 64
    elif fault == 'extra': bundle['standardRef']['permission'] = 'activate'
    elif fault == 'missing-content': bundle['standardRef'].pop('contentDigest')
    subject = dict(bundle); subject.pop('recordDigest')
    bundle['recordDigest'] = contracts.codec.digest(subject)
    raw = contracts.codec.canonical(bundle)
    if fault == 'none': assert contracts.validate(raw, bundle['contractIdentity']) == bundle
    else:
        with pytest.raises((ValidationError, ValueError)): contracts.validate(raw, bundle['contractIdentity'])
