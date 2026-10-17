"""Exact approved-fact contract fixtures; structural checks grant no authority."""
from copy import deepcopy
import json
from pathlib import Path
import sys

import pytest
from jsonschema.exceptions import ValidationError

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import exact_contracts as contracts


def vector():
    return json.loads((ROOT / 'fixtures/das_v1_5/approved_facts_vector.json').read_text())


def test_public_only_fact_vector_is_closed_and_bindings_are_explicit():
    fixture = vector()
    payload = fixture['payload']
    assert contracts.validate(contracts.codec.canonical(payload), 'das-approved-facts/v1') == payload
    assert payload['policyRef'] == fixture['controlContext']['policyRef']
    assert payload['target'] == fixture['controlContext']['target']
    assert fixture['controlContext']['keys'][0]['principal'] != payload['proposedBy']
    assert 'not authority' in fixture['description']


def facts_input():
    fixture = vector()
    return dict(contractIdentity='das-approved-facts-preview-input/v1', factsEnvelope=fixture['envelope'],
                controlContext=fixture['controlContext'], catalog={}, requirementsCatalog={})


def test_supplied_control_context_has_an_explicit_diagnostic_input_identity():
    value = facts_input()
    assert contracts.validate(contracts.codec.canonical(value), value['contractIdentity']) == value
    with pytest.raises(ValidationError):
        contracts.validate(contracts.codec.canonical(value), 'das-bundle-preview-input/v2')


@pytest.mark.parametrize('fault', ['unsigned-facts', 'missing-time', 'missing-target', 'missing-revocation',
                                 'missing-epoch', 'key-extension', 'generation-null', 'staleness-zero',
                                 'staleness-unbounded', 'threshold-zero', 'invalid-key', 'digest-newline'])
def test_context_input_cannot_omit_binding_or_change_scalar_domains(fault):
    value = facts_input(); context = value['controlContext']
    if fault == 'unsigned-facts': value['facts'] = []
    elif fault == 'missing-time': del context['observedAt']
    elif fault == 'missing-target': del context['target']['candidateDigest']
    elif fault == 'missing-revocation': del context['factsRevoked']
    elif fault == 'missing-epoch': del context['policyRef']['authorityEpoch']
    elif fault == 'key-extension': context['keys'][0]['privateKey'] = 'forbidden'
    elif fault == 'generation-null': context['factsGeneration'] = None
    elif fault == 'staleness-zero': context['maxStalenessSeconds'] = 0
    elif fault == 'staleness-unbounded': context['maxStalenessSeconds'] = 31
    elif fault == 'threshold-zero': context['threshold'] = 0
    elif fault == 'invalid-key': context['keys'][0]['publicKeyBase64'] = 'invalid'
    else: context['target']['candidateDigest'] += '\n'
    with pytest.raises((ValidationError, ValueError)):
        contracts.validate(contracts.codec.canonical(value), value['contractIdentity'])


@pytest.mark.parametrize('fault', ['missing-policy', 'missing-target', 'missing-source', 'unknown-field',
                                 'authority-flag', 'fractional-generation', 'unsafe-generation', 'wrong-value',
                                 'bad-time', 'old-purpose', 'digest-newline', 'key-newline', 'scope-newline'])
def test_signed_fact_structure_preserves_exact_binding_and_scalar_domains(fault):
    payload = deepcopy(vector()['payload'])
    if fault == 'missing-policy': del payload['policyRef']['policyDigest']
    elif fault == 'missing-target': del payload['target']['candidateDigest']
    elif fault == 'missing-source': del payload['facts'][0]['sourceRef']
    elif fault == 'unknown-field': payload['policyRef']['allow'] = True
    elif fault == 'authority-flag': payload['authorityVerified'] = True
    elif fault == 'unsafe-generation': payload['factsGeneration'] = 9007199254740992
    elif fault == 'wrong-value': payload['facts'][0]['value'] = 'false'
    elif fault == 'bad-time': payload['expiresAt'] = 'not-a-time'
    elif fault == 'old-purpose': payload['contractIdentity'] = 'das-action-authorization/v1'
    elif fault == 'digest-newline': payload['catalogDigest'] += '\n'
    elif fault == 'key-newline': payload['facts'][0]['key'] += '\n'
    elif fault == 'scope-newline': payload['scope'] += '\n'
    data = json.dumps(payload, separators=(',', ':'), ensure_ascii=False).encode()
    if fault == 'fractional-generation':
        old = ('"factsGeneration":' + str(payload['factsGeneration'])).encode()
        assert data.count(old) == 1
        data = data.replace(old, old + b'.000000000000000001')
    with pytest.raises((ValidationError, ValueError)):
        contracts.validate(data, 'das-approved-facts/v1')
