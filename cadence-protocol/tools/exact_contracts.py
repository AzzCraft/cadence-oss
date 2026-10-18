"""Offline validator for new identities with exact number and field semantics."""
from decimal import Decimal
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker, validators
from referencing import Registry, Resource

try:
    from . import exact_json as codec
except ImportError:
    import exact_json as codec

ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = {
    **{'das-' + name.replace('_', '-') + '/v1': name + '.schema.json'
       for name in ('analysis_task_binding', 'analysis_verification_plan',
                    'analysis_verification_evidence', 'analysis_action_decision', 'analysis_completion',
                    'version_verification_plan', 'version_verification_evidence', 'version_action_decision')},
    "das-http-declaration/v1": "http_declaration.schema.json",
    "das-http-inventory/v1": "http_inventory.schema.json",
    "das-verification-plan/v1": "verification_plan.schema.json",
    "das-verification-evidence/v1": "verification_evidence.schema.json",
    "das-action-decision/v1": "action_decision.schema.json",
    "das-integration-plan/v1": "integration_plan.schema.json",
    "das-integration-receipt/v1": "integration_receipt.schema.json",
    "das-completion/v1": "completion.schema.json",
    'das-approved-facts-check/v1': 'approved_facts_check.schema.json',
    'das-bundle-resolution/v1': 'bundle_resolution.schema.json',
    'das-context-pack/v1': 'context_pack.schema.json',
    "das-approved-facts/v1": "approved_facts.schema.json",
    "das-approved-facts-preview-input/v1": "approved_facts_preview_input.schema.json",
    "das-candidate-binding/v1": "candidate_binding.schema.json",
    "das-version-tree-plan/v1": "version_tree_plan.schema.json",
    "das-version-switch-receipt/v1": "version_switch_receipt.schema.json",
    "das-resource-action-intent/v1": "resource_action_intent.schema.json",
    "das-action-authorization/v1": "action_authorization.schema.json",
    "das-bundle-preview-input/v1": "bundle_preview_input.schema.json",
    "das-bundle-preview/v1": "bundle_preview.schema.json",
    "das-bundle-preview-input/v2": "bundle_preview_input_v2.schema.json",
    "das-bundle-preview/v2": "bundle_preview_v2.schema.json",
    "das-bundle-preview-input/v3": "bundle_preview_input_v3.schema.json",
    "das-bundle-preview/v3": "bundle_preview_v3.schema.json",
    "das-approved-facts-check/v2": "approved_facts_check_v2.schema.json",
    "das-bundle-resolution/v2": "bundle_resolution_v2.schema.json",
    "das-context-pack/v2": "context_pack_v2.schema.json",
    "das-text-delta/v1": "text_delta.schema.json",
    "das-text-delta-end/v1": "text_delta_end.schema.json",
}


def _integer(_, value):
    try:
        codec.safe_integer(value)
        return True
    except ValueError:
        return False


def _number(_, value):
    return not isinstance(value, bool) and isinstance(value, (int, Decimal)) and (not isinstance(value, Decimal) or value.is_finite())


ExactValidator = validators.extend(Draft202012Validator,
    type_checker=Draft202012Validator.TYPE_CHECKER.redefine("integer", _integer).redefine("number", _number))


def _refused(_):
    raise ValueError("external schema retrieval is forbidden")


def validate(data: bytes, identity: str):
    if identity not in SCHEMAS:
        raise ValueError("unsupported exact contract identity")
    value = (codec.parse_catalog(data) if identity in (
        "das-bundle-preview-input/v2", "das-bundle-preview-input/v3", "das-approved-facts-preview-input/v1", "das-context-pack/v1", "das-context-pack/v2") else codec.parse(data))
    schemas = {name: codec.parse((ROOT / "schemas/das_v1_5" / path).read_bytes()) for name, path in SCHEMAS.items()}
    if len({schema["$id"] for schema in schemas.values()}) != len(schemas):
        raise ValueError("duplicate schema author identity")
    registry = Registry(retrieve=_refused).with_resources((schema["$id"], Resource.from_contents(schema)) for schema in schemas.values())
    schema = schemas[identity]
    if schema["$schema"] != "https://json-schema.org/draft/2020-12/schema" or schema.get("$vocabulary"):
        raise ValueError("unapproved schema dialect or required vocabulary")
    ExactValidator.check_schema(schema)
    checker = FormatChecker()
    if 'date-time' not in checker.checkers:
        raise ValueError('date-time validation requires rfc3339-validator; install requirements-verify.txt')
    ExactValidator(schema, registry=registry, format_checker=checker).validate(value)
    if identity in ('das-bundle-resolution/v1', 'das-context-pack/v1', 'das-bundle-resolution/v2', 'das-context-pack/v2'):
        field = 'recordDigest' if identity in ('das-bundle-resolution/v1', 'das-bundle-resolution/v2') else 'contextPackDigest'
        subject = dict(value); received = subject.pop(field)
        actual = codec.digest_catalog(subject) if identity in ('das-context-pack/v1', 'das-context-pack/v2') else codec.digest(subject)
        if actual != received:
            raise ValueError('derived Bundle or Context Pack digest changed')
        if identity in ('das-bundle-resolution/v1', 'das-bundle-resolution/v2'):
            derivation = {name: value[name] for name in ('contractIdentity', 'scope', 'standardVersion',
                'policyRef', 'target', 'resolver', 'resolution', 'status', 'digestMethod')}
            derivation.update(authorityDomain=value['current']['authorityDomain'],
                factsRef={name: value['factsRef'][name] for name in ('factsId', 'factsGeneration', 'approvedFactsDigest')})
            if 'standardRef' in value: derivation['standardRef'] = value['standardRef']
            if codec.digest(derivation) != value['bundleDigest']:
                raise ValueError('stable Bundle derivation digest changed')
        if identity in ('das-bundle-resolution/v1', 'das-bundle-resolution/v2'):
            resolution = value['resolution']
            preview_subject = dict(resolution)
            preview_digest = preview_subject.pop('previewDigest')
            if codec.digest(preview_subject) != preview_digest:
                raise ValueError('Bundle native resolution digest changed')
            if (resolution['scope'] != value['scope'] or resolution['standardVersion'] != value['standardVersion']
                    or resolution['policyDigest'] != value['policyRef']['policyDigest']
                    or value['current']['authorityEpoch'] != value['policyRef']['authorityEpoch']
                    or (resolution['leafMigrationComplete'] is False and value['status'] != 'migration_incomplete')):
                raise ValueError('Bundle bindings or migration status changed')
    if identity == 'das-integration-plan/v1' and value['beforeCandidateDigest'] == value['afterCandidateDigest']:
        raise ValueError('integration plan does not change the target')
    if identity == 'das-integration-receipt/v1' and codec.safe_integer(value['afterGeneration']) != codec.safe_integer(value['beforeGeneration'])+1:
        raise ValueError('integration receipt is not the next target generation')
    if identity == 'das-completion/v1' and value['parentChange']['status']=='closing' and value['parentChange']['taskSetDigest'] is None:
        raise ValueError('closing Completion lacks its frozen task set')
    return value
