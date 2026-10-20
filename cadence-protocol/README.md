# cadence-protocol

Shared **schemas and contracts** for the Cadence ecosystem.

## Scope

- Evidence artifacts aligned to DAS: **RunManifest**, **PipelineResult**, **JobEnvelope**
- Dataset + evaluation governance artifacts: **DatasetManifest**, **EvalReport**
- Plugin protocol request/response (batch mode)
- Remote execution envelopes (task/result)
- `cadence.lock` schema
- Waiver (break-glass) schema
- Cassette v1 (AI replay record) schema

## Canonical Names

The v9 canonical schema families are:

- `replay_package`
- `plugin_registry_index`
- `signature`
- `envelope`

Deprecated compatibility aliases remain accepted for one release cycle:

- `replay_bundle` -> `replay_package`
- `registry_entry` -> `plugin_registry_index`
- `signature_envelope` -> `signature`

`envelope` is the canonical superset for the current signing payload shape. In this pass it does not require any new producer-only fields.

## Versioning

Version identities are specific to each contract family; do not rewrite legacy
fixtures to a tool release number.

| Contract family | Identity | Reader/profile |
|---|---|---|
| General protocol objects | SemVer `schemaVersion` as required by their own schema | Python `protocol/v1` |
| Historical native inventory | `schemaVersion=1.0.0`, native chain `cadence-run/v1` | Go `cadence-run/v1`; Python `native-inventory/v1` (schema only) |
| Current native inventory | `schemaVersion=cadence-evidence-bundle/v2`, `chainProfile=cadence-run/v1` | Go `cadence-run/v2`; Python `native-inventory/v2` (schema only) |
| Current DAS preview input/result | `contractIdentity=das-bundle-preview-input/v3` / `das-bundle-preview/v3` | `cadence resolve --preview` |
| Standard requirement catalog | `schemaVersion=3.0.0` | Complete-catalog resolver |
| Tool release | `1.2.0-beta.1` | `cadence version --json`; separate from schema identity |

Breaking contract changes require a new applicable major/identity. Native v2
inventory still binds the v1 step-chain profile; those numbers do not conflict.
See [DAS contracts](docs/DAS_V1_5_REFERENCE_CONTRACTS.md) for independently
versioned signed-facts input, payload and outer result identities.

## Layout

- `schemas/` — JSON Schemas
- `examples/` — example JSON payloads
- `docs/` — conventions, versioning, compatibility, migrations
- `MIGRATIONS.md` — compatibility redirect to `docs/MIGRATIONS.md`

Generated: 2026-01-26 (UTC)
