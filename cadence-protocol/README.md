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

- Schemas use SemVer under `schemaVersion`.
- Breaking changes MUST bump major.

## Layout

- `schemas/` — JSON Schemas
- `examples/` — example JSON payloads
- `docs/` — conventions, versioning, compatibility, migrations
- `MIGRATIONS.md` — compatibility redirect to `docs/MIGRATIONS.md`

Generated: 2026-01-26 (UTC)
