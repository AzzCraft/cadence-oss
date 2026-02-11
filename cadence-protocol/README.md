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

## Versioning

- Schemas use SemVer under `schemaVersion`.
- Breaking changes MUST bump major.

## Layout

- `schemas/` — JSON Schemas
- `examples/` — example JSON payloads
- `docs/` — conventions (canonical JSON, hashing, signature fields)

Generated: 2026-01-26 (UTC)
