# Registry Index Format

## Overview

`cadence-registry` uses one canonical entry shape across:

- `indexes/plugins.json`
- `indexes/policy-packs.json`
- `indexes/runtime-profiles.json`
- `registry.json` (root consumer index used by `cadence-core`)
- `registry-core.json` (core-only root index used by shipped examples)

The schema lives at `schemas/registry_index.schema.json`.

## Entry Contract

Every entry MUST include these fields:

- `id`
- `kind` (`plugin`, `policyPack`, `runtimeProfile`, `sandboxProfile`)
- `version`
- `status` (`active`, `deprecated`, `removed`)
- `digest` (`sha256:<64-hex>`)
- `ref`
- `trust` (`signer`, `allowlisted`)
- `deprecatedAt`
- `deprecationReason`
- `compatWindow`

Status semantics:

- `active`: `deprecatedAt` and `deprecationReason` MUST be `null`; `compatWindow` is still required (`current` by default).
- `active`: `compatWindow` MUST be `current`.
- `deprecated` / `removed`: `deprecatedAt`, `deprecationReason`, and `compatWindow` MUST be non-empty, and `compatWindow` MUST be bounded (`until ...` or `from ... to ...`).

Compat window format is constrained to one of:

- `current`
- `until YYYY-MM-DD`
- `from YYYY-MM-DD to YYYY-MM-DD`

## Verify Requirements

`scripts/verify` enforces:

- JSON validity for all indexes and both consumer registries.
- Full required-key and shape checks for each entry.
- Trust/digest/deprecation/compat metadata semantics.
- Ref target existence checks.
- Root-registry parity with indexed entries for consumed metadata fields.
- Unit tests in `tests/test_registry_semantics.py`.

`cadence-core` consumers must also enforce the same compat-window and
allowlist semantics at runtime, using one shared reference time for policy,
runtime, sandbox, and plugin resolution inside a verify run.
