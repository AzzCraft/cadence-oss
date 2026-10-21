# Cadence Core Configuration

## Overview

Cadence core reads its configuration from `cadence.yaml` (or `cadence.yml`) at the repository root. Config loading follows the schema-required field set first, then applies semantic validation to closure, tooling, runtime, registry, sandbox, and policy references before verify runs.

## Schema

See [config.schema.json](../config.schema.json) for the formal JSON Schema definition.

## Fields

| Field | Type | Default | Required | Description |
|-------|------|---------|:--------:|-------------|
| `projectId` | string | — | Yes | Unique project identifier |
| `mode` | string | `strict_offline` | No | Execution mode (`strict_offline`, `relaxed`, `ci`) |
| `closureRef` | string | — | Yes | Path to suite version closure file |
| `toolingLock` | string | — | Yes | Path to tooling lock file |
| `runtimeRef` | string | — | Yes | Path to legacy runtime metadata (schemaVersion/runtimeId/networkAccess/deterministicClock); execution controls come from sandboxRef |
| `registryRef` | string | — | Yes | Path to plugin/pack registry index |
| `sandboxRef` | string | — | Yes | Path to sandbox profile file |
| `rootAnchor` | string | `operator-local` | No | Declared signing root anchor used for `key-hierarchy.json` / `hsm-anchor.json` |
| `policies` | list[string] | — | Yes | Policy pack metadata identifiers to pin and validate; rules/params are not executed by core |
| `baselinePath` | string | `.cadence/baseline.json` | No | Path to baseline evidence |

### UI Block

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `ui.enabled` | boolean | `false` | Core verify rejects true as unsupported; use the independent reference UI runner |
| `ui.profile` | string | `pr` | Reference UI profile metadata; core does not execute it |

## Strict Mode Behavior

- Unknown fields are rejected (parser raises error).
- The config must declare explicit refs for closure/lock/policy/runtime when those features are used.
- `closureRef` must be a suite-version-closure artifact, not a generic JSON file or protocol run-manifest.
- `toolingLock` must match the DAS tooling-lock contract and, when present, its `suiteVersionClosureRef` must point back to the configured `closureRef`.
- `rootAnchor` can be overridden at runtime by `CADENCE_ROOT_ANCHOR`; that env var is part of the governed input identity surface.
- Missing required fields fail configuration loading.

## Example

```yaml
projectId: my-product
mode: strict_offline
closureRef: suite_version_closure.json
toolingLock: tooling_lock.json
sandboxRef: sandbox-profile.json
runtimeRef: runtime.json
registryRef: registry.json
rootAnchor: operator-local
policies:
  - core-v140-baseline
  - headless-v140
ui:
  enabled: false
  profile: pr
```

## Policy and runtime metadata boundary

Core executes the fixed built-in scanner rules. Selected policy pack rules,
parameters and historical `runtimeCompatibility` declarations are retained as
metadata, not applied or certified compatible with this Core executable. Evidence
marks those dependencies `metadata-only` and compatibility `not-evaluated-for-execution`.
Malformed or misidentified selected metadata is rejected even when its digest is valid.
Historical `1.4.x` pack declarations do not identify the `1.2.0-beta.1` Core version.
Do not use a successful core scan as proof that a pack-specific policy ran.

### Replay identity compatibility

Cassette content hashes now use the explicit prefix
`cadence-cassette-ordered/v2:sha256:` and preserve interaction order, because
replay consumes responses in that order. Header key order remains irrelevant.
Stored cassette JSON is unchanged; an old sorted/unversioned digest must be
recomputed and labelled with the new identity, not compared as the same format.

Generic JCS JSON accepts exact IEEE-754 integers and the canonical decimal
spelling emitted by JCS for a finite number, so canonical output can be read
again. Integers that would silently round are rejected. Typed protocol fields
that require safe integers retain their narrower bounds; this does not change
those schemas or authorize a wider currency/budget range.
