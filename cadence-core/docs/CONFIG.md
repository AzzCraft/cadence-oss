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
| `runtimeRef` | string | — | Yes | Path to runtime reference configuration |
| `registryRef` | string | — | Yes | Path to plugin/pack registry index |
| `sandboxRef` | string | — | Yes | Path to sandbox profile file |
| `rootAnchor` | string | `operator-local` | No | Declared signing root anchor used for `key-hierarchy.json` / `hsm-anchor.json` |
| `policies` | list[string] | — | Yes | Policy pack identifiers to apply |
| `baselinePath` | string | `.cadence/baseline.json` | No | Path to baseline evidence |

### UI Block

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `ui.enabled` | boolean | `false` | Enable UI verification |
| `ui.profile` | string | `pr` | UI verification profile |

## Strict Mode Behavior

- Unknown fields are rejected (parser raises error).
- The config must declare explicit refs for closure/lock/policy/runtime when those features are used.
- `closureRef` must be a suite-version-closure artifact, not a generic JSON file or protocol run-manifest.
- `toolingLock` must match the DAS tooling-lock contract and, when present, its `suiteVersionClosureRef` must point back to the configured `closureRef`.
- `rootAnchor` can be overridden at runtime by `CADENCE_ROOT_ANCHOR`; that env var is part of the governed input identity surface.
- Missing required fields fail configuration loading.

## Example shape

The following is an illustrative configuration shape. Every relative path is
owned by the product repository being verified; Cadence Core does not bundle a
suite closure, registry, sandbox service, or policy-pack catalog in this
core-only source archive.

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
  - local-policy
ui:
  enabled: false
  profile: pr
```

For an executable end-to-end example, run the shipped integration suite with
`bash ../scripts/verify --full`; it creates all required local artifacts and
invokes the public CLI without a sibling checkout.
