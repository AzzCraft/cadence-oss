# Plugin Versioning Strategy

## Version Semantics

Cadence plugins use **semantic versioning** (MAJOR.MINOR.PATCH):

- **MAJOR**: Breaking changes to the plugin's public contract (entrypoint signature, output schema).
- **MINOR**: New capabilities or non-breaking additions.
- **PATCH**: Bug fixes with no contract changes.

## Protocol Version

Each plugin declares its protocol compatibility via the `compatWindow` field in its manifest:

```json
{
  "compatWindow": {
    "minProtocol": "1.0.0",
    "maxProtocol": "1.x"
  }
}
```

- `minProtocol`: Oldest protocol version the plugin supports.
- `maxProtocol`: Newest protocol version the plugin supports. Use `1.x` for "any 1.x protocol".

## Protocol vs Plugin Version

| Aspect | Protocol Version | Plugin Version |
|--------|:----------------:|:--------------:|
| Scope | cadence-core ↔ plugin wire format | Individual plugin release |
| Owner | cadence-protocol | Plugin author |
| Pace | Slow (rare breaking changes) | Per-plugin cadence |
| Compatibility | Backward-compat within major version | Independent |

## Compatibility Rules

1. A plugin is compatible with cadence-core when the core's protocol version falls within [minProtocol, maxProtocol].
2. Multiple plugins with overlapping `compatWindow` ranges can run together in a single verify flow.
3. If a plugin's `maxProtocol` is below the core's current protocol version, the plugin must be upgraded.

## Upgrade Path

1. Check current protocol version: `cadence verify --version`
2. Check plugin compatibility: inspect each manifest's `compatWindow`
3. If incompatible: update plugin, bump version, test with `scripts/verify`
4. Update registry index if distributed through cadence-registry

## Current Plugin Matrix

| Plugin | Version | Kind | Protocol Window |
|--------|---------|------|:--------------:|
| cadence-plugin-ts | 1.0.0 | linter | 1.0.0 – 1.x |
| cadence-plugin-python | 1.0.0 | linter | 1.0.0 – 1.x |
| cadence-bridge-eslint | 1.0.0 | bridge | 1.0.0 – 1.x |
| cadence-bridge-prettier | 1.0.0 | bridge | 1.0.0 – 1.x |
| cadence-bridge-ruff | 1.0.0 | bridge | 1.0.0 – 1.x |
