# Trust Model — cadence-registry

## Overview

The Cadence registry is a local trust index for plugins, policy packs,
runtime profiles, and sandbox profiles.  It does NOT host artifacts — it
indexes references and attests to their integrity via digest pins.

## Trust Levels

| Level | Description |
|-------|-------------|
| `active` | Entry is trusted and available for use in verify pipelines. |
| `deprecated` | Entry is still functional but consumers should migrate. |
| `removed` | Entry is no longer available; references to it must fail. |

## Digest Pinning

Entries require a `sha256:` digest and strictly boolean trust metadata. Both
Go and Python resolvers validate the registry structure before selection and
verify the selected file bytes before use. A null digest is not a supported
local-development bypass. Python resolution uses today's date by default;
`--date YYYY-MM-DD` explicitly selects a historical compatibility check.

## Allowlist Enforcement

Only entries present in the registry indexes are permitted in verify
pipelines.  Unknown plugins, packs, or profiles MUST be rejected.

## Deprecation Policy

- When an entry is deprecated, `deprecatedAt`, `deprecationReason`, and
  `compatWindow` fields are set.
- During the compatibility window, the entry may still be used with a
  warning emitted.
- After the window expires, the entry MUST be treated as `removed`.
- `active` entries must use `compatWindow=current`.
- `deprecated` and `removed` entries must use a bounded compat window
  (`until ...` or `from ... to ...`), never `current`.
- `cadence-core` applies these reference-time-aware checks consistently across
  policy packs, runtime profiles, sandbox profiles, and plugins.
