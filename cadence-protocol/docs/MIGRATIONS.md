# Protocol Schema Migrations

## Overview

This document describes how Cadence protocol schema versions are migrated when breaking changes occur.

## Versioning Strategy

Protocol schemas follow semantic versioning:

- **Major**: Breaking changes (field removals, type changes, required to removed).
- **Minor**: Backward-compatible additions (new optional fields, new artifact types).
- **Patch**: Documentation or non-functional fixes.

See [VERSIONING.md](VERSIONING.md) for the full version policy.

## Canonical and Alias Naming

The canonical v9 schema families are:

- `replay_package`
- `plugin_registry_index`
- `signature`
- `envelope`

Deprecated aliases remain readable for one release cycle:

- `replay_bundle`
- `registry_entry`
- `signature_envelope`

Migration work in this pass is naming-compatible rather than payload-breaking. The alias payloads remain schema-equivalent to their canonical counterparts where explicitly marked as aliases.

## Migration Mechanism

### Forward Migration (v1 -> v2)

1. A migration function is registered for each `(fromVersion, toVersion)` pair.
2. When a reader encounters an artifact with an older schema version:
   - it applies the migration chain in order,
   - validates the migrated artifact against the target schema,
   - preserves the original artifact unchanged on disk.

### Backward Compatibility Window

Each major version maintains backward-read compatibility for **N-1** major versions:

| Current | Can Read | Cannot Read |
|---------|----------|-------------|
| v2.x | v1.x, v2.x | v0.x |
| v3.x | v2.x, v3.x | v1.x, v0.x |

### No Backward Migration

Downgrading (v2 -> v1) is not supported. Users must use a reader that supports the artifact's schema version.

## Migration Registry

Compatibility migrations are implemented in `tools/migrate.py` for the governed legacy fixtures in this repo pack.

## Testing

Each migration must have:

- a compatibility fixture under `fixtures/compat/`
- a migration entry in `tools/migrate.py`
- a `scripts/verify-compat` check

## Current Schema Versions

See [COMPATIBILITY_MATRIX.md](COMPATIBILITY_MATRIX.md) for the current version matrix across canonical and deprecated alias names.
