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

### Implemented conversion

`tools/migrate.py` selects one of four explicit legacy kinds. It accepts the
retained 0.9.0 fixtures (or the documented unversioned RunManifest) and the
current 1.0.0 identity; other source identities are rejected. The result is
explicitly labelled 1.0.0 and validated before an output file is written.
There is no automatic multi-version migration chain.

### Backward Compatibility Window

The three retained RunManifest, PipelineResult and EvidenceBundle examples
have enough information for the current conversion. The retained legacy
JobEnvelope lacks required timestamps and profile/side-effect provenance,
including run start/end times. Its CLI conversion is rejected; the original
fixture is retained. A caller must supply accurate missing input information
before requesting conversion. The tool never invents those facts.

`scripts/verify-compat` checks the three supported conversions and this explicit
JobEnvelope refusal. Current core-object helpers use the shipped offline
schemas for required fields, optional output, dates and status enums. Passing
those structural checks does not prove native evidence integrity or authorize
an action. Unknown major versions are not accepted by guessing a format.

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
