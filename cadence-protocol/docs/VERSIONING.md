# Cadence Protocol Versioning

## Schema Versioning Rules

All Cadence protocol schemas use **Semantic Versioning** (`MAJOR.MINOR.PATCH`).

### Version Semantics

| Change Type | Version Bump | Example |
|------------|-------------|---------|
| Breaking: field removed, type changed, required field added | MAJOR | 1.0.0 → 2.0.0 |
| Additive: optional field added, new enum value | MINOR | 1.0.0 → 1.1.0 |
| Fix: description change, default value fix | PATCH | 1.0.0 → 1.0.1 |

### Writer / Reader Rules

- **Writers** MUST produce the **current** schema version.
- **Readers** MUST accept the current version and MAY accept older versions within the same MAJOR.
- **Readers** MUST reject unknown MAJOR versions (fail-loud).
- **Readers** SHOULD ignore unknown optional fields in MINOR+ versions (forward-compatible).

### Current Schema Versions

| Schema | Version | Status | Notes |
|--------|---------|--------|-------|
| run_manifest | 1.0.0 | canonical | |
| pipeline_result | 1.0.0 | canonical | |
| job_envelope | 1.0.0 | canonical | |
| replay_package | 1.0.0 | canonical | `replay_bundle` remains a deprecated alias |
| replay_bundle | 1.0.0 | deprecated alias | Prefer `replay_package` |
| evidence_bundle | 1.0.0 | canonical | |
| signature | 1.0.0 | canonical | `signature_envelope` remains a deprecated alias |
| signature_envelope | 1.0.0 | deprecated alias | Prefer `signature` |
| envelope | 1.0.0 | canonical | Superset that accepts the current signing payload shape |
| sandbox_result | 1.0.0 | canonical | Runtime-aligned only; legacy abstract envelopes are rejected. |
| sandbox_profile | 1.0.0 | canonical | |
| runtime_profile | 1.0.0 | canonical | |
| plugin_manifest | 1.0.0 | canonical | |
| plugin_registry_index | 1.0.0 | canonical | `registry_entry` remains a deprecated alias |
| registry_entry | 1.0.0 | deprecated alias | Prefer `plugin_registry_index` |
| plugin_request | 1.0.0 | canonical | |
| plugin_response | 1.0.0 | canonical | |
| waiver | 1.0.0 | canonical | |
| cadence_lock | 1.0.0 | canonical | |

### Migration Path

`sandbox_result` does not provide a legacy abstract compatibility mode. Readers
and writers must use the current runtime-aligned shape (`profileId`,
`backend`, `command`, `checks`, `passed`, `status`, etc.) and reject legacy
envelopes built around `sandboxId`, `runId`, or `details`.

When a MAJOR version bump occurs:

1. Add migration handler in `tools/migrate.py` with `--kind <schema>-v<old>-to-v<new>`
2. Add fixtures in `fixtures/` for both old and new versions
3. Update `scripts/verify-compat` to test the new migration
4. Update this table with new version

## Compatibility Matrix

See [COMPATIBILITY_MATRIX.md](COMPATIBILITY_MATRIX.md) for the current reader/writer compatibility table and alias policy.
