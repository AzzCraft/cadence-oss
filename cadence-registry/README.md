# cadence-registry

Reviewed registry metadata and trust indexes consumed by `cadence-core`.

This directory represents the local registry unit for plugin, policy pack, and
runtime/sandbox profile discovery within `cadence-oss`.

## Structure

```
registry.json                — Full reviewed registry, including opt-in plugins
registry-core.json           — Core-only default registry used by shipped examples
indexes/
  plugins.json               — Registered plugins
  policy-packs.json          — Registered policy packs
  runtime-profiles.json      — Registered runtime and sandbox profiles
schemas/
  registry_index.schema.json — Index entry schema
docs/
  TRUST_MODEL.md             — Trust levels, digest pinning, deprecation
scripts/
  verify                     — Index and both consumer-registry validation
```

## Verification

```bash
./scripts/verify
```

## Split-Trigger Policy

This unit is bundled inside `cadence-oss`. The conditions under which it may be
promoted to an independent release unit are documented in
[`docs/RELEASE_UNITS.md`](../docs/RELEASE_UNITS.md#internal-unit-split-trigger-policy).
