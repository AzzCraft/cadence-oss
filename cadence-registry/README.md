# cadence-registry

Internal registry metadata and trust index consumed by `cadence-core`.

This directory represents the local registry unit for plugin, policy pack, and
runtime/sandbox profile discovery within `cadence-oss`.

## Structure

```
registry.json                — Canonical consumer registry (consumed by cadence-core)
indexes/
  plugins.json               — Registered plugins
  policy-packs.json          — Registered policy packs
  runtime-profiles.json      — Registered runtime and sandbox profiles
schemas/
  registry_index.schema.json — Index entry schema
docs/
  TRUST_MODEL.md             — Trust levels, digest pinning, deprecation
scripts/
  verify                     — Index validation
```

## Verification

```bash
./scripts/verify
```

## Split-Trigger Policy

This unit is bundled inside `cadence-oss`. The conditions under which it may be
promoted to an independent release unit are documented in
[`docs/RELEASE_UNITS.md`](../docs/RELEASE_UNITS.md#internal-unit-split-trigger-policy).
