# Sandbox Upgrade Path

This document governs how the sandbox profile family can evolve without
breaking the current `cadence.yaml` public refs.

## Current compatibility contract

- Existing repos may keep using `runtime_profile.json` and
  `sandbox_profile.json`.
- The canonical profile family lives under `profiles/`.
- Changes to the canonical profiles must preserve the root compatibility
  aliases or explicitly version the alias files.

## Allowed migration path

1. Prove the new profile shape in `profiles/*.json`.
2. Update `docs/PROFILE_MATRIX.md` and `docs/SECURITY_MODEL.md`.
3. Extend `cadence-core/internal/sandbox` tests to consume the new semantics.
4. Extend `cadence-sandbox/tests/test_profiles.py`.
5. Only then point new consumers at the canonical profile.

## Disallowed shortcuts

- Do not silently repurpose `local_offline` into a different isolation model.
- Do not document `strict` / `standard` / `permissive` profiles; those names do
  not describe the current tree.
- Do not add a new profile family without a corresponding `cadence-core`
  consumer test.
