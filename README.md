# Cadence OSS

Cadence OSS is an offline verification command-line runtime. This first public
release contains the Go implementation in `cadence-core` and its tests.

## What is included

- `cadence-core/` — offline Go CLI (`verify`, `scan`, `report`, `lock`, and `doctor`)
- `cadence-core/internal/` — verification, evidence, replay comparison, and policy implementation
- `cadence-core/scripts/verify` — complete public-source test, vet, and build gate


## Verification

```bash
bash ./scripts/verify
```

## Quickstart

Run all public-source checks:

```bash
bash ./scripts/verify
```

The public v1 runtime does not execute third-party plugins: configured plugin
execution fails closed until a platform-enforced isolated runner is available.
Replay comparison requires separate expected and actual bundles.
