# cadence-examples

Example consumer repository layout for Cadence.

This repo is **not** part of Cadence product runtime. It demonstrates:
- `cadence.lock` + `cadencew` wrapper usage (offline-friendly)
- `cadence.yaml` baseline configuration
- UI Blueprint location under `ui/blueprints/`

Generated: 2026-01-27 (UTC)

## Quickstart

Run verify using the repo-local wrapper:

```bash
./cadencew verify --profile dev
```

Notes:
- If a pinned CLI binary exists at `.cadence/bin/cadence`, `cadencew` will use it.
- Otherwise, `cadencew` will build `cadence-core` from `../cadence-core` (requires Go).
