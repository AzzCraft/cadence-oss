# cadence-examples

Example consumer repository layout for Cadence.

This repo is **not** part of Cadence product runtime. It demonstrates:
- `tooling_lock.json` as the authoritative Cadence input lock
- `suite_version_closure.json` as the pinned suite-closure contract artifact
- `local_extension_manifest.json` as the local extension surface declaration
- `cadence.lock` only as a temporary compatibility concept, not the source of truth
- `cadencew` wrapper usage (offline-friendly)
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
- `tooling_lock.json` is the authoritative tool/runtime/policy reference file for this example repo.
