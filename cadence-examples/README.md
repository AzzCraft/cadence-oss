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
- `cadencew` builds the current `../cadence-core` source into `.cadence/bin/cadence`
  using Go's build cache (requires Go); an old binary is not reused without a build.
- The core configuration keeps `ui.enabled: false`. For browser verification,
  follow [the explicit UI sample runner](examples/standard-ui-minimal/ui/UI_SPEC.md).
  Passing core verification does not imply that browser checks ran.
- `tooling_lock.json` is the authoritative tool/runtime/policy reference file for this example repo.
- The shared `suite_lock.json` is a separate historical 1.4 compatibility fixture
  required by the legacy closure contract. Root and nested examples reference this
  local file; verification needs no neighboring Suite checkout and does not clone
  or activate the fixture's historical module pins.
