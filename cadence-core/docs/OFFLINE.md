# Offline posture (Core)

Cadence Core is designed to be *runtime offline*:
- `verify/scan/adopt/report` MUST NOT require network access during execution.
- Any network usage must be an explicit subcommand (e.g. `fetch`, `fix --endpoint`, `record`), and must be guarded by egress allowlists + audit when enabled.

## Modes
- Strict Offline: no network
- Air-gapped Intranet: only intranet allowlist
- Online Cloud: public network / private link

## Offline attestation (optional)
If configured, an Egress Guard can enforce deny-egress at the process/container layer and emit an attestation artifact into the Evidence output.

## Subprocess environment policy

Cadence subprocesses do not inherit the full parent environment.

- Sandbox launcher env is reduced to an allowlisted parent-key set plus
  explicit `CADENCE_SANDBOX_*` markers.
- Plugin subprocess env is reduced to manifest allowlists plus explicit
  `CADENCE_PLUGIN_*` markers.
- Parent env keys with reserved `CADENCE_SANDBOX_` or `CADENCE_PLUGIN_`
  prefixes are rejected before verify runs.
