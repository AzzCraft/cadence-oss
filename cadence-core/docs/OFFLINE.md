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
