# Verify Requirements — Cadence OSS Core v1.0.0

```bash
bash ./scripts/verify          # fast, default
bash ./scripts/verify --full   # complete Go and Python suite
```

Both commands work from an arbitrary clone name and from the extracted source
archive. The verifier prints the selected mode, source identity when available,
Cadence version, DAS Standard manifest version, and tool versions.

## Prerequisites

- Go 1.25.12 or newer, with the checked-in vendored modules available.
- Python 3.10 or newer; `pytest` is required only for `--full`.
- Bash 3.2 or newer.

## What is verified

- fast: offline Go build, vet, unit/integration tests, and first-party Go
  formatting;
- full: fast checks plus all shipped Python tests and public replay/signing
  helper smoke checks.

The v1.0.0 archive does not contain or verify the separate Cadence protocol,
plugin, policy-pack, sandbox, registry, contract-hub, or examples units.
