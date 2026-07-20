# Verify Requirements — Cadence OSS v1.1.0

```bash
bash ./scripts/verify          # fast, default
bash ./scripts/verify --full   # complete eight-unit public bundle
```

Both commands work from an arbitrary clone name and from the extracted source
archive. The verifier prints the selected mode, source identity when available,
Cadence version, DAS Standard manifest version, and tool versions.

## Prerequisites

- Go 1.25.12 or newer, with the checked-in vendored modules available.
- Python 3.10 or newer; `pytest` is required for the full gate.
- Node.js 20 or newer for the TypeScript plugin fixture checks in the full
  gate.
- Bash 3.2 or newer.

## What is verified

- fast: the v1.0-compatible Cadence Core offline build, vet,
  unit/integration tests, and first-party Go formatting;
- full: fast checks, the complete Cadence Core suite, and the protocol,
  plugins, policy packs, contract-hub template, examples, sandbox, and
  registry unit verifiers.

Once prerequisites are installed, both modes are offline and work from an
extracted source archive. Plugin execution remains opt-in: the full gate
validates shipped plugin contracts but does not enable third-party plugins in
the default runtime.

Install the pinned full-gate Python dependency before running the full gate:

```bash
python3 -m pip install -r requirements-verify.txt
```
