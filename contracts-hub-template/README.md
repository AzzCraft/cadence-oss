# Contracts Hub Template (Cadence)

This repository is a reference **Contract Hub** aligned to the DAS Standard.
A contract is only considered *complete* when it includes:

1. Schema (`contracts/schemas/`)
2. Semantics (`contracts/semantics/`)
3. Fixtures (valid + invalid) (`contracts/fixtures/<contract>/{valid,invalid}/`)
4. Executable checks (`contracts/scripts/verify.py`, `contracts/scripts/compatibility_runner.py`)
5. Shared identifiers (`contracts/ids/`)

## Quickstart

```bash
bash ./scripts/verify
```
