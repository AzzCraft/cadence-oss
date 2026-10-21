# Contracts Hub Template (Cadence)

This repository is a reference **Contract Hub** aligned to the DAS Standard.
A contract is only considered *complete* when it includes:

1. Schema (`contracts/schemas/`)
2. Semantics (`contracts/semantics/`)
3. Fixtures (valid + invalid) (`contracts/fixtures/<contract>/{valid,invalid}/`) as the canonical fixture tree
4. Executable checks (`contracts/scripts/verify.py`, `contracts/scripts/compatibility_runner.py`)
5. Shared identifiers (`contracts/ids/`)

## Quickstart

```bash
bash ./scripts/verify
```

Notes:

- The canonical fixture location is `contracts/fixtures/`.
- No duplicate top-level `fixtures/` tree is maintained.
- `common.schema.json` supplies shared `$defs`, not a standalone instance contract.
  Core's fixture-presence check exempts only definition containers with annotations
  and optional `type: object`; root constraints or `$ref` still require fixtures.
  Canonical instance contracts need both valid and invalid examples; legacy flat
  fixtures remain readable. This presence check does not replace the schema and
  semantic checks in `contracts/scripts/verify.py`.

## Standalone verification dependencies

Install `python3 -m pip install -r requirements.txt`, then run `bash scripts/verify`.
Contract schemas and semantic checks are bundled; the result does not change
when a neighboring `cadence-protocol` checkout is present or absent. Schema
references resolve only to the delivered local resources, without network access.
`contracts/scripts/compatibility_runner.py` can be invoked from any directory.
