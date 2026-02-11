# Cadence OSS

Cadence OSS is the open-source part of the Cadence governance and verification toolchain.

This repo is designed to be vendored into a product repository and used as the "verify gate" layer.

Recommended usage:

- Use **DAS Suite** to pull this repo into `src/cadence-oss`.
- Use `cadencew verify` from inside a product repo, or vendor Cadence into `vendor/cadence`.

## What is included

This repo contains a multi-package layout:

- `cadence-core/` — offline deterministic CLI (`verify`, `scan`, `adopt`, `report`, `lock`, `doctor`)
- `cadence-protocol/` — JSON schemas + lightweight validators
- `cadence-plugins/` — stdlib-only plugin demos (Node + Python)
- `cadence-policy-packs/` — sample policy packs
- `contracts-hub-template/` — example contract hub layout
- `cadence-examples/` — consumer repo demonstrating `cadencew verify`


## Quickstart

Run the OSS verifications:

```bash
bash ./cadence-core/scripts/verify
```

## Notes

- The Cadence Pro and Enterprise repos are optional and may be private.
- DAS Suite can skip them automatically when you do not have permission.
