# cadence-policy-packs

Policy packs for Cadence.

## Concepts
- A *policy pack* is a versioned bundle of rules + parameters.
- Cadence Core pins and validates selected pack metadata during `verify`; its fixed built-in scanner does not execute pack rules or parameters.
- Packs can be distributed as offline metadata. Core does not implement a remote policy execution service.
- Historical runtime compatibility fields describe the pack author’s original targets; core does not claim to have enforced those ranges or applied the pack.

## Layout
- `packs/` — versioned packs
- `docs/` — authoring guide
- `examples/` — sample configurations

Generated: 2026-01-26 (UTC)
