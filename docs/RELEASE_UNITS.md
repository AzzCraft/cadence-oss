# Release Units

`cadence-oss` is a root bundle that releases these internal units together:

- `cadence-protocol`
- `cadence-core`
- `cadence-plugins`
- `cadence-policy-packs`
- `contracts-hub-template`
- `cadence-examples`
- `cadence-sandbox`
- `cadence-registry`

The root repo owns only orchestration, release packaging, and cross-unit documentation. Runtime behavior remains inside the subunits.

## Internal-Unit Split-Trigger Policy

`cadence-sandbox` and `cadence-registry` are currently internal units bundled
within `cadence-oss`. They MAY be promoted to independent release units (sibling
repos or separately versioned packages) when **all** of the following conditions
are met:

1. **Second real consumer** — A second production consumer outside `cadence-core`
   depends on the unit's public contract surface. Internal test or example
   consumers do not count.
2. **Stable contract boundary** — The unit exposes a documented, versioned
   contract (schema + verification script) that has been unchanged for at least
   two consecutive release cycles.
3. **Independent release cadence** — The unit's change frequency diverges from
   the bundle: it requires a release when the rest of `cadence-oss` does not, or
   vice versa, on two or more occasions within a quarter.
4. **Removal of bundle-only coupling** — The unit no longer imports from or
   references other `cadence-oss` internal units at verify-time. All
   cross-unit references go through the protocol contract layer.

Until all four conditions are satisfied, the units remain internal and release
as part of the `cadence-oss` bundle. The decision to split is recorded in this
file and in each unit's README.
