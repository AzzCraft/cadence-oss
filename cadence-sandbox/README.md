# cadence-sandbox

Internal sandbox profiles and runtime adapter consumed by `cadence-core`.

This unit is intentionally local to `cadence-oss`; it is not a sibling repo and it is not a customer-facing product.

## Structure

```
profiles/
  rootless-dev.json      — Development: minimal isolation
  ci-container.json      — CI: container-level isolation
  release-microvm.json   — Release: micro-VM full isolation
docs/
  SECURITY_MODEL.md      — Isolation layers, escape classification
scripts/
  verify                 — Profile schema and key validation
sandbox_profile.json     — Legacy root profile (consumed by cadence-core)
runtime_profile.json     — Legacy root runtime profile
```

## Verification

```bash
./scripts/verify
```

## Runtime Adapter Contract

`cadence-core` keeps `host-local` execution on the direct launcher path, but
all non-host profiles now execute through an internal runtime adapter contract.

- `container-runtime` requires `CADENCE_SANDBOX_CONTAINER_ADAPTER`
- `microvm-runtime` requires `CADENCE_SANDBOX_MICROVM_ADAPTER`

The adapter receives one JSON request on `stdin` containing the selected
backend, command, work directory, allowlisted environment, filesystem/network/
resource constraints, and the required proof checks for that backend.

The adapter must return one JSON response on `stdout` containing:

- `exitCode`
- `stdout`
- `stderr`
- `observedChecks`
- `namespaceProofHash`
- optional `namespaceProofs`
- optional backend-specific evidence such as `seccompProfile`

If the adapter is missing, exits unsuccessfully, or returns insufficient proof,
`cadence-core verify` fails closed and records the failure in
`sandbox-result.json`.

## Split-Trigger Policy

This unit is bundled inside `cadence-oss`. The conditions under which it may be
promoted to an independent release unit are documented in
[`docs/RELEASE_UNITS.md`](../docs/RELEASE_UNITS.md#internal-unit-split-trigger-policy).
