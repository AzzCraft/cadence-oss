# Cadence Core security notes

Cadence Core v1.0.0 is an offline verification runtime with deterministic
evidence and canonical JSON. The shipped code includes path containment,
regular-file checks, hash chains, replay-bundle validation, secret-pattern
checks, policy/registry validation, and fail-closed plugin behavior.

The release process generates an SPDX SBOM for the archive and records release
provenance. Cadence Core does **not** ship a cosign verifier, a registry mirror,
or an Egress Guard service.

## Signing

Governed production evidence uses the Ed25519 signing path in the Go runtime.
`scripts/sign-evidence` and `scripts/verify-signature` implement a
development-only HMAC helper for local test fixtures. They read
`CADENCE_SIGNING_KEY` from the environment and never accept a key as a
command-line argument; do not use that helper as a production key-management
system.

## Secret scanning

The built-in baseline scanner checks common credential and private-key patterns.
See `internal/checks/rules.go` for the exact current rule set. Report security
issues through the root repository security policy.
