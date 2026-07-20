# Changelog

## v1.1.0

Backward-compatible bundle expansion.

- Retains the v1.0.0 Cadence Core CLI, configuration, output schemas, default
  verification behavior, and fail-closed plugin policy.
- Adds reviewed protocol, plugin, policy-pack, contract-hub template, example,
  sandbox, and registry units behind explicit all-unit verification.
- Makes direct core and example-wrapper builds portable outside a Git checkout.
- Corrects policy-pack identifiers and distinguishes DAS Standard compatibility
  from Cadence Core and protocol compatibility.

## v1.0.0

Initial public Cadence Core release.

- Offline Go CLI for verification, scanning, reporting, locking, and doctor
  operations.
- Deterministic evidence, replay-bundle verification, containment checks, and
  fail-closed third-party plugin behavior.
- Standalone fast/full source verification with vendored Go dependencies.
- This release intentionally contains Cadence Core only. Historical unversioned
  repository material outside the core boundary is not a supported v1.0.0
  surface.
