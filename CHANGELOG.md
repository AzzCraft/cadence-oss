# Changelog

## v1.2.0-beta.1 — Unreleased

- Add the DAS Standard 1.5 reference contracts, exact JSON/current-signature
  consumers, shared module resolver, and Linux/HTTP/UI source reference samples.
- Expose the existing HTTP coverage checker through `contracts check-http-coverage
  --probe`, comparing a separate baseline and observed routes without granting authority.
- Embed the component release version in the executable and its generated locks.
  This source candidate has not passed final installed beta acceptance or shipped.

## v1.0.0 - Current

- Imported `cadence-oss` into the DAS Tools control workspace as a fresh child Git
  repository.
- Removed stale DAS identity history from current-facing child content. Historical
  release context remains parent-audit-only.
