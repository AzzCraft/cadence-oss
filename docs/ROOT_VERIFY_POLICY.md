# Root Verify Policy

The root `cadence-oss` verifier is orchestration only.

Rules:

- It may call subunit verifiers inside the current repo.
- It must not traverse to any sibling repository.
- It must not assume nested `cadence-oss/cadence-oss/*` paths.
- It must fail if legacy baseline or legacy enterprise naming references remain under this repo.

The public full verifier also runs the explicitly selected root cross-unit and
verify-mode checks. Their four test/helper files are part of the beta public
source closure. Root internal remediation remains in `scripts/verify-root`;
that entry and its internal-only inputs are not required by public verification.
Missing public test files fail verification rather than silently skipping it.
