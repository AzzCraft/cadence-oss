# Root Verify Policy

The root `cadence-oss` verifier is orchestration only.

Rules:

- It may call subunit verifiers inside the current repo.
- It must not traverse to any sibling repository.
- It must not assume nested `cadence-oss/cadence-oss/*` paths.
- It must fail if legacy baseline or legacy enterprise naming references remain under this repo.
