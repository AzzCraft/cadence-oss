# Root Verify Policy

`scripts/verify` is the canonical standalone verifier. Its default is `fast`
and preserves the v1.0 Cadence Core verification contract. `--full` adds the
complete core suite and each of the seven optional public units.

The root verifier must not require a sibling repository, a checkout basename,
Git metadata or network access. Fast mode does not require an optional Cadence
unit. It reports the
verification mode and release identity information needed to audit a result.
