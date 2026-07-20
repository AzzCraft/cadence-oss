# Root Verify Policy

`scripts/verify` is the canonical standalone verifier for the core-only
archive. Its default is `fast`; `--full` adds every shipped Python test and
helper smoke check.

The root verifier must not require a sibling repository, a checkout basename,
Git metadata, network access, or an unshipped Cadence unit. It reports the
verification mode and release identity information needed to audit a result.
