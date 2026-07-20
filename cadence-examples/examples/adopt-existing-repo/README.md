# adopt-existing-repo

Shows how to adopt an existing repository into cadence governance without restructuring.

## Steps

1. Copy `cadence.yaml` and `tooling_lock.json` to your repo root.
2. Run `dasops adopt <repo-path>` to audit compliance.
3. Run `dasops normalize <repo-path>` to auto-create missing files.
4. Add `scripts/verify` to your CI pipeline.
