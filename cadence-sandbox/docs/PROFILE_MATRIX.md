# Sandbox Profile Matrix

This matrix freezes the current sandbox profile family that `cadence-core`
is allowed to consume.

## Canonical profiles

| Profile ID | Backend | Filesystem mode | Network | Time source | Intended use | Main-path eligibility |
| --- | --- | --- | --- | --- | --- | --- |
| `rootless-dev` | `host-local` | `workspace-only` | off | `injected` | local development and active-workspace rehearsal | no |
| `ci-container` | `container-runtime` | `container-isolated` | off | `injected` | CI and merge-to-main verification | yes |
| `release-microvm` | `microvm-runtime` | `microvm-isolated` | off | `injected` | pre-release and forensic verification | yes |

Runtime adapter discovery for the canonical non-host profiles:

- `ci-container` requires `CADENCE_SANDBOX_CONTAINER_ADAPTER`
- `release-microvm` requires `CADENCE_SANDBOX_MICROVM_ADAPTER`

## Compatibility aliases

The current Cadence examples still point at the legacy root profile files:

- `sandbox_profile.json` exposes `sandboxId=local_offline`
- `runtime_profile.json` exposes `runtimeId=strict_offline`
- `sandbox_profile.json` keeps `backend=host-local`

Those root files are compatibility aliases for the canonical profile family.
They remain supported so existing `cadence.yaml` refs stay stable, but new
documentation and future profile growth must be expressed against the canonical
IDs above.

## Hard rules

- `rootless-dev` may exist for convenience, but it is not the formal release
  verification profile.
- `ci-container` and `release-microvm` must keep network disabled, read-only
  inputs, explicit writable output directories, and bounded resources.
- Non-host backends fail closed if those constraints are missing from the
  profile contract.
- Non-host backends also fail closed if runtime attestation cannot prove the
  required seccomp, namespace, cgroup, and namespace-proof-hash checks.
- Non-host backends must execute through their configured runtime adapter; the
  host launcher path is only valid for `rootless-dev` / `host-local`.
- `cadence-core` consumer tests and `cadence-sandbox/scripts/verify` must stay
  aligned with this matrix.
