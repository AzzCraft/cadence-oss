# Sandbox Security Model

## Purpose

The Cadence sandbox isolates verification execution from the host system to
provide bounded execution contracts. It does not by itself make an execution
production-attested: a non-host run is accepted only when a guest-generated,
trusted receipt satisfies cadence-core's required checks.

## Isolation Layers

| Layer | Mechanism | Purpose |
|-------|-----------|---------|
| Backend | `host-local` launcher or `container-runtime` / `microvm-runtime` runtime adapter | Freeze the expected isolation backend and emit evidence |
| Filesystem | Read-only input mounts, dedicated writable output | Prevent mutation of source tree |
| Network | Disabled by default | Prevent non-deterministic external calls |
| Resources | CPU/memory/pids/timeout limits | Prevent runaway execution |
| Time | Injected clock source | Prevent wall-clock leakage into deterministic payload |
| Environment | Fixed runtime markers plus profile-declared command keys | Prevent implicit host env injection into an isolated image |

## Escape Classification

All sandbox violations are classified into:

- `hard_fail` — execution terminates immediately, evidence marked invalid
- `soft_fail` — execution continues but violation is recorded in evidence audit trail

## Profile Tiers

1. **rootless-dev** — minimal isolation for local development
2. **ci-container** — container-level isolation for CI pipelines
3. **release-microvm** — disabled compatibility specification; it is not a
   release profile until a guest-executed adapter and trusted receipt exist

## Evidence contract

`cadence-core` writes `sandbox-result.json` with:

- `backend`
- `mode=host-launcher` for `host-local`
- `mode=runtime-exec` for `container-runtime` and `microvm-runtime`
- `isolationLevel=backend-host-local-launcher` / `backend-container-runtime-enforced` / `backend-microvm-runtime-enforced`
- `backendEvidence.contractHash`
- `backendEvidence.attestationStatus`
- `backendEvidence.attestationLevel`
- `backendEvidence.requiredChecks`
- `backendEvidence.observedChecks`
- `backendEvidence.attestationFailures` when proof is insufficient
- `backendEvidence.seccompProfile` for non-host backends
- `backendEvidence.requiredParentEnvKeys`
- `backendEvidence.reservedParentEnvPrefixes`
- `backendEvidence.adapterEnvVar` for non-host backends
- `backendEvidence.adapterExecutable` when a non-host run actually used a runtime adapter
- declared filesystem/network/resource constraints

The contract hash is deterministic and machine-checkable across reruns.

For `container-runtime` and `microvm-runtime`, `cadence-core` sends one JSON
request to the configured runtime adapter:

- `CADENCE_SANDBOX_CONTAINER_ADAPTER` for `container-runtime`
- `CADENCE_SANDBOX_MICROVM_ADAPTER` for `microvm-runtime`

The adapter response must include the target command exit/result plus
machine-checkable guest evidence for seccomp, namespace separation, cgroup
fencing, and a stable receipt/proof hash before the verify path can stay green.
Host-side `/proc` probes after a container has exited are not accepted as guest
evidence. The shipped `microvm_adapter` is deliberately blocked: invoking a
hypervisor command line without a booted guest, command transport, and signed
guest receipt is not microVM execution. Missing adapter configuration, a
non-digest image, undeclared environment/mount, adapter execution failure, or
insufficient proof all fail closed.

The container adapter accepts only a digest-pinned `imageRef`, runs as a
non-root UID with a read-only root, no capabilities, no-new-privileges,
network disabled, resource limits, a read-only workspace mount, and one
validated writable output subdirectory. A release descriptor must supply the
image identity; the source profile intentionally does not fall back to a
mutable image tag.
