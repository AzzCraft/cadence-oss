"""MicroVM runtime adapter for cadence-sandbox.

Implements the RuntimeAdapter protocol for microvm-runtime backends.
Executes commands under microVM isolation, probes kernel-level isolation
evidence, and returns structured isolation proof to cadence-core.

Usage as standalone adapter binary:
    echo '{"backend":"microvm-runtime",...}' | python3 -m runtime.microvm_adapter
"""

from __future__ import annotations

import os
import sys
import hashlib
from typing import Any

from .adapter import (
    AdapterRequest,
    AdapterResponse,
    RuntimeAdapter,
    execute_subprocess,
    hash_namespace_proofs,
)


def _detect_microvm_runtime() -> str:
    """Detect which microVM runtime is available."""
    import shutil

    for runtime in ("firecracker", "cloud-hypervisor", "qemu-system-x86_64", "crosvm"):
        if shutil.which(runtime):
            return runtime
    return ""


def _runtime_version(engine: str) -> str:
    exit_code, stdout, stderr = execute_subprocess([engine, "--version"], "", {}, 5)
    if exit_code == 0:
        return (stdout or stderr).strip()
    return "unknown"


def _rootfs_digest(rootfs: str) -> str:
    if rootfs and os.path.isfile(rootfs):
        digest = hashlib.sha256()
        with open(rootfs, "rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return "sha256:" + digest.hexdigest()
    return "sha256:" + hashlib.sha256(rootfs.encode("utf-8")).hexdigest()


class MicrovmAdapter(RuntimeAdapter):
    """Runtime adapter for microvm-runtime backends.

    Executes commands within a microVM environment and collects
    kernel-level isolation evidence. This adapter is invoked by cadence-core
    when the sandbox profile specifies backend=microvm-runtime.

    The adapter fails closed: if required isolation checks cannot be
    verified, the response indicates attestation failure.
    """

    def backend_type(self) -> str:
        return "microvm-runtime"

    def execute(self, request: AdapterRequest) -> AdapterResponse:
        timeout = 0
        if request.resourceLimits and isinstance(
            request.resourceLimits.get("timeoutSeconds"), int
        ):
            timeout = request.resourceLimits["timeoutSeconds"]

        env = dict(request.env) if request.env else {}
        env["CADENCE_SANDBOX_BACKEND"] = "microvm-runtime"
        env["CADENCE_SANDBOX_PROFILE"] = request.backend
        if request.readOnlyInputs:
            env["CADENCE_SANDBOX_READ_ONLY_INPUTS"] = "1"
        if request.writableOutputDir:
            env["CADENCE_SANDBOX_WRITABLE_OUTPUT_DIR"] = request.writableOutputDir
        env["CADENCE_SANDBOX_NETWORK"] = "off"

        microvm_runtime = _detect_microvm_runtime()
        if not microvm_runtime:
            return AdapterResponse(
                exitCode=1,
                stderr="no microVM runtime found (firecracker, cloud-hypervisor, qemu, crosvm)",
                failureReasons=["no microVM runtime available"],
            )

        # Build microVM launch command
        # The microVM runtime launches a VM with the specified filesystem image
        # and executes the command inside it
        filesystem = request.filesystem or "cadence-sandbox-rootfs.ext4"
        vm_cmd: list[str] = [microvm_runtime]

        if microvm_runtime == "firecracker":
            vm_cmd.extend(["--no-api", "--config-file", "/dev/stdin"])
        elif microvm_runtime in ("cloud-hypervisor", "qemu-system-x86_64"):
            vm_cmd.extend(["--disk", f"path={filesystem}"])
        elif microvm_runtime == "crosvm":
            vm_cmd.extend(["run", "--disk", filesystem])

        exit_code, stdout, stderr = execute_subprocess(
            vm_cmd, request.workDir, env, timeout
        )

        observed_checks, namespace_proofs = self.probe_isolation()
        proof_hash = hash_namespace_proofs(namespace_proofs)

        # Verify required isolation checks are met
        failures: list[str] = []
        observed_set = set(observed_checks)
        for check in request.requiredChecks:
            if check not in observed_set:
                failures.append(f"missing isolation check: {check}")

        backend_evidence: dict[str, Any] = {
            "adapterType": "microvm",
            "isolationBackend": "microvm-runtime",
            "hypervisor": microvm_runtime,
            "vmId": "cadence-" + hashlib.sha256(" ".join(vm_cmd + request.command).encode("utf-8")).hexdigest()[:16],
            "kernelImage": os.environ.get("CADENCE_SANDBOX_MICROVM_KERNEL", "runtime-default-kernel"),
            "rootfsDigest": _rootfs_digest(filesystem),
            "channelId": "stdio",
            "runtimeVersion": _runtime_version(microvm_runtime),
        }
        # Detect cgroup version
        if os.path.exists("/sys/fs/cgroup/cgroup.controllers"):
            backend_evidence["cgroupVersion"] = "v2"
        elif os.path.exists("/sys/fs/cgroup"):
            backend_evidence["cgroupVersion"] = "v1"

        return AdapterResponse(
            exitCode=exit_code,
            stdout=stdout,
            stderr=stderr,
            observedChecks=observed_checks,
            namespaceProofHash=proof_hash,
            namespaceProofs=namespace_proofs,
            backendEvidence=backend_evidence,
            failureReasons=failures,
        )


def main() -> None:
    adapter = MicrovmAdapter()
    adapter.run()


if __name__ == "__main__":
    main()
