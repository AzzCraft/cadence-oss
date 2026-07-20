"""Container runtime adapter for cadence-sandbox.

Implements the RuntimeAdapter protocol for container-runtime backends.
Executes commands under container isolation, probes namespace/seccomp/cgroup
evidence, and returns structured isolation proof to cadence-core.

Usage as standalone adapter binary:
    echo '{"backend":"container-runtime",...}' | python3 -m runtime.container_adapter
"""

from __future__ import annotations

import os
import sys
import tempfile
from typing import Any

from .adapter import (
    AdapterRequest,
    AdapterResponse,
    RuntimeAdapter,
    execute_subprocess,
    hash_namespace_proofs,
)


def _detect_container_runtime() -> str:
    """Detect which container runtime is available."""
    import shutil

    for runtime in ("docker", "podman", "nerdctl"):
        if shutil.which(runtime):
            return runtime
    return ""


def _runtime_version(engine: str) -> str:
    exit_code, stdout, stderr = execute_subprocess([engine, "--version"], "", {}, 5)
    if exit_code == 0:
        return (stdout or stderr).strip()
    return "unknown"


class ContainerAdapter(RuntimeAdapter):
    """Runtime adapter for container-runtime backends.

    Executes commands within an isolated container namespace and collects
    isolation evidence. This adapter is invoked by cadence-core when the
    sandbox profile specifies backend=container-runtime.

    The adapter fails closed: if required isolation checks cannot be
    verified, the response indicates attestation failure.
    """

    def backend_type(self) -> str:
        return "container-runtime"

    def execute(self, request: AdapterRequest) -> AdapterResponse:
        timeout = 0
        if request.resourceLimits and isinstance(
            request.resourceLimits.get("timeoutSeconds"), int
        ):
            timeout = request.resourceLimits["timeoutSeconds"]

        env = dict(request.env) if request.env else {}
        env["CADENCE_SANDBOX_BACKEND"] = "container-runtime"
        env["CADENCE_SANDBOX_PROFILE"] = request.backend
        if request.readOnlyInputs:
            env["CADENCE_SANDBOX_READ_ONLY_INPUTS"] = "1"
        if request.writableOutputDir:
            env["CADENCE_SANDBOX_WRITABLE_OUTPUT_DIR"] = request.writableOutputDir
        env["CADENCE_SANDBOX_NETWORK"] = "off"

        container_runtime = _detect_container_runtime()
        if not container_runtime:
            return AdapterResponse(
                exitCode=1,
                stderr="no container runtime found (docker, podman, nerdctl)",
                failureReasons=["no container runtime available"],
            )

        cid_file = tempfile.NamedTemporaryFile(prefix="cadence-container-", delete=False)
        cid_file.close()

        # Build container run command with isolation flags
        container_cmd: list[str] = [
            container_runtime, "run", "--rm",
            "--cidfile", cid_file.name,
            "--network", "none",
            "--read-only",
        ]
        for key, val in env.items():
            container_cmd.extend(["-e", f"{key}={val}"])
        if request.workDir:
            container_cmd.extend(["-w", request.workDir])
        if request.writableOutputDir:
            container_cmd.extend(["-v", f"{request.writableOutputDir}:{request.writableOutputDir}"])
        if request.readOnlyInputs:
            container_cmd.append("--tmpfs=/tmp")
        filesystem = request.filesystem or "cadence-sandbox:latest"
        container_cmd.append(filesystem)
        container_cmd.extend(request.command)

        exit_code, stdout, stderr = execute_subprocess(
            container_cmd, request.workDir, {}, timeout
        )
        container_id = ""
        try:
            with open(cid_file.name, encoding="utf-8") as handle:
                container_id = handle.read().strip()
        except OSError:
            container_id = ""
        finally:
            try:
                os.unlink(cid_file.name)
            except OSError:
                pass

        observed_checks, namespace_proofs = self.probe_isolation()
        proof_hash = hash_namespace_proofs(namespace_proofs)

        # Verify required isolation checks are met
        failures: list[str] = []
        observed_set = set(observed_checks)
        for check in request.requiredChecks:
            if check not in observed_set:
                failures.append(f"missing isolation check: {check}")

        backend_evidence: dict[str, Any] = {
            "adapterType": "container",
            "isolationBackend": "container-runtime",
            "engine": container_runtime,
            "containerId": container_id or "unavailable",
            "imageRef": filesystem,
            "runtimeVersion": _runtime_version(container_runtime),
            "cgroupPath": "/sys/fs/cgroup",
            "seccompProfileRef": "runtime-default",
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
    adapter = ContainerAdapter()
    adapter.run()


if __name__ == "__main__":
    main()
