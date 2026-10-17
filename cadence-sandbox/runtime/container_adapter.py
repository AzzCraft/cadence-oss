"""Container runtime adapter for cadence-sandbox.

Implements the RuntimeAdapter protocol for container-runtime backends.
Executes commands under container isolation, probes namespace/seccomp/cgroup
evidence, and returns structured isolation proof to cadence-core.

Usage as standalone adapter binary:
    echo '{"backend":"container-runtime",...}' | python3 -m runtime.container_adapter
"""

from __future__ import annotations

import os
import re
import sys
import tempfile
from pathlib import Path
from typing import Any

from .adapter import (
    AdapterRequest,
    AdapterResponse,
    RuntimeAdapter,
    execute_subprocess,
)


_IMAGE_DIGEST_RE = re.compile(
    r"^[a-z0-9][a-z0-9._/-]*@sha256:[0-9a-f]{64}$"
)
_ENV_KEY_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")
_CONTAINER_WORKDIR = "/workspace"
_CONTAINER_OUTPUT_DIR = "/workspace/.cadence/out"
_RUNTIME_ENV = {
    "CADENCE_SANDBOX_BACKEND",
    "CADENCE_SANDBOX_PROFILE",
    "CADENCE_SANDBOX_NETWORK",
    "CADENCE_SANDBOX_FILESYSTEM",
    "CADENCE_SANDBOX_READ_ONLY_INPUTS",
    "CADENCE_SANDBOX_WRITABLE_OUTPUT_DIR",
}


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

    def validate_request(self, request: AdapterRequest) -> list[str]:
        failures = super().validate_request(request)
        if not _IMAGE_DIGEST_RE.fullmatch(request.imageRef):
            failures.append("container-runtime requires a digest-pinned imageRef")
        if request.allowedMounts:
            failures.append("container-runtime does not permit arbitrary allowedMounts")
        if any(not _ENV_KEY_RE.fullmatch(key) for key in request.allowedEnv):
            failures.append("container-runtime allowedEnv contains an invalid key")
        for key in request.env:
            if key not in _RUNTIME_ENV and key not in request.allowedEnv:
                failures.append(f"container-runtime rejected undeclared environment key: {key}")
        limits = request.resourceLimits or {}
        for key in ("cpuLimit", "memoryLimitMB", "pidsLimit", "timeoutSeconds"):
            if not isinstance(limits.get(key), int) or limits[key] <= 0:
                failures.append(f"container-runtime requires a positive resource limit: {key}")
        return failures

    @staticmethod
    def _resolve_mounts(request: AdapterRequest) -> tuple[Path, Path]:
        """Resolve the only two host mounts the runtime is allowed to expose."""
        root = Path(request.workDir).resolve(strict=True)
        if not root.is_dir():
            raise RuntimeError("container-runtime workDir must be a directory")
        configured_output = Path(request.writableOutputDir)
        output = configured_output if configured_output.is_absolute() else root / configured_output
        output.parent.mkdir(parents=True, exist_ok=True)
        output = output.resolve()
        try:
            output.relative_to(root)
        except ValueError as exc:
            raise RuntimeError("container-runtime writableOutputDir must be inside workDir") from exc
        output.mkdir(parents=True, exist_ok=True)
        if output.is_symlink():
            raise RuntimeError("container-runtime writableOutputDir may not be a symlink")
        return root, output

    @staticmethod
    def _container_argument(value: str, workspace: Path, output: Path) -> str:
        """Translate only validated host-workspace paths into container paths."""
        try:
            candidate = Path(value).resolve()
        except (OSError, RuntimeError):
            return value
        for host_path, container_path in ((output, _CONTAINER_OUTPUT_DIR), (workspace, _CONTAINER_WORKDIR)):
            try:
                relative = candidate.relative_to(host_path)
            except ValueError:
                continue
            return container_path if relative == Path(".") else f"{container_path}/{relative.as_posix()}"
        return value

    def execute(self, request: AdapterRequest) -> AdapterResponse:
        limits = request.resourceLimits or {}
        timeout = limits["timeoutSeconds"]

        env = {
            key: value
            for key, value in (request.env or {}).items()
            if key in _RUNTIME_ENV or key in request.allowedEnv
        }
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

        try:
            workspace, output = self._resolve_mounts(request)
        except RuntimeError as exc:
            return AdapterResponse(exitCode=1, failureReasons=[str(exc)])
        if any("," in str(path) or "\n" in str(path) for path in (workspace, output)):
            return AdapterResponse(exitCode=1, failureReasons=["container-runtime mount path is unsafe"])

        cid_file = tempfile.NamedTemporaryFile(prefix="cadence-container-", delete=False)
        cid_file.close()

        # Build container run command with isolation flags
        container_cmd: list[str] = [
            container_runtime, "run", "--rm",
            "--cidfile", cid_file.name,
            "--network", "none",
            "--read-only",
            "--user", "65532:65532",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges:true",
            "--pids-limit", str(limits["pidsLimit"]),
            "--memory", f"{limits['memoryLimitMB']}m",
            "--cpus", str(limits["cpuLimit"]),
            "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=64m",
            "--mount", f"type=bind,src={workspace},dst={_CONTAINER_WORKDIR},readonly",
            "--mount", f"type=bind,src={output},dst={_CONTAINER_OUTPUT_DIR}",
            "--workdir", _CONTAINER_WORKDIR,
        ]
        for key, val in env.items():
            container_cmd.extend(["-e", f"{key}={val}"])
        container_cmd.append(request.imageRef)
        container_cmd.extend(
            self._container_argument(argument, workspace, output)
            for argument in request.command
        )

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

        # Host namespaces are not evidence of the completed container.  The
        # adapter records launch controls only; a production image must emit a
        # guest-signed receipt before cadence-core can treat this as attested.
        observed_checks: list[str] = []
        namespace_proofs: list[dict[str, Any]] = []
        proof_hash = ""

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
            "imageRef": request.imageRef,
            "runtimeVersion": _runtime_version(container_runtime),
            "cgroupPath": "/sys/fs/cgroup",
            "seccompProfileRef": "runtime-default",
            "launchControls": {
                "capabilities": "dropped",
                "network": "none",
                "nonRootUser": "65532:65532",
                "noNewPrivileges": True,
                "readOnlyRoot": True,
                "workspaceMount": "read-only",
                "outputMount": _CONTAINER_OUTPUT_DIR,
            },
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
