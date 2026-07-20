"""Base runtime adapter protocol for cadence-sandbox.

This module defines the adapter interface and shared protocol that both
container and microvm adapters implement. Adapters communicate with
cadence-core via stdin/stdout JSON protocol:

  - Receives a RuntimeAdapterRequest JSON object on stdin
  - Returns a RuntimeAdapterResponse JSON object on stdout

The adapter MUST fail closed: if any isolation check cannot be verified,
the response must indicate failure.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class AdapterRequest:
    """Mirrors cadence-core RuntimeAdapterRequest."""

    backend: str
    command: list[str]
    workDir: str
    env: dict[str, str] = field(default_factory=dict)
    filesystem: str = ""
    networkAccess: bool = False
    readOnlyInputs: bool = False
    writableOutputDir: str = ""
    allowedMounts: list[str] = field(default_factory=list)
    resourceLimits: dict[str, Any] | None = None
    requiredChecks: list[str] = field(default_factory=list)
    requiredParentEnvKeys: list[str] = field(default_factory=list)
    reservedParentEnvPrefixes: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AdapterRequest:
        return cls(
            backend=data.get("backend", ""),
            command=data.get("command", []),
            workDir=data.get("workDir", ""),
            env=data.get("env") or {},
            filesystem=data.get("filesystem", ""),
            networkAccess=data.get("networkAccess", False),
            readOnlyInputs=data.get("readOnlyInputs", False),
            writableOutputDir=data.get("writableOutputDir", ""),
            allowedMounts=data.get("allowedMounts") or [],
            resourceLimits=data.get("resourceLimits"),
            requiredChecks=data.get("requiredChecks") or [],
            requiredParentEnvKeys=data.get("requiredParentEnvKeys") or [],
            reservedParentEnvPrefixes=data.get("reservedParentEnvPrefixes") or [],
        )


@dataclass
class NamespaceProof:
    """Captures namespace isolation evidence."""

    namespace: str
    selfDescriptor: str = ""
    initDescriptor: str = ""
    matchesInit: bool = False


@dataclass
class AdapterResponse:
    """Mirrors cadence-core RuntimeAdapterResponse."""

    exitCode: int = 0
    stdout: str = ""
    stderr: str = ""
    observedChecks: list[str] = field(default_factory=list)
    namespaceProofHash: str = ""
    namespaceProofs: list[dict[str, Any]] = field(default_factory=list)
    backendEvidence: dict[str, Any] = field(default_factory=dict)
    failureReasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "exitCode": self.exitCode,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "observedChecks": self.observedChecks,
            "namespaceProofHash": self.namespaceProofHash,
            "namespaceProofs": self.namespaceProofs,
            "backendEvidence": self.backendEvidence,
            "failureReasons": self.failureReasons,
        }


def hash_namespace_proofs(proofs: list[dict[str, Any]]) -> str:
    """Compute sha256 hash of namespace proofs for verification."""
    if not proofs:
        return ""
    payload = json.dumps(proofs, separators=(",", ":"), sort_keys=True).encode()
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def probe_namespace(name: str) -> NamespaceProof:
    """Probe a Linux namespace for isolation evidence."""
    proof = NamespaceProof(namespace=name)
    self_path = f"/proc/self/ns/{name}"
    init_path = f"/proc/1/ns/{name}"
    try:
        proof.selfDescriptor = os.readlink(self_path)
    except OSError:
        pass
    try:
        proof.initDescriptor = os.readlink(init_path)
    except OSError:
        pass
    if proof.selfDescriptor and proof.initDescriptor:
        proof.matchesInit = proof.selfDescriptor == proof.initDescriptor
    return proof


class RuntimeAdapter(ABC):
    """Base class for sandbox runtime adapters.

    Subclasses implement execute() to run commands under their specific
    isolation backend (container, microvm, etc.). The adapter protocol:

    1. Read RuntimeAdapterRequest JSON from stdin
    2. Validate isolation requirements
    3. Execute command under isolation
    4. Probe actual isolation evidence
    5. Return RuntimeAdapterResponse JSON on stdout
    """

    @abstractmethod
    def backend_type(self) -> str:
        """Return the backend identifier (e.g. 'container-runtime')."""

    @abstractmethod
    def execute(self, request: AdapterRequest) -> AdapterResponse:
        """Execute a command under this adapter's isolation backend."""

    def validate_request(self, request: AdapterRequest) -> list[str]:
        """Validate the adapter request. Returns list of failure reasons."""
        failures: list[str] = []
        if not request.command:
            failures.append("command is required")
        if request.backend != self.backend_type():
            failures.append(
                f"backend mismatch: expected {self.backend_type()}, got {request.backend}"
            )
        if request.networkAccess:
            failures.append(
                f"backend {self.backend_type()} requires networkAccess=false"
            )
        if not request.readOnlyInputs:
            failures.append(
                f"backend {self.backend_type()} requires readOnlyInputs=true"
            )
        if not request.writableOutputDir:
            failures.append(
                f"backend {self.backend_type()} requires writableOutputDir"
            )
        return failures

    def probe_isolation(self) -> tuple[list[str], list[dict[str, Any]]]:
        """Probe current isolation and return (observed_checks, namespace_proofs)."""
        checks: list[str] = []
        proofs: list[dict[str, Any]] = []

        for ns_name in ("pid", "mnt", "net"):
            proof = probe_namespace(ns_name)
            if proof.selfDescriptor or proof.initDescriptor:
                proof_dict = {
                    "namespace": proof.namespace,
                    "selfDescriptor": proof.selfDescriptor,
                    "initDescriptor": proof.initDescriptor,
                    "matchesInit": proof.matchesInit,
                }
                proofs.append(proof_dict)

        pid_proof = probe_namespace("pid")
        if pid_proof.selfDescriptor and pid_proof.initDescriptor and not pid_proof.matchesInit:
            checks.append("pid-namespace")

        mnt_proof = probe_namespace("mnt")
        if mnt_proof.selfDescriptor and mnt_proof.initDescriptor and not mnt_proof.matchesInit:
            checks.append("mount-namespace")

        net_proof = probe_namespace("net")
        if net_proof.selfDescriptor and net_proof.initDescriptor and not net_proof.matchesInit:
            checks.append("network-namespace")

        # seccomp detection
        try:
            with open("/proc/self/status") as f:
                for line in f:
                    if line.startswith("Seccomp:"):
                        val = line.split(":")[1].strip()
                        if val != "0":
                            checks.append("seccomp-active")
                        break
        except OSError:
            pass

        # cgroup detection
        if os.path.exists("/sys/fs/cgroup/cgroup.controllers"):
            checks.append("cgroup-fenced")
        elif os.path.exists("/sys/fs/cgroup"):
            checks.append("cgroup-fenced")

        if proofs:
            checks.append("namespace-proof-hash")

        checks.sort()
        return checks, proofs

    def run(self, stdin_data: bytes | None = None) -> None:
        """Main entry point: read request from stdin, execute, write response to stdout."""
        raw = stdin_data if stdin_data is not None else sys.stdin.buffer.read()
        try:
            request_data = json.loads(raw)
        except json.JSONDecodeError as exc:
            response = AdapterResponse(
                exitCode=1,
                failureReasons=[f"invalid JSON request: {exc}"],
            )
            sys.stdout.write(json.dumps(response.to_dict()))
            sys.stdout.flush()
            return

        request = AdapterRequest.from_dict(request_data)
        failures = self.validate_request(request)
        if failures:
            response = AdapterResponse(exitCode=1, failureReasons=failures)
            sys.stdout.write(json.dumps(response.to_dict()))
            sys.stdout.flush()
            return

        response = self.execute(request)
        sys.stdout.write(json.dumps(response.to_dict()))
        sys.stdout.flush()


def execute_subprocess(
    command: list[str],
    work_dir: str,
    env: dict[str, str],
    timeout_seconds: int = 0,
) -> tuple[int, str, str]:
    """Execute a subprocess with the given command, workdir, env, and timeout."""
    try:
        result = subprocess.run(
            command,
            cwd=work_dir or None,
            env=env or None,
            capture_output=True,
            text=True,
            timeout=timeout_seconds if timeout_seconds > 0 else None,
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "command timed out"
    except FileNotFoundError:
        return -1, "", f"command not found: {command[0] if command else '(empty)'}"
    except OSError as exc:
        return -1, "", str(exc)
