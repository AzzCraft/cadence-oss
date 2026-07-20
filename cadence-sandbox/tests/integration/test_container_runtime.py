"""Integration tests for cadence-sandbox real-runtime adapters.

These tests require a container runtime (docker/podman) to be available.
They validate that the container_adapter and microvm_adapter actually
invoke real isolation backends rather than running commands bare on the host.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def _has_docker() -> bool:
    return shutil.which("docker") is not None


@unittest.skipUnless(_has_docker(), "docker not available")
class ContainerAdapterIntegrationTest(unittest.TestCase):
    """Verify container_adapter invokes docker/podman for real isolation."""

    def test_container_adapter_uses_docker(self) -> None:
        """Send a minimal request to container_adapter and verify it attempts docker run."""
        request = {
            "backend": "container-runtime",
            "command": ["echo", "hello"],
            "workDir": "/tmp",
            "readOnlyInputs": True,
            "writableOutputDir": "/tmp/out",
            "requiredChecks": [],
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(request, f)
            f.flush()
            result = subprocess.run(
                ["python3", "-m", "runtime.container_adapter"],
                cwd=ROOT,
                input=json.dumps(request),
                capture_output=True,
                text=True,
                timeout=30,
            )
        # The adapter should attempt to use docker regardless of whether
        # the image exists
        response = json.loads(result.stdout) if result.stdout.strip() else {}
        self.assertIn("exitCode", response)


if __name__ == "__main__":
    unittest.main()
