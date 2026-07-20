import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from tests._root_contract import repository_root_for_test_file
from unittest import mock


ROOT = repository_root_for_test_file(__file__)
sys.path.insert(0, str(ROOT))


class SandboxProfileTests(unittest.TestCase):
    def test_declared_profiles_have_unique_ids_and_supported_semantics(self) -> None:
        profile_ids = set()
        for path in sorted((ROOT / "profiles").glob("*.json")):
            payload = json.loads(path.read_text())
            profile_id = payload["profileId"]
            self.assertNotIn(profile_id, profile_ids)
            profile_ids.add(profile_id)
            self.assertIn(
                payload["backend"],
                {"host-local", "container-runtime", "microvm-runtime"},
            )

            self.assertIn(
                payload["filesystem"]["mode"],
                {"workspace-only", "container-isolated", "microvm-isolated"},
            )
            self.assertFalse(payload["network"]["access"])
            self.assertIn(payload["timeSource"], {"injected", "epoch-frozen"})
            self.assertGreater(payload["resources"]["timeoutSeconds"], 0)
            self.assertIn("writableOutputDir", payload["filesystem"])

    def test_legacy_root_profiles_remain_parseable(self) -> None:
        sandbox_profile = json.loads((ROOT / "sandbox_profile.json").read_text())
        self.assertEqual(sandbox_profile["sandboxId"], "local_offline")
        self.assertEqual(sandbox_profile["backend"], "host-local")
        self.assertEqual(sandbox_profile["filesystem"], "workspace-only")
        self.assertFalse(sandbox_profile["networkAccess"])

        runtime_profile = json.loads((ROOT / "runtime_profile.json").read_text())
        self.assertEqual(runtime_profile["runtimeId"], "strict_offline")
        self.assertFalse(runtime_profile["networkAccess"])
        self.assertTrue(runtime_profile["deterministicClock"])

    def test_audit_hook_smokes_current_profile_family(self) -> None:
        audit_hook = ROOT / "scripts" / "audit-hook"
        profile_files = sorted((ROOT / "profiles").glob("*.json")) + [ROOT / "sandbox_profile.json"]

        with tempfile.TemporaryDirectory() as tmpdir:
            outdir = Path(tmpdir)
            for profile in profile_files:
                subprocess.run(
                    [str(audit_hook), str(profile), str(outdir)],
                    check=True,
                    cwd=ROOT,
                    capture_output=True,
                    text=True,
                )

            audit_files = list(outdir.glob("audit-*.json"))
            self.assertGreaterEqual(len(audit_files), len(profile_files))
            latest = json.loads(sorted(audit_files)[-1].read_text())
            self.assertEqual(latest["schemaVersion"], "1.0.0")
            self.assertIn("profileId", latest)
            self.assertEqual(latest["summary"]["status"], "pass")


if __name__ == "__main__":
    unittest.main()


class RuntimeAdapterProtocolTests(unittest.TestCase):
    """Tests for the runtime adapter base protocol."""

    def test_adapter_request_from_dict_parses_minimal(self) -> None:
        from runtime.adapter import AdapterRequest

        data = {
            "backend": "container-runtime",
            "command": ["echo", "hello"],
            "workDir": "/workspace",
        }
        req = AdapterRequest.from_dict(data)
        self.assertEqual(req.backend, "container-runtime")
        self.assertEqual(req.command, ["echo", "hello"])
        self.assertEqual(req.workDir, "/workspace")
        self.assertFalse(req.networkAccess)
        self.assertFalse(req.readOnlyInputs)
        self.assertEqual(req.env, {})

    def test_adapter_request_from_dict_parses_full(self) -> None:
        from runtime.adapter import AdapterRequest

        data = {
            "backend": "microvm-runtime",
            "command": ["python3", "run.py"],
            "workDir": "/workspace",
            "env": {"KEY": "VALUE"},
            "filesystem": "microvm-isolated",
            "networkAccess": False,
            "readOnlyInputs": True,
            "writableOutputDir": "/workspace/.cadence/out",
            "allowedMounts": ["/data"],
            "resourceLimits": {"timeoutSeconds": 300},
            "requiredChecks": ["pid-namespace", "mount-namespace"],
        }
        req = AdapterRequest.from_dict(data)
        self.assertEqual(req.backend, "microvm-runtime")
        self.assertTrue(req.readOnlyInputs)
        self.assertEqual(req.writableOutputDir, "/workspace/.cadence/out")
        self.assertEqual(req.resourceLimits, {"timeoutSeconds": 300})
        self.assertIn("pid-namespace", req.requiredChecks)

    def test_adapter_response_to_dict_roundtrip(self) -> None:
        from runtime.adapter import AdapterResponse

        resp = AdapterResponse(
            exitCode=0,
            stdout="ok",
            stderr="",
            observedChecks=["pid-namespace"],
            namespaceProofHash="sha256:abc",
            backendEvidence={"cgroupVersion": "v2"},
        )
        d = resp.to_dict()
        self.assertEqual(d["exitCode"], 0)
        self.assertEqual(d["stdout"], "ok")
        self.assertIn("pid-namespace", d["observedChecks"])
        self.assertEqual(d["namespaceProofHash"], "sha256:abc")

    def test_hash_namespace_proofs_empty(self) -> None:
        from runtime.adapter import hash_namespace_proofs

        self.assertEqual(hash_namespace_proofs([]), "")

    def test_hash_namespace_proofs_deterministic(self) -> None:
        from runtime.adapter import hash_namespace_proofs

        proofs = [{"namespace": "pid", "selfDescriptor": "pid:[123]", "initDescriptor": "pid:[1]", "matchesInit": False}]
        h1 = hash_namespace_proofs(proofs)
        h2 = hash_namespace_proofs(proofs)
        self.assertEqual(h1, h2)
        self.assertTrue(h1.startswith("sha256:"))
        self.assertEqual(len(h1), 7 + 64)


class ContainerAdapterTests(unittest.TestCase):
    """Tests for the container runtime adapter."""

    def test_container_adapter_backend_type(self) -> None:
        from runtime.container_adapter import ContainerAdapter

        adapter = ContainerAdapter()
        self.assertEqual(adapter.backend_type(), "container-runtime")

    def test_container_adapter_validates_backend_mismatch(self) -> None:
        from runtime.adapter import AdapterRequest
        from runtime.container_adapter import ContainerAdapter

        adapter = ContainerAdapter()
        req = AdapterRequest(
            backend="microvm-runtime",
            command=["echo"],
            workDir="/tmp",
            readOnlyInputs=True,
            writableOutputDir="/tmp/out",
        )
        failures = adapter.validate_request(req)
        self.assertTrue(any("backend mismatch" in f for f in failures))

    def test_container_adapter_validates_network_required_off(self) -> None:
        from runtime.adapter import AdapterRequest
        from runtime.container_adapter import ContainerAdapter

        adapter = ContainerAdapter()
        req = AdapterRequest(
            backend="container-runtime",
            command=["echo"],
            workDir="/tmp",
            networkAccess=True,
            readOnlyInputs=True,
            writableOutputDir="/tmp/out",
        )
        failures = adapter.validate_request(req)
        self.assertTrue(any("networkAccess=false" in f for f in failures))

    def test_container_adapter_validates_readonly_inputs(self) -> None:
        from runtime.adapter import AdapterRequest
        from runtime.container_adapter import ContainerAdapter

        adapter = ContainerAdapter()
        req = AdapterRequest(
            backend="container-runtime",
            command=["echo"],
            workDir="/tmp",
            readOnlyInputs=False,
            writableOutputDir="/tmp/out",
        )
        failures = adapter.validate_request(req)
        self.assertTrue(any("readOnlyInputs=true" in f for f in failures))

    def test_container_adapter_validates_writable_output_dir(self) -> None:
        from runtime.adapter import AdapterRequest
        from runtime.container_adapter import ContainerAdapter

        adapter = ContainerAdapter()
        req = AdapterRequest(
            backend="container-runtime",
            command=["echo"],
            workDir="/tmp",
            readOnlyInputs=True,
            writableOutputDir="",
        )
        failures = adapter.validate_request(req)
        self.assertTrue(any("writableOutputDir" in f for f in failures))

    def test_container_adapter_execute_succeeds(self) -> None:
        from runtime.adapter import AdapterRequest
        from runtime.container_adapter import ContainerAdapter

        adapter = ContainerAdapter()
        req = AdapterRequest(
            backend="container-runtime",
            command=["echo", "hello"],
            workDir="/tmp",
            readOnlyInputs=True,
            writableOutputDir="/tmp/out",
            resourceLimits={"timeoutSeconds": 10},
        )
        with (
            mock.patch("runtime.container_adapter._detect_container_runtime", return_value="docker"),
            mock.patch(
                "runtime.container_adapter.execute_subprocess",
                side_effect=[(0, "hello\n", ""), (0, "Docker version 25.0.0\n", "")],
            ) as run,
        ):
            resp = adapter.execute(req)
        self.assertEqual(resp.exitCode, 0)
        self.assertIn("hello", resp.stdout)
        self.assertIsInstance(resp.observedChecks, list)
        self.assertIsInstance(resp.backendEvidence, dict)
        self.assertEqual(resp.backendEvidence["adapterType"], "container")
        self.assertEqual(resp.backendEvidence["engine"], "docker")
        self.assertEqual(resp.backendEvidence["imageRef"], "cadence-sandbox:latest")
        self.assertIn("containerId", resp.backendEvidence)
        self.assertIn("--network", run.call_args_list[0].args[0])

    def test_container_adapter_fails_closed_on_missing_command(self) -> None:
        from runtime.adapter import AdapterRequest
        from runtime.container_adapter import ContainerAdapter

        adapter = ContainerAdapter()
        req = AdapterRequest(
            backend="container-runtime",
            command=[],
            workDir="/tmp",
            readOnlyInputs=True,
            writableOutputDir="/tmp/out",
        )
        failures = adapter.validate_request(req)
        self.assertTrue(any("command is required" in f for f in failures))


class MicrovmAdapterTests(unittest.TestCase):
    """Tests for the microvm runtime adapter."""

    def test_microvm_adapter_backend_type(self) -> None:
        from runtime.microvm_adapter import MicrovmAdapter

        adapter = MicrovmAdapter()
        self.assertEqual(adapter.backend_type(), "microvm-runtime")

    def test_microvm_adapter_validates_backend_mismatch(self) -> None:
        from runtime.adapter import AdapterRequest
        from runtime.microvm_adapter import MicrovmAdapter

        adapter = MicrovmAdapter()
        req = AdapterRequest(
            backend="container-runtime",
            command=["echo"],
            workDir="/tmp",
            readOnlyInputs=True,
            writableOutputDir="/tmp/out",
        )
        failures = adapter.validate_request(req)
        self.assertTrue(any("backend mismatch" in f for f in failures))

    def test_microvm_adapter_execute_succeeds(self) -> None:
        from runtime.adapter import AdapterRequest
        from runtime.microvm_adapter import MicrovmAdapter

        adapter = MicrovmAdapter()
        req = AdapterRequest(
            backend="microvm-runtime",
            command=["echo", "microvm-test"],
            workDir="/tmp",
            readOnlyInputs=True,
            writableOutputDir="/tmp/out",
            resourceLimits={"timeoutSeconds": 10},
        )
        with (
            mock.patch("runtime.microvm_adapter._detect_microvm_runtime", return_value="qemu-system-x86_64"),
            mock.patch(
                "runtime.microvm_adapter.execute_subprocess",
                side_effect=[(0, "microvm-test\n", ""), (0, "QEMU emulator version 8.0.0\n", "")],
            ),
        ):
            resp = adapter.execute(req)
        self.assertEqual(resp.exitCode, 0)
        self.assertIn("microvm-test", resp.stdout)
        self.assertEqual(resp.backendEvidence["adapterType"], "microvm")
        self.assertEqual(resp.backendEvidence["hypervisor"], "qemu-system-x86_64")
        self.assertIn("vmId", resp.backendEvidence)
        self.assertIn("rootfsDigest", resp.backendEvidence)

    def test_microvm_adapter_fails_closed_on_network_access(self) -> None:
        from runtime.adapter import AdapterRequest
        from runtime.microvm_adapter import MicrovmAdapter

        adapter = MicrovmAdapter()
        req = AdapterRequest(
            backend="microvm-runtime",
            command=["echo"],
            workDir="/tmp",
            networkAccess=True,
            readOnlyInputs=True,
            writableOutputDir="/tmp/out",
        )
        failures = adapter.validate_request(req)
        self.assertTrue(any("networkAccess=false" in f for f in failures))


class AdapterProtocolIntegrationTests(unittest.TestCase):
    """Integration tests for adapter stdin/stdout JSON protocol."""

    def test_container_adapter_json_protocol(self) -> None:
        from runtime.container_adapter import ContainerAdapter

        adapter = ContainerAdapter()
        request_data = json.dumps({
            "backend": "container-runtime",
            "command": ["echo", "protocol-test"],
            "workDir": "/tmp",
            "readOnlyInputs": True,
            "writableOutputDir": "/tmp/out",
            "resourceLimits": {"timeoutSeconds": 10},
            "requiredChecks": [],
        }).encode()

        import io
        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            with (
                mock.patch("runtime.container_adapter._detect_container_runtime", return_value="docker"),
                mock.patch(
                    "runtime.container_adapter.execute_subprocess",
                    side_effect=[(0, "protocol-test\n", ""), (0, "Docker version 25.0.0\n", "")],
                ),
            ):
                adapter.run(stdin_data=request_data)
            output = sys.stdout.getvalue()
        finally:
            sys.stdout = old_stdout

        response = json.loads(output)
        self.assertEqual(response["exitCode"], 0)
        self.assertIn("protocol-test", response["stdout"])
        self.assertIsInstance(response["observedChecks"], list)

    def test_adapter_rejects_invalid_json(self) -> None:
        from runtime.container_adapter import ContainerAdapter

        adapter = ContainerAdapter()
        import io
        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            adapter.run(stdin_data=b"not-json")
            output = sys.stdout.getvalue()
        finally:
            sys.stdout = old_stdout

        response = json.loads(output)
        self.assertEqual(response["exitCode"], 1)
        self.assertTrue(any("invalid JSON" in r for r in response["failureReasons"]))

    def test_adapter_rejects_wrong_backend(self) -> None:
        from runtime.container_adapter import ContainerAdapter

        adapter = ContainerAdapter()
        request_data = json.dumps({
            "backend": "microvm-runtime",
            "command": ["echo"],
            "workDir": "/tmp",
            "readOnlyInputs": True,
            "writableOutputDir": "/tmp/out",
        }).encode()

        import io
        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            adapter.run(stdin_data=request_data)
            output = sys.stdout.getvalue()
        finally:
            sys.stdout = old_stdout

        response = json.loads(output)
        self.assertEqual(response["exitCode"], 1)
        self.assertTrue(any("backend mismatch" in r for r in response["failureReasons"]))
