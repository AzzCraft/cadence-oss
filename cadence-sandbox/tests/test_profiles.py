import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
PINNED_IMAGE = "registry.example/cadence-sandbox@sha256:" + "a" * 64
CONTAINER_LIMITS = {
    "cpuLimit": 2,
    "memoryLimitMB": 256,
    "pidsLimit": 64,
    "timeoutSeconds": 10,
}


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
            self.assertEqual(payload["allowedEnv"], ["PYTHONDONTWRITEBYTECODE"])
            self.assertIn(payload["timeSource"], {"injected", "epoch-frozen"})
            self.assertGreater(payload["resources"]["timeoutSeconds"], 0)
            self.assertIn("writableOutputDir", payload["filesystem"])

    def test_legacy_root_profiles_remain_parseable(self) -> None:
        sandbox_profile = json.loads((ROOT / "sandbox_profile.json").read_text())
        self.assertEqual(sandbox_profile["sandboxId"], "local_offline")
        self.assertEqual(sandbox_profile["backend"], "host-local")
        self.assertEqual(sandbox_profile["allowedEnv"], ["PYTHONDONTWRITEBYTECODE"])
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
            for audit_path in audit_files:
                observed = json.loads(audit_path.read_text())
                self.assertEqual(observed["schemaVersion"], "1.0.0")
                self.assertIn("profileId", observed)
                self.assertEqual(observed["summary"]["status"], "not_observed")
                self.assertEqual(observed["summary"]["executionAudit"], "not_run")
                self.assertTrue(all(f["status"] == "declared" for f in observed["findings"]))
            empty = outdir / "empty.json"
            empty.write_text("{}")
            result = subprocess.run([str(audit_hook), str(empty), str(outdir)], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)




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
        """The real adapter constructs controls and propagates engine failures."""
        from runtime.adapter import AdapterRequest
        from runtime.container_adapter import ContainerAdapter

        for code, stdout, stderr in ((0, "hello\n", ""), (125, "", "daemon failed")):
            with self.subTest(exit_code=code), tempfile.TemporaryDirectory() as work:
                req = AdapterRequest(
                    backend="container-runtime", command=["echo", "hello"],
                    workDir=work, readOnlyInputs=True, writableOutputDir="out",
                    imageRef=PINNED_IMAGE, resourceLimits=CONTAINER_LIMITS,
                )
                with (
                    mock.patch("runtime.container_adapter._detect_container_runtime", return_value="docker"),
                    mock.patch("runtime.container_adapter.execute_subprocess",
                               side_effect=[(code, stdout, stderr), (0, "Docker version 25.0.0", "")]) as run,
                ):
                    resp = ContainerAdapter().execute(req)
                self.assertEqual((resp.exitCode, resp.stdout, resp.stderr), (code, stdout, stderr))
                argv = run.call_args_list[0].args[0]
                self.assertEqual(argv[:3], ["docker", "run", "--rm"])
                for flag, value in (("--network", "none"), ("--user", "65532:65532"),
                                    ("--cap-drop", "ALL"), ("--security-opt", "no-new-privileges:true")):
                    self.assertEqual(argv[argv.index(flag) + 1], value)
                self.assertIn("--read-only", argv)
                self.assertEqual(argv[-3:], [PINNED_IMAGE, "echo", "hello"])
                mounts = [argv[i + 1] for i, v in enumerate(argv) if v == "--mount"]
                self.assertEqual(mounts, [f"type=bind,src={Path(work).resolve()},dst=/workspace,readonly",
                                         f"type=bind,src={Path(work).resolve() / 'out'},dst=/workspace/.cadence/out"])
                self.assertFalse(resp.observedChecks, "mocked engine is not attestation")

    def test_mount_validation_has_no_rejected_path_side_effects(self):
        from runtime.adapter import AdapterRequest
        from runtime.container_adapter import ContainerAdapter
        with tempfile.TemporaryDirectory() as work:
            root = Path(work) / "root"
            root.mkdir()
            outside = Path(work) / "outside"
            outside.mkdir()
            (root / "link").symlink_to(outside, target_is_directory=True)
            for output in (".", str(root), "../escaped", str(outside / "new"), "link/new"):
                with self.subTest(output=output):
                    req = AdapterRequest(backend="container-runtime", command=["echo"], workDir=str(root),
                                         readOnlyInputs=True, writableOutputDir=output)
                    with self.assertRaises(RuntimeError):
                        ContainerAdapter._resolve_mounts(req)
                    self.assertFalse((outside / "new").exists())
                    self.assertFalse((Path(work) / "escaped").exists())
            req.writableOutputDir = "out"
            self.assertEqual(ContainerAdapter._resolve_mounts(req), (root, root / "out"))

    def test_cid_file_is_absent_at_launch_and_literal_arguments_are_preserved(self):
        from runtime.adapter import AdapterRequest
        from runtime.container_adapter import ContainerAdapter
        with tempfile.TemporaryDirectory() as work:
            root = Path(work)
            req = AdapterRequest(backend="container-runtime", command=["echo", "hello", "--flag", "relative.txt", str(root / "input")],
                                 workDir=work, readOnlyInputs=True, writableOutputDir="out",
                                 imageRef=PINNED_IMAGE, resourceLimits=CONTAINER_LIMITS)
            seen = []
            def execute(argv, *args, **kwargs):
                if "--cidfile" not in argv:
                    return 0, "Docker version fixture", ""
                cid = Path(argv[argv.index("--cidfile") + 1])
                self.assertFalse(cid.exists())
                self.assertEqual(argv[-5:], ["echo", "hello", "--flag", "relative.txt", "/workspace/input"])
                cid.write_text("fixture-id")
                seen.append(cid)
                return 0, "hello", ""
            with mock.patch("runtime.container_adapter._detect_container_runtime", return_value="docker"), mock.patch("runtime.container_adapter.execute_subprocess", side_effect=execute):
                result = ContainerAdapter().execute(req)
            self.assertEqual(result.backendEvidence["containerId"], "fixture-id")
            self.assertFalse(seen[0].parent.exists())

    def test_container_adapter_rejects_unpinned_image_and_incomplete_limits(self) -> None:
        from runtime.adapter import AdapterRequest
        from runtime.container_adapter import ContainerAdapter

        failures = ContainerAdapter().validate_request(
            AdapterRequest(
                backend="container-runtime",
                command=["echo", "hello"],
                workDir="/tmp",
                readOnlyInputs=True,
                writableOutputDir="out",
                imageRef="cadence-sandbox:latest",
                resourceLimits={"timeoutSeconds": 10},
            )
        )
        self.assertTrue(any("digest-pinned" in failure for failure in failures))
        self.assertTrue(any("cpuLimit" in failure for failure in failures))

    def test_container_adapter_rejects_undeclared_environment_and_extra_mount(self) -> None:
        from runtime.adapter import AdapterRequest
        from runtime.container_adapter import ContainerAdapter

        failures = ContainerAdapter().validate_request(
            AdapterRequest(
                backend="container-runtime",
                command=["echo", "hello"],
                workDir="/tmp",
                readOnlyInputs=True,
                writableOutputDir="out",
                imageRef=PINNED_IMAGE,
                resourceLimits=CONTAINER_LIMITS,
                env={"SECRET": "not-allowed"},
                allowedMounts=["/host"],
            )
        )
        self.assertTrue(any("undeclared environment" in failure for failure in failures))
        self.assertTrue(any("arbitrary allowedMounts" in failure for failure in failures))

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

    def test_microvm_adapter_blocks_without_guest_execution_protocol(self) -> None:
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
        resp = adapter.execute(req)
        self.assertNotEqual(resp.exitCode, 0)
        self.assertEqual(resp.stdout, "")
        self.assertTrue(resp.failureReasons)
        self.assertEqual(resp.backendEvidence["adapterType"], "microvm")
        self.assertFalse(resp.backendEvidence["guestExecution"])
        self.assertFalse(resp.backendEvidence["guestReceiptVerified"])
        self.assertFalse(resp.backendEvidence["releaseEvidenceEligible"])
        self.assertEqual(resp.backendEvidence["attestationStatus"], "blocked-guest-receipt-required")
        self.assertIn("guestCommandSha256", resp.backendEvidence["requiredGuestReceiptFields"])
        self.assertEqual(resp.observedChecks, [])
        self.assertEqual(resp.namespaceProofs, [])

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
            "writableOutputDir": "out",
            "imageRef": PINNED_IMAGE,
            "resourceLimits": CONTAINER_LIMITS,
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


if __name__ == "__main__":
    unittest.main()
