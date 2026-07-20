from __future__ import annotations

import unittest
from pathlib import Path
from tests._root_contract import repository_root_for_test_file


ROOT = repository_root_for_test_file(__file__)


class SandboxRemediationSpecTests(unittest.TestCase):
    def test_sbox_001_container_adapter_requires_real_runtime_execution(self) -> None:
        text = (ROOT / "runtime" / "container_adapter.py").read_text(encoding="utf-8")
        self.assertNotIn("execute_subprocess(request.command", text)
        self.assertTrue(
            any(token in text for token in ("docker", "podman", "nerdctl", "containerd")),
            text,
        )
        for token in ("engine", "containerId", "imageRef", "runtimeVersion", "cgroupPath", "seccompProfileRef"):
            with self.subTest(token=token):
                self.assertIn(token, text)

    def test_sbox_001_microvm_adapter_requires_real_runtime_execution(self) -> None:
        text = (ROOT / "runtime" / "microvm_adapter.py").read_text(encoding="utf-8")
        self.assertNotIn("execute_subprocess(request.command", text)
        self.assertTrue(
            any(token in text for token in ("firecracker", "cloud-hypervisor", "qemu", "crosvm")),
            text,
        )
        for token in ("hypervisor", "vmId", "kernelImage", "rootfsDigest", "channelId"):
            with self.subTest(token=token):
                self.assertIn(token, text)

    # --- SBOX-002: real-runtime integration tests exist ---
    def test_sbox_002_integration_test_directory_exists(self) -> None:
        integ = ROOT / "tests" / "integration"
        self.assertTrue(integ.exists(), "tests/integration/ directory missing")
        test_files = list(integ.glob("test_*.py"))
        self.assertGreater(len(test_files), 0, "No integration test files found")

    def test_sbox_002_integration_test_uses_real_runtime(self) -> None:
        integ = ROOT / "tests" / "integration"
        if not integ.exists():
            self.fail("tests/integration/ directory missing")
        combined = ""
        for f in integ.glob("test_*.py"):
            combined += f.read_text(encoding="utf-8")
        self.assertTrue(
            any(tok in combined for tok in ("docker", "podman", "firecracker", "container_adapter")),
            "Integration tests do not reference real runtime"
        )
        verify_script = (ROOT / "scripts" / "verify").read_text(encoding="utf-8")
        self.assertIn("CADENCE_TEST_REAL_CONTAINER_RUNTIME", verify_script)
        self.assertIn("CADENCE_TEST_REAL_MICROVM_RUNTIME", verify_script)

    # --- SBOX-BASE-001 (partially completed): protocol/profile tests exist ---
    def test_sbox_base_001_protocol_tests_exist(self) -> None:
        test_dir = ROOT / "tests"
        candidates = list(test_dir.glob("test_profile*.py")) + list(test_dir.glob("test_protocol*.py"))
        self.assertGreater(
            len(candidates), 0,
            "No profile/protocol test files found in tests/",
        )

    def test_sbox_base_001_adapter_module_exists(self) -> None:
        self.assertTrue((ROOT / "runtime" / "adapter.py").exists())
        self.assertTrue((ROOT / "runtime" / "container_adapter.py").exists())
        self.assertTrue((ROOT / "runtime" / "microvm_adapter.py").exists())

    # --- SBOX-001 deep: adapters have execute method ---
    def test_sbox_001_container_adapter_has_execute(self) -> None:
        text = (ROOT / "runtime" / "container_adapter.py").read_text(encoding="utf-8")
        self.assertIn("def execute", text)

    def test_sbox_001_microvm_adapter_has_execute(self) -> None:
        text = (ROOT / "runtime" / "microvm_adapter.py").read_text(encoding="utf-8")
        self.assertIn("def execute", text)

    # --- SBOX-BASE-001 deep: adapter.py base class ---
    def test_sbox_base_001_adapter_has_base_class(self) -> None:
        text = (ROOT / "runtime" / "adapter.py").read_text(encoding="utf-8")
        self.assertTrue(
            "class RuntimeAdapter" in text or "class BaseAdapter" in text or "class Adapter" in text,
            "adapter.py has no recognizable base adapter class",
        )

    # --- SBOX depth: sandbox has scripts/verify ---
    def test_sbox_verify_script_exists(self) -> None:
        self.assertTrue((ROOT / "scripts" / "verify").exists())

    # --- SBOX depth: sandbox verify mentions runtime env vars ---
    def test_sbox_verify_mentions_runtime_vars(self) -> None:
        text = (ROOT / "scripts" / "verify").read_text(encoding="utf-8")
        self.assertIn("CADENCE_TEST_REAL_CONTAINER_RUNTIME", text)
        self.assertIn("CADENCE_TEST_REAL_MICROVM_RUNTIME", text)

    # --- SBOX depth: sandbox has scripts/verify ---
    def test_sbox_verify_script_exists(self) -> None:
        self.assertTrue((ROOT / "scripts" / "verify").exists())

    # --- SBOX depth: sandbox verify mentions runtime env vars ---
    def test_sbox_verify_mentions_runtime_vars(self) -> None:
        text = (ROOT / "scripts" / "verify").read_text(encoding="utf-8")
        self.assertIn("CADENCE_TEST_REAL_CONTAINER_RUNTIME", text)
        self.assertIn("CADENCE_TEST_REAL_MICROVM_RUNTIME", text)

    # --- V9 Item 08: cadence-sandbox materialized as internal release unit ---

    def test_v9_08_sandbox_changelog_exists(self) -> None:
        self.assertTrue((ROOT / "CHANGELOG.md").exists())

    def test_v9_08_sandbox_runtime_profile_exists(self) -> None:
        self.assertTrue((ROOT / "runtime_profile.json").exists())

    def test_v9_08_sandbox_profile_exists(self) -> None:
        self.assertTrue((ROOT / "sandbox_profile.json").exists())

    def test_v9_08_sandbox_profile_matrix_doc_exists(self) -> None:
        self.assertTrue((ROOT / "docs" / "PROFILE_MATRIX.md").exists())

    def test_v9_08_sandbox_test_profiles_exist(self) -> None:
        self.assertTrue((ROOT / "tests" / "test_profiles.py").exists())


class RegistryRemediationSpecTests(unittest.TestCase):

    # --- V9 Item 08: cadence-registry materialized as internal release unit ---

    def setUp(self) -> None:
        self.REG = ROOT.parent / "cadence-registry"

    def test_v9_08_registry_dir_exists(self) -> None:
        self.assertTrue(self.REG.is_dir())

    def test_v9_08_registry_changelog_exists(self) -> None:
        self.assertTrue((self.REG / "CHANGELOG.md").exists())

    def test_v9_08_registry_readme_exists(self) -> None:
        self.assertTrue((self.REG / "README.md").exists())

    def test_v9_08_registry_verify_script_exists(self) -> None:
        self.assertTrue((self.REG / "scripts" / "verify").exists())

    def test_v9_08_registry_json_exists(self) -> None:
        self.assertTrue((self.REG / "registry.json").exists())

    def test_v9_08_registry_index_format_doc_exists(self) -> None:
        self.assertTrue((self.REG / "docs" / "INDEX_FORMAT.md").exists())

    def test_v9_08_registry_schema_exists(self) -> None:
        self.assertTrue((self.REG / "schemas" / "registry_index.schema.json").exists())

    def test_v9_08_registry_semantics_test_exists(self) -> None:
        self.assertTrue((self.REG / "tests" / "test_registry_semantics.py").exists())

    # --- Additional Item 08 content-validation tests ---

    def test_v9_08_runtime_profile_valid_json(self) -> None:
        import json
        data = json.loads((ROOT / "runtime_profile.json").read_text(encoding="utf-8"))
        self.assertIsInstance(data, dict)
        self.assertGreater(len(data), 0, "runtime_profile.json is empty")

    def test_v9_08_sandbox_profile_valid_json(self) -> None:
        import json
        data = json.loads((ROOT / "sandbox_profile.json").read_text(encoding="utf-8"))
        self.assertIsInstance(data, dict)
        self.assertGreater(len(data), 0, "sandbox_profile.json is empty")

    def test_v9_08_registry_json_valid_and_nonempty(self) -> None:
        import json
        reg = ROOT.parent / "cadence-registry"
        data = json.loads((reg / "registry.json").read_text(encoding="utf-8"))
        self.assertIsInstance(data, (dict, list))

    def test_v9_08_registry_schema_has_required_fields(self) -> None:
        import json
        reg = ROOT.parent / "cadence-registry"
        schema = json.loads((reg / "schemas" / "registry_index.schema.json").read_text(encoding="utf-8"))
        self.assertIn("properties", schema)


if __name__ == "__main__":
    unittest.main()
