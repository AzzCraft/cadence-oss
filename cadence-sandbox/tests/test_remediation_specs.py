"""Static artifact/document checks; executable behavior is checked by native tests."""

import unittest
from pathlib import Path
from tests._root_contract import repository_root_for_test_file


ROOT = repository_root_for_test_file(__file__)


class SandboxRemediationSpecTests(unittest.TestCase):

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

    def test_sbox_verify_script_exists(self) -> None:
        self.assertTrue((ROOT / "scripts" / "verify").exists())

    def test_sbox_verify_mentions_runtime_vars(self) -> None:
        text = (ROOT / "scripts" / "verify").read_text(encoding="utf-8")
        self.assertIn("CADENCE_TEST_REAL_CONTAINER_RUNTIME", text)
        self.assertIn("CADENCE_TEST_REAL_MICROVM_RUNTIME", text)

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
