"""V9 remediation spec tests for cadence-protocol (Item 09: expanded schema families)."""
from __future__ import annotations

import json
import unittest
from pathlib import Path
from tests._root_contract import repository_root_for_test_file


ROOT = repository_root_for_test_file(__file__)


class ProtocolRemediationSpecTests(unittest.TestCase):

    # --- Item 09: cadence-protocol ships expanded L2 protocol family ---

    def test_proto_009_changelog_exists(self) -> None:
        self.assertTrue((ROOT / "CHANGELOG.md").exists())

    def test_proto_009_readme_exists(self) -> None:
        self.assertTrue((ROOT / "README.md").exists())

    def test_proto_009_migrations_doc_exists(self) -> None:
        self.assertTrue((ROOT / "MIGRATIONS.md").exists())

    def test_proto_009_compatibility_matrix_exists(self) -> None:
        self.assertTrue((ROOT / "docs" / "COMPATIBILITY_MATRIX.md").exists())

    def test_proto_009_verify_script_exists(self) -> None:
        self.assertTrue((ROOT / "scripts" / "verify").exists())

    def test_proto_009_verify_compat_script_exists(self) -> None:
        self.assertTrue((ROOT / "scripts" / "verify-compat").exists())

    def test_proto_009_migrate_tool_exists(self) -> None:
        self.assertTrue((ROOT / "tools" / "migrate.py").exists())

    def test_proto_009_compat_matrix_tool_exists(self) -> None:
        self.assertTrue((ROOT / "tools" / "compat_matrix.py").exists())

    def test_proto_009_fixture_families_exist(self) -> None:
        expected_families = [
            "replay_bundle",
            "replay_package",
            "evidence_bundle",
            "signature",
            "signature_envelope",
            "plugin_manifest",
            "plugin_registry_index",
            "registry_entry",
            "sandbox_profile",
            "sandbox_result",
            "runtime_profile",
            "waiver",
            "waiver_audit_trail",
            "hsm_anchor",
            "key_hierarchy",
        ]
        for family in expected_families:
            with self.subTest(family=family):
                self.assertTrue(
                    (ROOT / "fixtures" / family).is_dir(),
                    f"missing fixture family: {family}",
                )

    def test_proto_009_schemas_directory_has_files(self) -> None:
        schemas = ROOT / "schemas"
        self.assertTrue(schemas.is_dir(), "schemas/ directory missing")
        schema_files = list(schemas.glob("*.schema.json"))
        self.assertGreater(len(schema_files), 0, "No .schema.json files in schemas/")

    def test_proto_009_all_schema_files_are_valid_json(self) -> None:
        schemas = ROOT / "schemas"
        if not schemas.is_dir():
            self.fail("schemas/ directory missing")
        files = list(schemas.glob("*.schema.json"))
        self.assertTrue(files, "schemas are empty")
        for f in files:
            with self.subTest(schema=f.name):
                data = json.loads(f.read_text(encoding="utf-8"))
                self.assertIsInstance(data, dict)

    def test_proto_009_examples_directory_has_files(self) -> None:
        examples = ROOT / "examples"
        self.assertTrue(examples.is_dir(), "examples/ directory missing")
        example_files = list(examples.glob("*.example.json"))
        self.assertGreater(len(example_files), 0, "No .example.json files in examples/")

    def test_proto_009_all_example_files_are_valid_json(self) -> None:
        examples = ROOT / "examples"
        self.assertTrue(examples.is_dir(), "examples/ directory missing")
        files = list(examples.glob("*.example.json"))
        self.assertTrue(files, "examples are empty")
        for f in files:
            with self.subTest(example=f.name):
                data = json.loads(f.read_text(encoding="utf-8"))
                self.assertIsInstance(data, dict)

    def test_proto_009_no_placeholder_in_schemas(self) -> None:
        schemas = ROOT / "schemas"
        self.assertTrue(schemas.is_dir(), "schemas/ directory missing")
        files = list(schemas.glob("*.schema.json"))
        self.assertTrue(files, "schemas are empty")
        for f in files:
            text = f.read_text(encoding="utf-8")
            with self.subTest(schema=f.name):
                self.assertNotIn("TODO", text)
                self.assertNotIn("PLACEHOLDER", text)

    def test_proto_009_verify_script_is_shell(self) -> None:
        text = (ROOT / "scripts" / "verify").read_text(encoding="utf-8")
        self.assertTrue(text.startswith("#!/"))

    # --- Additional Item 09 content-validation tests ---

    def test_proto_009_each_fixture_family_has_valid_and_invalid(self) -> None:
        fixtures = ROOT / "fixtures"
        for family_dir in fixtures.iterdir():
            if family_dir.is_dir() and family_dir.name != "compat":
                with self.subTest(family=family_dir.name):
                    self.assertTrue(
                        (family_dir / "valid").is_dir(),
                        f"fixture family {family_dir.name} missing valid/ dir",
                    )
                    self.assertTrue(
                        (family_dir / "invalid").is_dir(),
                        f"fixture family {family_dir.name} missing invalid/ dir",
                    )

    def test_proto_009_migrate_tool_has_main(self) -> None:
        text = (ROOT / "tools" / "migrate.py").read_text(encoding="utf-8")
        self.assertTrue(
            "def main" in text or "if __name__" in text,
            "migrate.py has no main entry point",
        )

    def test_proto_009_compat_matrix_has_versions(self) -> None:
        text = (ROOT / "docs" / "COMPATIBILITY_MATRIX.md").read_text(encoding="utf-8")
        from tools.compat_matrix import collect_schemas, generate_matrix
        entries = collect_schemas(ROOT / "schemas")
        self.assertEqual(text, generate_matrix(entries))
        self.assertTrue(entries)
        for entry in entries:
            self.assertTrue(entry["path"].startswith("schemas/"))
            self.assertTrue((ROOT / entry["path"]).is_file())

    def test_proto_009_no_legacy_baseline_in_tree(self) -> None:
        marker = "unified-" + "current-baseline"
        for path in ROOT.rglob("*"):
            if "tests" in path.parts:
                continue
            if path.is_file() and path.suffix in {".md", ".json", ".py", ".yaml", ".yml", ".sh"}:
                text = path.read_text(encoding="utf-8", errors="ignore")
                with self.subTest(file=str(path.relative_to(ROOT))):
                    self.assertNotIn(marker, text)


if __name__ == "__main__":
    unittest.main()
