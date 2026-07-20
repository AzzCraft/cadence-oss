"""V9 remediation spec tests for cadence-plugins (Item 11: aligned to v1.4.x artifacts)."""
from __future__ import annotations

import unittest
from pathlib import Path
from tests._root_contract import repository_root_for_test_file


ROOT = repository_root_for_test_file(__file__)


class PluginsRemediationSpecTests(unittest.TestCase):

    # --- Item 11: cadence-plugins aligned to v1.4.x ---

    def test_plugins_011_changelog_exists(self) -> None:
        self.assertTrue((ROOT / "CHANGELOG.md").exists())

    def test_plugins_011_readme_exists(self) -> None:
        self.assertTrue((ROOT / "README.md").exists())

    def test_plugins_011_verify_script_exists(self) -> None:
        self.assertTrue((ROOT / "scripts" / "verify").exists())

    def test_plugins_011_no_legacy_baseline_in_files(self) -> None:
        marker = "unified-" + "current-baseline"
        for path in ROOT.rglob("*"):
            if "tests" in path.parts:
                continue
            if path.is_file() and path.suffix in {".md", ".yaml", ".yml", ".json", ".py", ".sh", ".txt"}:
                text = path.read_text(encoding="utf-8", errors="ignore")
                with self.subTest(file=str(path.relative_to(ROOT))):
                    self.assertNotIn(marker, text)

    def test_plugins_011_manifest_files_are_valid_json(self) -> None:
        import json
        for f in ROOT.rglob("*.json"):
            with self.subTest(file=str(f.relative_to(ROOT))):
                data = json.loads(f.read_text(encoding="utf-8"))
                self.assertIsInstance(data, (dict, list))

    # --- Additional Item 11 content-validation tests ---

    def test_plugins_011_no_placeholder_in_json(self) -> None:
        import json as _json
        for f in ROOT.rglob("*.json"):
            text = f.read_text(encoding="utf-8")
            with self.subTest(file=str(f.relative_to(ROOT))):
                self.assertNotIn("PLACEHOLDER", text)
                self.assertNotIn("TODO", text)


if __name__ == "__main__":
    unittest.main()
