"""V9 remediation spec tests for cadence-policy-packs (Item 11: aligned to v1.4.x artifacts)."""
from __future__ import annotations

import unittest
from pathlib import Path
from tests._root_contract import repository_root_for_test_file


ROOT = repository_root_for_test_file(__file__)


class PolicyPacksRemediationSpecTests(unittest.TestCase):

    # --- Item 11: cadence-policy-packs has v1.4.0 families ---

    def test_packs_011_expected_families_exist(self) -> None:
        packs = ROOT / "packs"
        expected = ["core-v146-baseline", "headless-v146", "hfvi-v146", "standard-ui-v146"]
        for pack in expected:
            with self.subTest(pack=pack):
                self.assertTrue((packs / pack).is_dir(), f"missing pack family: {pack}")

    def test_packs_011_changelog_exists(self) -> None:
        self.assertTrue((ROOT / "CHANGELOG.md").exists())

    def test_packs_011_readme_exists(self) -> None:
        self.assertTrue((ROOT / "README.md").exists())

    def test_packs_011_verify_script_exists(self) -> None:
        self.assertTrue((ROOT / "scripts" / "verify").exists())

    def test_packs_011_no_legacy_baseline_in_files(self) -> None:
        marker = "unified-" + "current-baseline"
        for path in ROOT.rglob("*"):
            if "tests" in path.parts:
                continue
            if path.is_file() and path.suffix in {".md", ".yaml", ".yml", ".json", ".py", ".sh", ".txt"}:
                text = path.read_text(encoding="utf-8", errors="ignore")
                with self.subTest(file=str(path.relative_to(ROOT))):
                    self.assertNotIn(marker, text)

    # --- Additional Item 11 content-validation tests ---

    def test_packs_011_each_pack_has_policy_file(self) -> None:
        packs = ROOT / "packs"
        directories = [p for p in packs.iterdir() if p.is_dir()]
        self.assertTrue(directories, "no policy pack directories")
        for pack_dir in directories:
            if pack_dir.is_dir():
                with self.subTest(pack=pack_dir.name):
                    files = list(pack_dir.rglob("*.yaml")) + list(pack_dir.rglob("*.json"))
                    self.assertGreater(len(files), 0, f"Pack {pack_dir.name} has no policy files")

    def test_packs_011_no_v17_naming(self) -> None:
        packs = ROOT / "packs"
        directories = [p for p in packs.iterdir() if p.is_dir()]
        self.assertTrue(directories, "no policy pack directories")
        for pack_dir in directories:
            if pack_dir.is_dir():
                with self.subTest(pack=pack_dir.name):
                    self.assertNotIn("v17", pack_dir.name)


if __name__ == "__main__":
    unittest.main()
