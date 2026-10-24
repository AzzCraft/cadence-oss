"""V9 remediation spec tests for cadence-policy-packs (Item 11: aligned to v1.4.x artifacts)."""
from __future__ import annotations

import unittest
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from tests._root_contract import repository_root_for_test_file


ROOT = repository_root_for_test_file(__file__)


class PolicyPacksRemediationSpecTests(unittest.TestCase):

    def test_metadata_only_adapter_preserves_normal_pack_validation(self) -> None:
        import yaml
        with tempfile.TemporaryDirectory(prefix='cadence-policy-validation-') as temp:
            root = Path(temp)
            for name in ('packs', 'scripts'):
                shutil.copytree(ROOT / name, root / name)
            # Exercise the real shell entry without recursively copying this test.
            (root / 'tests').mkdir()
            (root / 'tests/test_control.py').write_text('def test_control(): pass\n')
            env = os.environ.copy()
            env.pop('PYTHONPATH', None)
            def verify():
                return subprocess.run(['bash', 'scripts/verify'], cwd=root, env=env,
                                      capture_output=True, text=True, timeout=30)
            control = verify()
            self.assertEqual(control.returncode, 0, control.stdout + control.stderr)
            adapter = root / 'packs/scaffold-v15/pack.yaml'
            original = adapter.read_bytes()
            value = yaml.safe_load(original)
            del value['runtimeCompatibility']
            adapter.write_text(yaml.safe_dump(value))
            missing = verify()
            self.assertNotEqual(missing.returncode, 0)
            self.assertIn('runtime compatibility is missing', missing.stdout + missing.stderr)
            value = yaml.safe_load(original)
            value['rules'] = [{'ruleId': 'unexpected'}]
            adapter.write_text(yaml.safe_dump(value))
            unexpected = verify()
            self.assertNotEqual(unexpected.returncode, 0)
            self.assertIn('must not declare rules', unexpected.stdout + unexpected.stderr)
            adapter.write_bytes(original)
            ordinary = root / 'packs/core-v146-baseline/pack.yaml'
            value = yaml.safe_load(ordinary.read_text())
            value['rules'] = []
            ordinary.write_text(yaml.safe_dump(value))
            empty = verify()
            self.assertNotEqual(empty.returncode, 0)
            self.assertIn('rules must be a non-empty list', empty.stdout + empty.stderr)

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
