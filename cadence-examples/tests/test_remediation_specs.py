"""V9 remediation spec tests for cadence-examples (Item 11: aligned to v1.4.x artifacts)."""
from __future__ import annotations

import json
import unittest
from pathlib import Path
from tests._root_contract import repository_root_for_test_file


ROOT = repository_root_for_test_file(__file__)


class ExamplesRemediationSpecTests(unittest.TestCase):

    # --- Item 11: cadence-examples aligned to v1.4.x ---

    def test_examples_011_tooling_lock_exists(self) -> None:
        self.assertTrue((ROOT / "tooling_lock.json").exists())

    def test_examples_011_local_extension_manifest_exists(self) -> None:
        self.assertTrue((ROOT / "local_extension_manifest.json").exists())

    def test_examples_011_suite_version_closure_exists(self) -> None:
        self.assertTrue((ROOT / "suite_version_closure.json").exists())

    def test_examples_011_verify_script_exists(self) -> None:
        self.assertTrue((ROOT / "scripts" / "verify").exists())

    def test_examples_011_no_legacy_baseline_in_files(self) -> None:
        marker = "unified-" + "current-baseline"
        for path in ROOT.rglob("*"):
            if "tests" in path.parts:
                continue
            if path.is_file() and path.suffix in {".md", ".yaml", ".yml", ".json", ".py", ".sh", ".txt"}:
                text = path.read_text(encoding="utf-8", errors="ignore")
                with self.subTest(file=str(path.relative_to(ROOT))):
                    self.assertNotIn(marker, text)

    def test_examples_011_json_files_valid(self) -> None:
        for f in ROOT.glob("*.json"):
            with self.subTest(file=f.name):
                data = json.loads(f.read_text(encoding="utf-8"))
                self.assertIsInstance(data, (dict, list))

    # --- Additional Item 11 content-validation tests ---

    def test_examples_011_tooling_lock_has_source_of_truth(self) -> None:
        import json
        data = json.loads((ROOT / "tooling_lock.json").read_text(encoding="utf-8"))
        self.assertIn("sourceOfTruth", data)

    def test_examples_011_closure_has_suite_version(self) -> None:
        import json
        data = json.loads((ROOT / "suite_version_closure.json").read_text(encoding="utf-8"))
        self.assertIn("suiteVersion", data)

    def test_local_closure_inputs_are_inside_the_public_repository(self) -> None:
        roots = [ROOT] + sorted(p for p in (ROOT / "examples").iterdir() if p.is_dir())
        for repo in roots:
            closure = json.loads((repo / "suite_version_closure.json").read_bytes())
            tooling = json.loads((repo / "tooling_lock.json").read_bytes())
            refs = [closure["suiteLockRef"], *closure["lockRefs"].values(),
                    *(tooling[key] for key in ("suiteLockRef", "suiteVersionClosureRef", "verifyRegistryRef"))]
            for ref in refs:
                with self.subTest(repo=repo.name, uri=ref["uri"]):
                    target = (repo / ref["uri"]).resolve()
                    self.assertTrue(target.is_relative_to(ROOT.parent.resolve()))
                    self.assertTrue(target.is_file())


if __name__ == "__main__":
    unittest.main()
