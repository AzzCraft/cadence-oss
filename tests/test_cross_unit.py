"""Cross-unit integration tests for cadence-oss."""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from tests._root_contract import repository_root_for_test_file

OSS_ROOT = repository_root_for_test_file(__file__)


class TestSubunitCHANGELOGs(unittest.TestCase):
    """Verify all subunits have CHANGELOG.md."""

    SUBUNITS = [
        "cadence-protocol",
        "cadence-core",
        "cadence-plugins",
        "cadence-policy-packs",
        "cadence-sandbox",
        "cadence-registry",
        "cadence-examples",
        "contracts-hub-template",
    ]

    def test_changelogs_exist(self):
        for sub in self.SUBUNITS:
            path = OSS_ROOT / sub / "CHANGELOG.md"
            self.assertTrue(path.exists(), f"Missing: {sub}/CHANGELOG.md")


class TestProtocolSchemas(unittest.TestCase):
    """Verify protocol schemas are valid JSON."""

    def test_all_schemas_parse(self):
        schemas_dir = OSS_ROOT / "cadence-protocol" / "schemas"
        self.assertTrue(schemas_dir.is_dir(), "schemas dir missing")
        schemas = list(schemas_dir.glob("*.schema.json"))
        self.assertTrue(schemas, "schemas directory is empty")
        for schema in schemas:
            with self.subTest(schema=schema.name):
                data = json.loads(schema.read_text(encoding="utf-8"))
                self.assertIsInstance(data, dict)


class TestVersionConsistency(unittest.TestCase):
    """Verify root VERSION in CHANGELOG."""

    def test_version_trace(self):
        version = (OSS_ROOT / "VERSION").read_text().strip()
        changelog = (OSS_ROOT / "CHANGELOG.md").read_text()
        self.assertIn(version, changelog)


class TestVerifierDispatch(unittest.TestCase):
    def test_final_success_follows_required_tests_and_core_keeps_its_bound(self):
        """Exercise shipped shells; child recorders prove dispatch, not product behavior."""
        entries = (
            ("cadence-core/scripts/verify", ["--full"], "[cadence-core] OK"),
            ("cadence-plugins/scripts/verify", [], "[cadence-plugins] OK"),
            ("cadence-policy-packs/scripts/verify", [], "[cadence-policy-packs] OK"),
            ("verify_all.sh", [], "ALL OK"),
        )
        with tempfile.TemporaryDirectory(prefix="cadence-dispatch-") as temporary:
            workspace = Path(temporary)
            tools = workspace / "tools"; tools.mkdir()
            for subunit in TestSubunitCHANGELOGs.SUBUNITS:
                (workspace / subunit).mkdir()
            recorder = (
                f"#!{sys.executable}\n"
                "import json, os, sys\n"
                "from pathlib import Path\n"
                "with open(os.environ['TEST_DISPATCH_LOG'], 'a') as log:\n"
                " log.write(json.dumps([Path(sys.argv[0]).name, *sys.argv[1:]])+'\\n')\n"
                "raise SystemExit(int(os.environ['TEST_PYTEST_EXIT']) if 'pytest' in sys.argv else 0)\n"
            )
            for name in ("python3", "go", "bash"):
                tool = tools / name; tool.write_text(recorder); tool.chmod(0o755)
            # Only shell ordering is under test; validators/Go have their own consumers.
            for relative, args, success in entries:
                script = workspace / relative
                script.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(OSS_ROOT / relative, script)
            for relative, args, success in entries:
                for failure in (0, 37):
                    with self.subTest(script=relative, child_exit=failure):
                        log = workspace / "calls.jsonl"; log.write_text("")
                        env = {**os.environ, "PATH": str(tools) + os.pathsep + os.environ["PATH"],
                               "TMPDIR": temporary, "TEST_DISPATCH_LOG": str(log), "TEST_PYTEST_EXIT": str(failure)}
                        result = subprocess.run(["/bin/bash", str(workspace / relative), *args],
                                                env=env, capture_output=True, text=True, timeout=15)
                        self.assertEqual(result.returncode, failure, result.stdout + result.stderr)
                        self.assertEqual(success in result.stdout.splitlines(), failure == 0, result.stdout)
                        calls = [json.loads(line) for line in log.read_text().splitlines()]
                        self.assertEqual(sum("pytest" in call for call in calls), 1)
                        if relative.startswith("cadence-core/"):
                            self.assertEqual([c for c in calls if c[:2] == ["go", "test"]],
                                             [["go", "test", "./...", "-count=1", "-timeout=120s"]])
                        if relative == "verify_all.sh":
                            self.assertEqual([c for c in calls if c[0] == "bash"].count(["bash", "./scripts/verify-full"]), 1)
                            self.assertEqual([c for c in calls if "pytest" in c], [[
                                "python3", "-B", "-m", "pytest", "-q", "-p", "no:cacheprovider",
                                "tests/test_cross_unit.py", "tests/test_root_verify_modes.py",
                            ]])


if __name__ == "__main__":
    unittest.main()
