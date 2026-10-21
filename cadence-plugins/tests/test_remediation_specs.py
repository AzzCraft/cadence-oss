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


def test_all_plugin_entrypoints_obey_wire_contract(tmp_path):
    import json
    import subprocess
    import sys
    from jsonschema import Draft202012Validator
    request_validator = Draft202012Validator(json.loads((ROOT.parent / "cadence-protocol/schemas/plugin_request.schema.json").read_text()))
    response_validator = Draft202012Validator(json.loads((ROOT.parent / "cadence-protocol/schemas/plugin_response.schema.json").read_text()))
    entries = [([sys.executable, str(ROOT / "plugins/python/plugin.py")], "from foo.internal import bar\n", "x = 1\n"),
               (["node", str(ROOT / "plugins/ts/index.mjs")], "import x from 'pkg/internal/x';\n", "const x = 1;\n"),
               ([sys.executable, str(ROOT / "bridge/ruff/plugin.py")], "print('example')\n", "x = 1\n"),
               (["node", str(ROOT / "bridge/eslint/index.mjs")], "console.log('example')\n", "const x = 1;\n"),
               (["node", str(ROOT / "bridge/prettier/index.mjs")], "const x = 1;\t", "const x = 1;\n")]
    for command, dirty, clean in entries:
        request = {"schemaVersion": "1.0.0", "protocolVersion": "1.0.0", "repoRoot": str(tmp_path), "files": ["input.txt"], "mode": "verify"}
        for text, findings in [(dirty, True), (clean, False)]:
            (tmp_path / "input.txt").write_text(text)
            request_validator.validate(request)
            result = subprocess.run(command, input=json.dumps(request), text=True, capture_output=True, cwd=tmp_path)
            assert result.returncode == 0, (command, result.stderr)
            response = json.loads(result.stdout)
            response_validator.validate(response)
            assert bool(response["violations"]) == findings
            assert response["metrics"]["filesScanned"] == 1
        empty = dict(request, files=[])
        result = subprocess.run(command, input=json.dumps(empty), text=True, capture_output=True, cwd=tmp_path)
        assert result.returncode == 0
        assert json.loads(result.stdout)["metrics"]["filesScanned"] == 0
        for payload in ["{broken", "[]", json.dumps(dict(request, files=[42])), json.dumps(dict(request, files=["missing"])), json.dumps(dict(request, mode="unsupported")), json.dumps(dict(request, protocolVersion="unknown"))]:
            result = subprocess.run(command, input=payload, text=True, capture_output=True, cwd=tmp_path)
            assert result.returncode != 0 and not result.stdout.strip(), (command, payload, result)
