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


def test_bridges_are_locale_independent(tmp_path):
    import json
    import os
    import subprocess
    controls = []
    for locale in ('de_DE.UTF-8', 'sv_SE.UTF-8'):
        env = dict(os.environ, LANG=locale, LC_ALL=locale)
        run = subprocess.run(['node','-p', 'JSON.stringify({locale:Intl.Collator().resolvedOptions().locale, order:"ä".localeCompare("z")})'],env=env,text=True,capture_output=True,check=True)
        controls.append(json.loads(run.stdout))
    assert controls[0]['locale'].startswith('de') and controls[1]['locale'].startswith('sv')
    assert controls[0]['order'] < 0 < controls[1]['order']
    for bridge, text in [('eslint', "console.log('synthetic');\n"), ('prettier', 'const x = 1;\t\n')]:
        names = ['a.js', 'z.js', 'ä.js', 'å.js', '中.js', '😀.js']
        for name in names:
            (tmp_path / name).write_text(text)
        request = dict(schemaVersion='1.0.0', protocolVersion='1.0.0', repoRoot=str(tmp_path), files=names, mode='verify')
        outputs = []
        for locale in ('de_DE.UTF-8', 'sv_SE.UTF-8'):
            env = dict(os.environ, LANG=locale, LC_ALL=locale)
            run = subprocess.run(['node', str(ROOT / 'bridge' / bridge / 'index.mjs')], input=json.dumps(request), text=True, capture_output=True, env=env, check=True)
            payload = json.loads(run.stdout)
            assert len(payload['violations']) == len(names) * (2 if bridge == 'prettier' else 1)
            assert payload['metrics']['filesScanned'] == len(names)
            assert {item['file'] for item in payload['violations']} == set(names)
            outputs.append(run.stdout)
        assert outputs[0] == outputs[1]


def test_python_import_syntax_does_not_skip_second_statement():
    import importlib.util
    spec = importlib.util.spec_from_file_location('python_import_review', ROOT/'plugins/python/cadence_plugin_python/plugin.py')
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    assert len(module.scan_imports('import os; import foo.internal as bad\n')) == 1
    assert len(module.scan_imports('from foo.internal import (\n value,\n)\n')) == 1
    assert module.scan_imports('# import foo.internal\ntext = "import foo.internal"\n') == []


def test_delivered_ts_plugin_covers_import_forms(tmp_path):
    import json
    import subprocess
    text = "import 'pkg/internal/side';\nimport {\n x\n} /* comment */ from 'pkg/src/multi';\nexport { x } from 'pkg/internal/export';\n// import 'pkg/internal/comment';\nconst text = \"import 'pkg/internal/string'\";\n"
    text += "import { from as local } from 'pkg/internal/named';\nexport { from } from 'pkg/src/named-export';\n"
    (tmp_path/'source.ts').write_text(text)
    request = dict(schemaVersion='1.0.0', protocolVersion='1.0.0', repoRoot=str(tmp_path), files=['source.ts'], mode='verify')
    result = subprocess.run(['node',str(ROOT/'plugins/ts/index.mjs')],input=json.dumps(request),text=True,capture_output=True,check=True)
    response = json.loads(result.stdout)
    assert len(response['violations']) == 5
    assert {finding['line'] for finding in response['violations']} == {1, 4, 5, 8, 9}
    assert response['metrics']['filesScanned'] == 1


def test_delivered_ts_plugin_bounds_declarations_and_decodes_literals(tmp_path):
    import json
    import subprocess
    cases = [
        ("const first = 1, second = 2\nexport { first }\nexport { second }\nimport value from 'pkg/internal/value'\n", 1),
        (r"import value from 'pkg\u002finternal\u002fvalue';", 1),
        (r"export { value } from 'pkg\x2fsrc\x2fvalue';", 1),
        (r"import('pkg\u{2f}internal\/value');", 1),
        ("import 'pkg/inte\\\nrnal/value';", 1),
        (r"import value from 'pkg\\u002finternal/value';", 0),
        ("const text = \"import value from 'pkg/internal/example'\";\n// import 'pkg/src/comment';", 0),
    ]
    request = dict(schemaVersion='1.0.0', protocolVersion='1.0.0', repoRoot=str(tmp_path), files=['input.ts'], mode='verify')
    for source, expected in cases:
        (tmp_path/'input.ts').write_text(source)
        result = subprocess.run(['node', str(ROOT/'plugins/ts/index.mjs')], input=json.dumps(request), text=True, capture_output=True, check=True)
        violations = json.loads(result.stdout)['violations']
        assert len(violations) == expected, (source, violations)
        if expected:
            assert violations[0]['message'].endswith(('pkg/internal/value', 'pkg/src/value'))


def test_delivered_ts_plugin_template_and_regexp_contexts(tmp_path):
    import json
    import subprocess
    cases = json.loads((ROOT.parent/'cadence-core/internal/checks/testdata/js_import_contexts.json').read_text())
    request = dict(schemaVersion='1.0.0', protocolVersion='1.0.0', repoRoot=str(tmp_path), files=['input.js'], mode='scan')
    for case in cases:
        syntax = subprocess.run(['node', '--input-type=module', '--check'], input=case['source'], text=True, capture_output=True)
        assert syntax.returncode == 0, (case['name'], syntax.stderr)
        (tmp_path/'input.js').write_text(case['source'])
        run = subprocess.run(['node', str(ROOT/'plugins/ts/index.mjs')], input=json.dumps(request), text=True, capture_output=True, check=True)
        findings = json.loads(run.stdout)['violations']
        assert [f['line'] for f in findings] == case['lines'], (case['name'], findings)
        assert all(f['ruleId'] == 'SDMM_DEEP_IMPORT' for f in findings)
