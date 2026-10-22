from __future__ import annotations

import json
import sys
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from tests._root_contract import repository_root_for_test_file


ROOT = repository_root_for_test_file(__file__)


class ContractsHubRemediationSpecTests(unittest.TestCase):
    def test_cht_001_release_template_locks_are_not_placeholders(self) -> None:
        for rel_path in ["cadence_lock.json", "suite_version_closure.json", "tooling_lock.json"]:
            text = (ROOT / rel_path).read_text(encoding="utf-8")
            self.assertNotIn("0.0.0", text, rel_path)
            self.assertNotIn("Template placeholder", text, rel_path)

        cadence_lock = json.loads((ROOT / "cadence_lock.json").read_text(encoding="utf-8"))
        version = cadence_lock["cadence_cli"]["version"]
        self.assertRegex(version, r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$")
        closure = json.loads((ROOT / "suite_version_closure.json").read_text(encoding="utf-8"))
        self.assertEqual(closure["componentVersions"]["cadence_cli"], version)
        tooling = json.loads((ROOT / "tooling_lock.json").read_text(encoding="utf-8"))
        self.assertEqual(
            tooling["pins"],
            {"suiteVersion": closure["suiteVersion"], "cadenceCliVersion": version},
        )

    def test_cht_001_placeholder_fixture_verify_fails_until_bootstrap_locks_exist(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            scratch = Path(tmp_dir) / "template"
            shutil.copytree(ROOT, scratch)
            (scratch / "cadence_lock.json").write_text(
                json.dumps(
                    {
                        "cadence_cli": {"version": "0.0.0"},
                        "note": "Template placeholder for negative fixture.",
                    },
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )
            (scratch / "suite_version_closure.json").write_text(
                json.dumps(
                    {
                        "schemaVersion": "1.0.0",
                        "suiteVersion": "1.0.0",
                        "standardVersion": "1.4.0",
                        "componentVersions": {},
                        "note": "Template placeholder for negative fixture.",
                    },
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )
            (scratch / "tooling_lock.json").write_text(
                json.dumps(
                    {
                        "schemaVersion": "1.0.0",
                        "pins": {},
                        "note": "Template placeholder for negative fixture.",
                    },
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )

            raw_verify = subprocess.run(
                ["bash", "scripts/verify"],
                cwd=scratch,
                env={**os.environ, "CADENCE_TEMPLATE_VERIFY_SKIP_TESTS": "1"},
                check=False,
                capture_output=True,
                text=True,
            )
            combined = raw_verify.stdout + raw_verify.stderr
            self.assertNotEqual(raw_verify.returncode, 0, combined)
            self.assertIn("bootstrap", combined.lower())

    def test_cht_001_release_template_verify_passes_without_bootstrap(self) -> None:
        proc = subprocess.run(
            ["bash", "scripts/verify"],
            cwd=ROOT,
            env={**os.environ, "CADENCE_TEMPLATE_VERIFY_SKIP_TESTS": "1"},
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)

    def test_cht_001_bootstrap_script_backfills_placeholder_locks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            scratch = Path(tmp_dir) / "template"
            shutil.copytree(ROOT, scratch)

            subprocess.check_call(
                [
                    "python3",
                    "tools/bootstrap_locks.py",
                    "--suite-version",
                    "1.0.0",
                    "--cadence-version",
                    "1.0.0",
                ],
                cwd=scratch,
            )

            lock = json.loads((scratch / "cadence_lock.json").read_text(encoding="utf-8"))
            self.assertNotEqual(lock["cadence_cli"]["version"], "0.0.0")
            closure = json.loads((scratch / "suite_version_closure.json").read_text(encoding="utf-8"))
            self.assertEqual(closure["suiteVersion"], "1.0.0")
            tooling = json.loads((scratch / "tooling_lock.json").read_text(encoding="utf-8"))
            self.assertEqual(
                tooling["pins"],
                {"suiteVersion": "1.0.0", "cadenceCliVersion": "1.0.0"},
            )

            fixed_verify = subprocess.run(
                ["bash", "scripts/verify"],
                cwd=scratch,
                env={**os.environ, "CADENCE_TEMPLATE_VERIFY_SKIP_TESTS": "1"},
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(fixed_verify.returncode, 0, fixed_verify.stdout + fixed_verify.stderr)

    def test_cht_011_contract_verify_ignores_ambient_validate_module(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            scratch = Path(tmp_dir) / "template"
            shutil.copytree(ROOT, scratch)
            ambient = Path(tmp_dir) / "ambient"
            ambient.mkdir()
            (ambient / "validate.py").write_text(
                "def unrelated():\n"
                "    return 'wrong module'\n",
                encoding="utf-8",
            )

            proc = subprocess.run(
                ["python3", "contracts/scripts/verify.py"],
                cwd=scratch,
                env={
                    **os.environ,
                    "PYTHONPATH": f"{ambient}{os.pathsep}{os.environ.get('PYTHONPATH', '')}",
                },
                check=False,
                capture_output=True,
                text=True,
            )

            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn("OK:", proc.stdout)

    # --- CHT-001 matrix exact: verify script mentions bootstrap ---
    def test_standalone_schema_and_runner_do_not_depend_on_layout(self):
        import sys
        with tempfile.TemporaryDirectory(prefix="hub review ") as temp:
            scratch=Path(temp)/"template";shutil.copytree(ROOT,scratch)
            runner=scratch/"contracts/scripts/compatibility_runner.py"
            fixture=next((scratch/"contracts/fixtures/payment/valid").glob("*.json"))
            original=fixture.read_bytes()
            def run(cwd, main=False):
                cmd=["bash",str(scratch/"scripts/verify")] if main else [sys.executable,"-B",str(runner)]
                return subprocess.run(cmd,cwd=cwd,env={**os.environ,"CADENCE_TEMPLATE_VERIFY_SKIP_TESTS":"1"},text=True,capture_output=True)
            for cwd in (scratch,runner.parent,Path(temp)):
                good=run(cwd);self.assertEqual(good.returncode,0,good.stdout+good.stderr)
            for neighbour in (False,True):
                if neighbour:
                    neighbour_dir=Path(temp)/"cadence-protocol/tools";neighbour_dir.mkdir(parents=True)
                    (neighbour_dir/"validate.py").write_text("raise RuntimeError('must not import neighbour')\n")
                for amount in (None,True,-1,"100"):
                    data=json.loads(original)
                    if amount is None:data.pop("amountCents")
                    else:data["amountCents"]=amount
                    fixture.write_text(json.dumps(data))
                    bad=run(scratch,main=True)
                    self.assertNotEqual(bad.returncode,0,bad.stdout+bad.stderr)
                    self.assertNotIn("must not import neighbour",bad.stderr)
                    self.assertNotEqual(run(Path(temp)).returncode,0)
                fixture.write_bytes(original)
                good=run(scratch,main=True);self.assertEqual(good.returncode,0,good.stdout+good.stderr)

    def test_job_manifest_run_id_must_match_even_with_same_hash(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / 'contracts'
            shutil.copytree(ROOT/'contracts', target)
            runner = target/'scripts/verify.py'
            positive = subprocess.run([sys.executable, str(runner)], text=True, capture_output=True)
            self.assertEqual(positive.returncode, 0, positive.stdout + positive.stderr)
            path = next((target/'fixtures/job_envelope/valid').glob('*.json'))
            value = json.loads(path.read_text())
            value['runs'][0]['manifestRef']['runId'] = 'TEST-different-run'
            path.write_text(json.dumps(value))
            negative = subprocess.run([sys.executable, str(runner)], text=True, capture_output=True)
            self.assertNotEqual(negative.returncode, 0)
            self.assertIn('manifest refs must match', negative.stderr)

    def test_cht_001_verify_script_mentions_bootstrap(self) -> None:
        text = (ROOT / "scripts" / "verify").read_text(encoding="utf-8")
        self.assertIn("bootstrap", text.lower())

    # --- CHT-001 deep: tools/bootstrap_locks.py exists ---
    def test_cht_001_bootstrap_tool_exists(self) -> None:
        self.assertTrue((ROOT / "tools" / "bootstrap_locks.py").exists())

    # --- Additional Item 11 content-validation tests ---

    def test_cht_011_fixture_tree_has_valid_invalid(self) -> None:
        fixtures = ROOT / "contracts" / "fixtures"
        self.assertTrue(fixtures.is_dir(), "contracts/fixtures/ must exist")
        families = [p for p in fixtures.iterdir() if p.is_dir()]
        self.assertTrue(families, "contracts/fixtures/ is empty")
        for contract_dir in families:
            if contract_dir.is_dir():
                with self.subTest(contract=contract_dir.name):
                    self.assertTrue((contract_dir / "valid").is_dir(),
                        f"{contract_dir.name} missing valid/ dir")
                    self.assertTrue((contract_dir / "invalid").is_dir(),
                        f"{contract_dir.name} missing invalid/ dir")

    def test_cht_011_required_contract_names_exist(self) -> None:
        fixtures = ROOT / "contracts" / "fixtures"
        required = {"payment", "run_manifest", "pipeline_result", "job_envelope"}
        actual = {d.name for d in fixtures.iterdir() if d.is_dir()}
        for name in required:
            with self.subTest(contract=name):
                self.assertIn(name, actual, f"Required contract fixture '{name}' missing")

    def test_cht_011_no_legacy_baseline(self) -> None:
        marker = "unified-" + "current-baseline"
        for path in ROOT.rglob("*"):
            if "tests" in path.parts:
                continue
            if path.is_file() and path.suffix in {".md", ".json", ".yaml", ".py", ".sh"}:
                text = path.read_text(encoding="utf-8", errors="ignore")
                with self.subTest(file=str(path.relative_to(ROOT))):
                    self.assertNotIn(marker, text)


if __name__ == "__main__":
    unittest.main()
