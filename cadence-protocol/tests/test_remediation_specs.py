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


def test_legacy_conversion_and_current_schema_agree():
    import importlib.util
    from copy import deepcopy
    import sys
    import pytest
    sys.path.insert(0, str(ROOT/'tools'))
    spec = importlib.util.spec_from_file_location('migration_review', ROOT/'tools/migrate.py')
    migrate = importlib.util.module_from_spec(spec); spec.loader.exec_module(migrate)
    spec = importlib.util.spec_from_file_location('validator_review', ROOT/'tools/validate.py')
    validate = importlib.util.module_from_spec(spec); spec.loader.exec_module(validate)
    source = json.loads((ROOT/'fixtures/compat/legacy_pipeline_result_v0.json').read_text())
    migrated = migrate.migrate_legacy_pipeline_result(source)
    assert migrated['schemaVersion'] == '1.0.0' and source['schemaVersion'] == '0.9.0'
    migrated.pop('output', None)  # Canonical Schema declares output optional.
    validate.validate_pipeline_result(migrated)
    for field, value in [('schemaVersion','9.0.0'), ('status','unknown')]:
        bad = deepcopy(migrated); bad[field] = value
        with pytest.raises(ValueError): validate.validate_pipeline_result(bad)
    source['schemaVersion'] = '9.0.0'
    with pytest.raises(ValueError, match='unsupported'): migrate.migrate_legacy_pipeline_result(source)
    job = json.loads((ROOT/'fixtures/compat/legacy_job_envelope_v0.json').read_text())
    incomplete = migrate.migrate_legacy_job_envelope(job)
    with pytest.raises(ValueError): validate.validate_job_envelope(incomplete)
    job.update(createdAt='2026-04-08T09:00:00Z', updatedAt='2026-04-08T09:00:00Z', profileId='TEST', sideEffectsMode='dryRun')
    job['runs'][0].update(startedAt='2026-04-08T09:00:00Z', finishedAt='2026-04-08T09:00:00Z')
    validate.validate_job_envelope(migrate.migrate_legacy_job_envelope(job))


def test_schema_rejections_keep_public_value_error_contract():
    import pytest
    from jsonschema.exceptions import ValidationError
    from tools.validate import validate_run_manifest

    valid = json.loads((ROOT/'fixtures/run_manifest/valid/basic.json').read_text())
    validate_run_manifest(valid)
    invalid = json.loads((ROOT/'fixtures/run_manifest/invalid/missing_runId.json').read_text())
    with pytest.raises(ValueError, match='runId') as raised:
        validate_run_manifest(invalid)
    assert isinstance(raised.value.__cause__, ValidationError)


def test_nested_pipeline_results_use_complete_validator_and_cli(tmp_path):
    from copy import deepcopy
    import subprocess
    import sys
    import pytest
    from tools.validate import validate_job_envelope, validate_pipeline_result

    job = json.loads((ROOT/'fixtures/job_envelope/valid/basic.json').read_text())
    job['runs'].append(deepcopy(job['runs'][0]))
    for filename, fixture in [('run-manifest.json', 'run_manifest'), ('pipeline-result.json', 'pipeline_result')]:
        (tmp_path/filename).write_bytes((ROOT/'fixtures'/fixture/'valid/basic.json').read_bytes())
    for defect in ['valid', 'no-output', 'error', 'cancelled', 'version', 'runId', 'hash']:
        case = deepcopy(job)
        child = case['runs'][1]['result']
        if defect == 'no-output': child.pop('output', None)
        elif defect in ('error', 'cancelled'): child.update(status=defect); child.pop('error', None)
        elif defect == 'version': child['schemaVersion'] = '2.0.0'
        elif defect == 'runId': child['manifestRef']['runId'] = 'other'
        elif defect == 'hash': child['manifestRef']['manifestHash'] = 'sha256:'+'a'*64
        valid = defect in ('valid', 'no-output')
        direct_valid = valid or defect in ('runId', 'hash')
        if direct_valid: validate_pipeline_result(child)
        else:
            with pytest.raises(ValueError): validate_pipeline_result(child)
        if valid: validate_job_envelope(case)
        else:
            with pytest.raises(ValueError): validate_job_envelope(case)
        (tmp_path/'job-envelope.json').write_text(json.dumps(case))
        run = subprocess.run([sys.executable, str(ROOT/'tools/validate_artifacts.py'), '--profile', 'protocol/v1', str(tmp_path)], capture_output=True, text=True)
        assert (run.returncode == 0) is valid, (defect, run.stdout, run.stderr)


def test_migration_cli_preserves_decimal_and_migrates_nested_legacy(tmp_path):
    import subprocess
    import sys
    from decimal import Decimal
    from tools import migrate
    from tools.validate import validate_job_envelope
    source=json.loads((ROOT/'fixtures/run_manifest/valid/basic.json').read_text())
    source['schemaVersion']='0.9.0'
    source['determinism']['seed']=Decimal('9007199254740993.0')
    input_path=tmp_path/'input.json';output=tmp_path/'output.json'
    input_path.write_text(migrate.lossless_json(source))
    result=subprocess.run([sys.executable,str(ROOT/'tools/migrate.py'),'--kind','legacy-run-manifest','--input',str(input_path),'--output',str(output)],capture_output=True,text=True)
    assert result.returncode==0,result.stderr
    assert json.loads(output.read_text(),parse_float=Decimal)['determinism']['seed']==Decimal('9007199254740993.0')
    job=json.loads((ROOT/'fixtures/job_envelope/valid/basic.json').read_text())
    job['schemaVersion']='0.9.0';job['runs'][0]['result']['schemaVersion']='0.9.0'
    converted=migrate.migrate_legacy_job_envelope(job)
    validate_job_envelope(converted)
    assert converted['runs'][0]['result']['schemaVersion']=='1.0.0'
    assert job['runs'][0]['result']['schemaVersion']=='0.9.0'
    job['runs'][0]['result']['schemaVersion']='9.0.0'
    import pytest
    with pytest.raises(ValueError,match='unsupported'):migrate.migrate_legacy_job_envelope(job)


def test_migration_cli_preserves_source_and_output_aliases(tmp_path):
    import os
    import subprocess
    import sys
    source=json.loads((ROOT/'fixtures/run_manifest/valid/basic.json').read_text())
    source['schemaVersion']='0.9.0'
    input_path=tmp_path/'input.json';input_path.write_text(json.dumps(source))
    original=input_path.read_bytes()
    def run(output):
        return subprocess.run([sys.executable,str(ROOT/'tools/migrate.py'),
            '--kind','legacy-run-manifest','--input',str(input_path),'--output',str(output)],
            capture_output=True,text=True)
    for mode in ('same','hardlink','symlink'):
        output=input_path if mode=='same' else tmp_path/mode
        if mode=='hardlink':os.link(input_path,output)
        if mode=='symlink':output.symlink_to(input_path)
        result=run(output)
        assert result.returncode!=0,(mode,result.stdout,result.stderr)
        assert input_path.read_bytes()==original
        if mode!='same':output.unlink()
    output=tmp_path/'result.json';unrelated=tmp_path/'unrelated.json'
    unrelated.write_bytes(b'preserve unrelated user data');os.link(unrelated,output)
    output.chmod(0o640)
    result=run(output);assert result.returncode==0,result.stderr
    assert unrelated.read_bytes()==b'preserve unrelated user data'
    assert input_path.read_bytes()==original
    assert json.loads(output.read_text())['schemaVersion']=='1.0.0'
    assert output.stat().st_mode & 0o777 == 0o640


def test_migration_failed_publication_preserves_existing_output(tmp_path,monkeypatch):
    import os
    import sys
    import pytest
    from tools import migrate
    source=json.loads((ROOT/'fixtures/run_manifest/valid/basic.json').read_text())
    source['schemaVersion']='0.9.0'
    input_path=tmp_path/'input.json';input_path.write_text(json.dumps(source))
    output=tmp_path/'output.json';output.write_bytes(b'previous output')
    before={p.name:p.read_bytes() for p in tmp_path.iterdir()}
    monkeypatch.setattr(sys,'argv',['migrate','--kind','legacy-run-manifest',
        '--input',str(input_path),'--output',str(output)])
    monkeypatch.syspath_prepend(str(ROOT/'tools'))
    def refuse(*args):raise OSError('controlled publication failure')
    monkeypatch.setattr(os,'replace',refuse)
    with pytest.raises(OSError,match='controlled publication failure'):migrate.main()
    assert {p.name:p.read_bytes() for p in tmp_path.iterdir()}==before
