"""Static artifact/document checks; executable behavior is checked by native tests."""
from __future__ import annotations

import json
import unittest
from pathlib import Path
from tests._root_contract import repository_root_for_test_file


ROOT = repository_root_for_test_file(__file__)  # cadence-oss/cadence-core


class CoreRemediationSpecTests(unittest.TestCase):

    def test_core_replay_001_replay_package_and_tests_exist(self) -> None:
        replay_dir = ROOT / "internal" / "replay"
        self.assertTrue(replay_dir.exists())
        self.assertTrue((replay_dir / "replay.go").exists())
        self.assertTrue((replay_dir / "replay_test.go").exists())

    def test_b02_signing_docs_exist_and_cover_modes(self) -> None:
        signing_md = ROOT / "docs" / "SIGNING.md"
        self.assertTrue(signing_md.exists(), "docs/SIGNING.md missing")
        text = signing_md.read_text(encoding="utf-8")
        self.assertIn("dev", text.lower())
        self.assertIn("governed", text.lower())
        self.assertIn("key hierarchy", text.lower())

    def test_signing_docs_cover_both_modes(self) -> None:
        text = (ROOT / "docs" / "SIGNING.md").read_text(encoding="utf-8")
        self.assertIn("dev", text.lower())
        self.assertIn("governed", text.lower())
        self.assertIn("Ed25519", text)

    def test_ip_boundary_exists(self) -> None:
        self.assertTrue((ROOT.parent / "IP_BOUNDARY.md").exists())

    def test_license_file_exists(self) -> None:
        self.assertTrue((ROOT.parent / "LICENSE").exists())

    def test_v9_10_runtime_module_dirs_exist(self) -> None:
        for mod in ("replay", "sandbox", "plugins", "registry", "signing", "waiver", "report"):
            with self.subTest(module=mod):
                self.assertTrue((ROOT / "internal" / mod).is_dir(), f"missing internal/{mod}")

    def test_v9_10_runtime_docs_exist(self) -> None:
        for doc in ("CONFIG.md", "REPLAY.md", "PLUGINS.md", "SIGNING.md", "WAIVERS.md"):
            with self.subTest(doc=doc):
                self.assertTrue((ROOT / "docs" / doc).exists(), f"missing docs/{doc}")

    def test_v9_10_config_schema_required_fields(self) -> None:
        import json
        schema = json.loads((ROOT / "config.schema.json").read_text(encoding="utf-8"))
        required_expected = {"projectId", "closureRef", "toolingLock", "runtimeRef", "registryRef", "sandboxRef", "policies"}
        schema_required = set(schema.get("required", []))
        self.assertTrue(
            required_expected.issubset(schema_required),
            f"config.schema.json required is incomplete. expected at least {sorted(required_expected)}, got {sorted(schema_required)}",
        )

    def test_v9_10_config_fixtures_exist(self) -> None:
        valid_dir = ROOT / "tests" / "fixtures" / "config" / "valid"
        invalid_dir = ROOT / "tests" / "fixtures" / "config" / "invalid"
        self.assertTrue(valid_dir.is_dir(), f"missing: {valid_dir}")
        self.assertTrue(invalid_dir.is_dir(), f"missing: {invalid_dir}")
        self.assertTrue(any(valid_dir.iterdir()), "valid config fixture dir is empty")
        self.assertTrue(any(invalid_dir.iterdir()), "invalid config fixture dir is empty")

    def test_v9_10_config_doc_mentions_required_fields(self) -> None:
        docs_config = (ROOT / "docs" / "CONFIG.md").read_text(encoding="utf-8")
        for field in ("projectId", "closureRef", "toolingLock", "runtimeRef", "registryRef", "sandboxRef", "policies"):
            with self.subTest(field=field):
                self.assertIn(field, docs_config)

    def test_p1_01_config_schema_properties_match_required(self) -> None:
        schema = json.loads((ROOT / "config.schema.json").read_text(encoding="utf-8"))
        required = set(schema.get("required", []))
        properties = set(schema.get("properties", {}).keys())
        for field in required:
            with self.subTest(field=field):
                self.assertIn(field, properties,
                    f"Required field {field} not defined in schema properties")

    def test_p1_01_valid_fixtures_have_required_fields(self) -> None:
        schema = json.loads((ROOT / "config.schema.json").read_text(encoding="utf-8"))
        required = set(schema.get("required", []))
        valid_dir = ROOT / "tests" / "fixtures" / "config" / "valid"
        for f in valid_dir.glob("*.yaml"):
            with self.subTest(fixture=f.name):
                lines = f.read_text(encoding="utf-8")
                for req_field in required:
                    self.assertIn(req_field, lines,
                        f"Valid fixture {f.name} missing required field: {req_field}")

    def test_p1_01_invalid_fixtures_exist(self) -> None:
        invalid_dir = ROOT / "tests" / "fixtures" / "config" / "invalid"
        self.assertTrue(invalid_dir.is_dir())
        invalid_files = list(invalid_dir.glob("*.yaml"))
        self.assertGreater(len(invalid_files), 0, "No invalid config fixtures")

    def test_p1_01_docs_config_mentions_all_required_fields(self) -> None:
        docs_config = (ROOT / "docs" / "CONFIG.md").read_text(encoding="utf-8")
        required = {"projectId", "closureRef", "toolingLock", "runtimeRef",
                    "registryRef", "sandboxRef", "policies"}
        for field in sorted(required):
            with self.subTest(field=field):
                self.assertIn(field, docs_config,
                    f"docs/CONFIG.md does not mention required field: {field}")

    # --- V7 B-02: CADENCE_GOVERNED_SIGNER_COMMAND env var ---


    # --- V7 B-02: main.go governed outputs ---





if __name__ == "__main__":
    unittest.main()
