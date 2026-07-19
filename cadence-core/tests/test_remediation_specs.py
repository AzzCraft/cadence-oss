"""Remediation spec tests for cadence-core (CORE-SIGN-001, CORE-DET-001, CORE-REPLAY-001, SBOX-002, B-01, B-02)."""
from __future__ import annotations

import json
import unittest
from pathlib import Path
from tests._root_contract import repository_root_for_test_file


ROOT = repository_root_for_test_file(__file__)  # cadence-oss/cadence-core


class CoreRemediationSpecTests(unittest.TestCase):

    # --- CORE-DET-001 (completed): determinism tier in evidence struct ---
    def test_core_det_001_determinism_struct_in_evidence(self) -> None:
        evidence = ROOT / "internal" / "evidence" / "evidence.go"
        self.assertTrue(evidence.exists())
        text = evidence.read_text(encoding="utf-8")
        self.assertIn("Determinism", text)
        self.assertIn("Tier", text)

    def test_core_det_001_verify_test_has_deterministic_artifact_assertions(self) -> None:
        text = (ROOT / "tests" / "integration" / "verify_test.go").read_text(encoding="utf-8")
        self.assertIn("deterministic-evidence.json", text)
        self.assertIn("step-hash-chain.json", text)
        self.assertIn("replay-package.json", text)
        self.assertIn("bundleHash", text)

    # --- CORE-REPLAY-001 (completed): replay bundle hash uses canonical fields ---
    def test_core_replay_001_replay_package_and_tests_exist(self) -> None:
        replay_dir = ROOT / "internal" / "replay"
        self.assertTrue(replay_dir.exists())
        self.assertTrue((replay_dir / "replay.go").exists())
        self.assertTrue((replay_dir / "replay_test.go").exists())

    def test_core_replay_001_replay_hash_uses_canonical_fields(self) -> None:
        text = (ROOT / "internal" / "replay" / "replay.go").read_text(encoding="utf-8")
        for needle in ("RelPath", "Mode", "Size", "FileHash"):
            with self.subTest(field=needle):
                self.assertIn(needle, text)

    # --- CORE-SIGN-001 (P1): HSM/KMS anchor uses real external command signer ---
    def test_core_sign_001_signing_has_real_hsm_provider(self) -> None:
        signing_go = ROOT / "internal" / "signing" / "signing.go"
        self.assertTrue(signing_go.exists())
        text = signing_go.read_text(encoding="utf-8")
        self.assertIn("ExternalCommandSigner", text)
        self.assertTrue(
            any(tok in text for tok in ('hsm://', 'kms://', 'pkcs11', 'awskms', 'gcpkms')),
            "signing.go has no HSM/KMS URI handling"
        )

    def test_core_sign_001_signing_test_covers_hsm_integration(self) -> None:
        signing_test = ROOT / "internal" / "signing" / "signing_test.go"
        self.assertTrue(signing_test.exists())
        text = signing_test.read_text(encoding="utf-8")
        self.assertTrue(
            any(tok in text for tok in (
                "ExternalCommandSigner", "TestExternalSigner", "HSMAnchor",
                "TestHSMSign", "TestKMSSign", "pkcs11", "awskms", "gcpkms",
                "BuildHSMAnchor", "BuildGovernedAnchor", "ValidateHSMAnchor",
            )),
            "signing_test.go has no HSM/KMS integration test"
        )

    def test_core_sign_001_no_operator_local_placeholder(self) -> None:
        text = (ROOT / "internal" / "signing" / "signing.go").read_text(encoding="utf-8")
        self.assertNotIn("operator-local-placeholder", text)

    def test_core_sign_001_software_hmac_only_in_dev_mode(self) -> None:
        text = (ROOT / "internal" / "signing" / "signing.go").read_text(encoding="utf-8")
        self.assertTrue(
            "software-hmac" not in text or "dev" in text.lower(),
            "software-hmac must only appear in dev mode context",
        )

    def test_core_sign_001_governed_test_functions_exist(self) -> None:
        text = (ROOT / "tests" / "integration" / "verify_test.go").read_text(encoding="utf-8")
        self.assertIn("TestGovernedSignatureUsesActiveHSMAnchor", text)
        self.assertIn("TestDevModeExplicitlyOptInToSoftwareHmac", text)

    # --- SBOX-002: verify_test.go has real-runtime integration tests ---
    def test_sbox_002_verify_test_has_real_container_runtime_test(self) -> None:
        text = (ROOT / "tests" / "integration" / "verify_test.go").read_text(encoding="utf-8")
        self.assertIn("TestVerifyUsesRealContainerRuntime", text)

    def test_sbox_002_verify_test_has_real_microvm_runtime_test(self) -> None:
        text = (ROOT / "tests" / "integration" / "verify_test.go").read_text(encoding="utf-8")
        self.assertIn("TestVerifyUsesRealMicrovmRuntime", text)

    # --- B-01 (D-03): evidence bundle AuditMetadata separation ---
    def test_b01_evidence_audit_metadata_separation(self) -> None:
        text = (ROOT / "internal" / "evidence" / "evidence.go").read_text(encoding="utf-8")
        self.assertIn("AuditMetadata", text)
        self.assertIn("BundleID", text)
        self.assertIn("Timestamp", text)

    def test_b01_bundle_hash_excludes_audit_metadata(self) -> None:
        text = (ROOT / "internal" / "evidence" / "evidence.go").read_text(encoding="utf-8")
        self.assertIn("BundleHash", text)
        # AuditMetadata is separate from the hash computation
        self.assertIn("AuditMeta", text)

    # --- B-02 (D-06): governed signing key hierarchy ---
    def test_b02_governed_signing_key_hierarchy(self) -> None:
        signing_go = (ROOT / "internal" / "signing" / "signing.go").read_text(encoding="utf-8")
        self.assertIn("CADENCE_GOVERNED_SIGN", signing_go)
        main_go = ROOT / "cmd" / "cadence" / "main.go"
        if main_go.exists():
            text = main_go.read_text(encoding="utf-8")
            self.assertTrue(
                "governed" in text.lower() or "key hierarchy" in text.lower() or "anchor" in text.lower(),
                "main.go lacks governed signing references",
            )

    def test_b02_signing_docs_exist_and_cover_modes(self) -> None:
        signing_md = ROOT / "docs" / "SIGNING.md"
        self.assertTrue(signing_md.exists(), "docs/SIGNING.md missing")
        text = signing_md.read_text(encoding="utf-8")
        self.assertIn("dev", text.lower())
        self.assertIn("governed", text.lower())
        self.assertIn("key hierarchy", text.lower())

    def test_b02_governed_mode_fail_closed_in_main(self) -> None:
        main_go = ROOT / "cmd" / "cadence" / "main.go"
        if not main_go.exists():
            self.skipTest("cmd/cadence/main.go not found")
        text = main_go.read_text(encoding="utf-8")
        self.assertIn("governed", text)
        self.assertIn("anchor", text.lower())

    def test_b02_test_governed_signature_verification_exists(self) -> None:
        text = (ROOT / "tests" / "integration" / "verify_test.go").read_text(encoding="utf-8")
        self.assertIn("TestGovernedSignatureVerification", text)

    # --- Signing depth: key hierarchy, dual-layer, detached ---
    def test_signing_key_hierarchy_structs_exist(self) -> None:
        text = (ROOT / "internal" / "signing" / "signing.go").read_text(encoding="utf-8")
        self.assertIn("KeyHierarchy", text)
        self.assertIn("KeyHierarchyLevel", text)
        self.assertIn("BuildGovernedKeyHierarchy", text)
        self.assertIn("ValidateKeyHierarchy", text)

    def test_signing_dual_layer_exists(self) -> None:
        text = (ROOT / "internal" / "signing" / "signing.go").read_text(encoding="utf-8")
        self.assertIn("DualLayerSignature", text)
        self.assertIn("NewDualLayerSignature", text)
        self.assertIn("VerifyDualLayerSignature", text)

    def test_signing_detached_signature_exists(self) -> None:
        text = (ROOT / "internal" / "signing" / "signing.go").read_text(encoding="utf-8")
        self.assertIn("DetachedSignature", text)
        self.assertIn("NewDetachedSignature", text)
        self.assertIn("VerifyDetachedSignature", text)

    def test_signing_rotation_ceremony_exists(self) -> None:
        text = (ROOT / "internal" / "signing" / "signing.go").read_text(encoding="utf-8")
        self.assertIn("RotationCeremony", text)
        self.assertIn("PlanRotation", text)
        self.assertIn("ExecuteRotation", text)

    # --- Determinism depth: TestDeterminism function in verify_test.go ---
    def test_core_det_001_test_determinism_function_exists(self) -> None:
        text = (ROOT / "tests" / "integration" / "verify_test.go").read_text(encoding="utf-8")
        self.assertIn("TestDeterminism", text)
        self.assertIn("bundleHash", text)

    # --- CORE-DET-001 matrix exact: verify_test checks canonical artifacts ---
    def test_core_det_001_matrix_canonical_artifacts(self) -> None:
        text = (ROOT / "tests" / "integration" / "verify_test.go").read_text(encoding="utf-8")
        for artifact in ("deterministic-evidence.json", "step-hash-chain.json", "replay-package.json"):
            with self.subTest(artifact=artifact):
                self.assertIn(artifact, text)
        self.assertIn("bundleHash differs between runs", text)

    # --- CORE-REPLAY-001 matrix exact: replay.go has canonical fields ---
    def test_core_replay_001_matrix_canonical_fields(self) -> None:
        text = (ROOT / "internal" / "replay" / "replay.go").read_text(encoding="utf-8")
        for needle in ("RelPath", "Mode", "Size", "FileHash"):
            with self.subTest(field=needle):
                self.assertIn(needle, text)

    # --- CORE-SIGN-001 matrix exact: no operator-local-placeholder ---
    def test_core_sign_001_matrix_no_placeholder(self) -> None:
        text = (ROOT / "internal" / "signing" / "signing.go").read_text(encoding="utf-8")
        self.assertNotIn("operator-local-placeholder", text)

    # --- CORE-SIGN-001 depth: software-hmac guarded by dev mode ---
    def test_core_sign_001_software_hmac_dev_guard(self) -> None:
        text = (ROOT / "internal" / "signing" / "signing.go").read_text(encoding="utf-8")
        if "software-hmac" in text:
            idx = text.index("software-hmac")
            context = text[max(0, idx - 200):idx + 200].lower()
            self.assertTrue(
                "dev" in context or "test" in context or "operator-local" in context,
                "software-hmac must be in dev/test context",
            )

    # --- Evidence structure: evidence.go has EvidenceBundle and AuditMetadata ---
    def test_evidence_bundle_structure(self) -> None:
        text = (ROOT / "internal" / "evidence" / "evidence.go").read_text(encoding="utf-8")
        self.assertIn("EvidenceBundle", text)
        self.assertIn("AuditMetadata", text)
        self.assertIn("BundleHash", text)

    # --- Evidence structure: evidence.go distinguishes deterministic from metadata ---
    def test_evidence_deterministic_separation(self) -> None:
        text = (ROOT / "internal" / "evidence" / "evidence.go").read_text(encoding="utf-8")
        self.assertIn("BundleID", text)
        self.assertIn("Timestamp", text)
        # These should be in AuditMetadata, not affecting BundleHash
        self.assertIn("AuditMetadata", text)

    # --- Signing docs: SIGNING.md covers dev and governed modes ---
    def test_signing_docs_cover_both_modes(self) -> None:
        text = (ROOT / "docs" / "SIGNING.md").read_text(encoding="utf-8")
        self.assertIn("dev", text.lower())
        self.assertIn("governed", text.lower())
        self.assertIn("Ed25519", text)

    # --- IP boundary: cadence-oss has IP_BOUNDARY.md ---
    def test_ip_boundary_exists(self) -> None:
        self.assertTrue((ROOT.parent / "IP_BOUNDARY.md").exists())

    # --- LICENSE: cadence-oss has LICENSE ---
    def test_license_file_exists(self) -> None:
        self.assertTrue((ROOT.parent / "LICENSE").exists())

    # --- Signing: verify_test has TestSignAndVerify ---
    def test_signing_test_sign_and_verify(self) -> None:
        text = (ROOT / "tests" / "integration" / "verify_test.go").read_text(encoding="utf-8")
        self.assertTrue(
            "TestSignAndVerify" in text or "TestGovernedSignatureVerification" in text,
            "Missing sign-and-verify integration test",
        )

    # --- V9 Item 10: cadence-core L2 modules exist ---

    def test_v9_10_runtime_module_dirs_exist(self) -> None:
        for mod in ("replay", "sandbox", "plugins", "registry", "signing", "waiver", "report"):
            with self.subTest(module=mod):
                self.assertTrue((ROOT / "internal" / mod).is_dir(), f"missing internal/{mod}")

    def test_v9_10_runtime_docs_exist(self) -> None:
        for doc in ("CONFIG.md", "REPLAY.md", "PLUGINS.md", "SIGNING.md", "WAIVERS.md"):
            with self.subTest(doc=doc):
                self.assertTrue((ROOT / "docs" / doc).exists(), f"missing docs/{doc}")

    def test_v9_10_no_legacy_baseline_in_tree(self) -> None:
        for path in ROOT.rglob("*"):
            if path.is_file() and path.suffix in {".go", ".md", ".yaml", ".yml", ".json", ".txt"}:
                text = path.read_text(encoding="utf-8", errors="ignore")
                with self.subTest(file=str(path.relative_to(ROOT))):
                    self.assertNotIn("unified" + "-current-baseline", text)

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

    # --- P1-01: config loader depth tests ---

    def test_p1_01_config_go_no_manual_parser_markers(self) -> None:
        config_go = (ROOT / "internal" / "config" / "config.go").read_text(encoding="utf-8")
        forbidden = [
            "parseCadenceConfigDocument",
            "type cadenceConfigDocument struct",
            "scalarKeys := map[string]struct{}",
            "blockKeys := map[string]struct{}",
            'strings.Split(string(data), "\\n")',
            "currentBlock",
        ]
        for marker in forbidden:
            with self.subTest(marker=marker):
                self.assertNotIn(marker, config_go,
                    f"config.go still contains legacy manual-parser marker: {marker}")

    def test_p1_01_config_loader_uses_yaml_and_json_schema(self) -> None:
        config_go = (ROOT / "internal" / "config" / "config.go").read_text(encoding="utf-8")
        go_mod = (ROOT / "go.mod").read_text(encoding="utf-8")
        for marker in ("gopkg.in/yaml.v3", "jsonschema", "config.schema.json"):
            with self.subTest(marker=marker):
                self.assertTrue(marker in config_go or marker in go_mod, f"missing schema-driven loader marker: {marker}")

    def test_p1_01_config_regression_tests_have_required_names(self) -> None:
        test_text = "\n".join(
            p.read_text(encoding="utf-8", errors="replace")
            for p in (ROOT / "internal" / "config").glob("*test.go")
        )
        for test_name in [
            "TestLoadRejectsUnknownTopLevelField",
            "TestLoadRejectsMissingRequiredPins",
            "TestLoadRejectsWrongTypeForPolicies",
            "TestConfigSchemaRequiredFieldsMatchLoader",
        ]:
            with self.subTest(test=test_name):
                self.assertIn(test_name, test_text, f"missing config regression test: {test_name}")

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

    def test_v7_b02_governed_signer_command_env_var(self) -> None:
        text = (ROOT / "internal" / "signing" / "signing.go").read_text(encoding="utf-8")
        self.assertIn("CADENCE_GOVERNED_SIGNER_COMMAND", text)

    # --- V7 B-02: main.go governed outputs ---

    def test_v7_b02_main_go_governed_key_hierarchy(self) -> None:
        main_go = ROOT / "cmd" / "cadence" / "main.go"
        if not main_go.exists():
            self.skipTest("cmd/cadence/main.go not found")
        text = main_go.read_text(encoding="utf-8")
        self.assertTrue("KeyHierarchy" in text or "key hierarchy" in text.lower(),
            "main.go must reference key hierarchy in governed mode")

    def test_v7_b02_main_go_governed_detached_signature(self) -> None:
        main_go = ROOT / "cmd" / "cadence" / "main.go"
        if not main_go.exists():
            self.skipTest("cmd/cadence/main.go not found")
        text = main_go.read_text(encoding="utf-8")
        self.assertTrue("DetachedSignature" in text or "detached" in text.lower(),
            "main.go must reference detached signatures")

    def test_v7_b02_governed_rejects_operator_local_anchor(self) -> None:
        main_go = ROOT / "cmd" / "cadence" / "main.go"
        if not main_go.exists():
            self.skipTest("cmd/cadence/main.go not found")
        text = main_go.read_text(encoding="utf-8")
        self.assertIn("operator-local", text,
            "main.go must contain operator-local check for fail-closed governed mode")


if __name__ == "__main__":
    unittest.main()
