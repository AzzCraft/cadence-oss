"""P1-01: cadence-core config loader must be offline-hermetic and self-contained.

Tests derived from:
- das_repos_420_recheck_md_bundle/das_repos_420_full_recheck_correct_only_unresolved.md
- das_repos_420_recheck_md_bundle/das_repos_420_unresolved_priority_fix_list.md
"""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from tests._root_contract import repository_root_for_test_file


CORE = repository_root_for_test_file(__file__)


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def write_json(path: Path, payload: dict) -> None:
    write_text(path, json.dumps(payload, ensure_ascii=False, indent=2))


class CoreHermeticConfigLoader420Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.config_go = (CORE / "internal" / "config" / "config.go").read_text(encoding="utf-8", errors="replace")
        cls.go_mod = (CORE / "go.mod").read_text(encoding="utf-8", errors="replace")

    def test_config_schema_is_embedded_not_source_tree_loaded(self) -> None:
        self.assertIn("//go:embed", self.config_go, "config.go must embed config.schema.json")
        self.assertIn("embed", self.config_go, "config.go must use Go embed")
        self.assertNotIn("runtime.Caller(0)", self.config_go, "runtime.Caller-based schema lookup remains")
        self.assertNotIn('..", "..", "config.schema.json"', self.config_go, "source-relative schema path remains")

    def test_direct_dependencies_are_vendored(self) -> None:
        self.assertIn("github.com/santhosh-tekuri/jsonschema/v5", self.go_mod)
        self.assertIn("gopkg.in/yaml.v3", self.go_mod)
        self.assertNotIn("// indirect", self.go_mod, "directly imported config deps must not remain indirect")
        self.assertTrue((CORE / "vendor").is_dir(), "vendor directory missing")
        self.assertTrue(
            (CORE / "vendor" / "github.com" / "santhosh-tekuri" / "jsonschema" / "v5").is_dir(),
            "vendor missing jsonschema/v5",
        )
        self.assertTrue((CORE / "vendor" / "gopkg.in" / "yaml.v3").is_dir(), "vendor missing yaml.v3")

    def test_verify_scripts_run_go_with_network_disabled_and_vendor_mode(self) -> None:
        for script_name in ("verify", "verify-full"):
            script = (CORE / "scripts" / script_name).read_text(encoding="utf-8", errors="replace")
            with self.subTest(script=script_name):
                self.assertIn("GOFLAGS", script)
                self.assertIn("-mod=vendor", script)
                self.assertIn("GOPROXY", script)
                self.assertIn("off", script)
                self.assertIn("GOSUMDB", script)


    def test_trimpath_binary_doctor_loads_config_without_source_tree_schema(self) -> None:
        env = os.environ.copy()
        env["GOPROXY"] = "off"
        env["GOSUMDB"] = "off"
        env["GOFLAGS"] = "-mod=vendor"

        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            binary = td_path / "cadence"
            build_proc = subprocess.run(
                ["go", "build", "-trimpath", "-buildvcs=false", "-mod=vendor", "-o", str(binary), "./cmd/cadence"],
                cwd=CORE,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=600,
            )
            self.assertEqual(build_proc.returncode, 0, "trimpath build failed\n" + build_proc.stdout)

            repo = td_path / "repo"
            repo.mkdir()
            write_text(
                repo / "cadence.yaml",
                """projectId: demo-project
mode: strict_offline
closureRef: suite_version_closure.json
toolingLock: tooling_lock.json
runtimeRef: runtime.json
registryRef: registry.json
sandboxRef: sandbox.json
rootAnchor: operator-local
policies:
  - standard-ui-v140
ui:
  enabled: false
  profile: pr
""",
            )
            write_text(repo / "runtime.json", "{}")
            write_json(
                repo / "registry.json",
                {
                    "schemaVersion": "1.0.0",
                    "registryId": "test-registry",
                    "entries": [],
                },
            )
            write_text(repo / "sandbox.json", "{}")
            write_json(repo / "suite_lock.json", {"schemaVersion": "1.0.0"})
            write_json(
                repo / "suite_version_closure.json",
                {
                    "schemaVersion": "1.0.0",
                    "standardVersion": "1.4.0",
                    "standardManifestVersion": "1.4.0",
                    "suiteVersion": "1.0.0",
                    "factoryVersion": "factory-1.0.0",
                    "verifyRuntimeVersion": "runtime-1.0.0",
                    "closureUpdatedAt": "2026-04-20T00:00:00Z",
                    "suiteLockRef": {
                        "kind": "file",
                        "uri": "./suite_lock.json",
                        "pinType": "manifest",
                        "pinValue": "suite_lock.json",
                        "floating": False,
                    },
                    "lockRefs": {
                        "suiteToolingLock": {
                            "kind": "file",
                            "uri": "./tooling_lock.json",
                            "pinType": "manifest",
                            "pinValue": "tooling_lock.json",
                            "floating": False,
                        }
                    },
                    "refs": {
                        "standard": {
                            "kind": "git",
                            "uri": "https://example.invalid/das-standard.git",
                            "pinType": "commit",
                            "pinValue": "1111111",
                            "floating": False,
                        },
                        "suite": {
                            "kind": "git",
                            "uri": "https://example.invalid/das-suite.git",
                            "pinType": "commit",
                            "pinValue": "2222222",
                            "floating": False,
                        },
                        "factory": {
                            "kind": "git",
                            "uri": "https://example.invalid/dasops.git",
                            "pinType": "commit",
                            "pinValue": "3333333",
                            "floating": False,
                        },
                        "verifyRuntime": {
                            "kind": "git",
                            "uri": "https://example.invalid/cadence-oss.git",
                            "pinType": "commit",
                            "pinValue": "4444444",
                            "floating": False,
                        },
                    },
                },
            )
            write_json(
                repo / "tooling_lock.json",
                {
                    "schemaVersion": "1.0.0",
                    "standardManifestVersion": "1.4.0",
                    "sourceOfTruth": {
                        "kind": "git",
                        "uri": "https://example.invalid/product.git",
                        "pinType": "commit",
                        "pinValue": "aaaaaaa",
                        "floating": False,
                    },
                    "verifyRuntime": {
                        "kind": "git",
                        "uri": "https://example.invalid/cadence-oss.git",
                        "pinType": "commit",
                        "pinValue": "4444444",
                        "floating": False,
                    },
                    "suiteVersionClosureRef": {
                        "kind": "file",
                        "uri": "./suite_version_closure.json",
                        "pinType": "manifest",
                        "pinValue": "suite_version_closure.json",
                        "floating": False,
                    },
                    "suiteLockRef": {
                        "kind": "file",
                        "uri": "./suite_lock.json",
                        "pinType": "manifest",
                        "pinValue": "suite_lock.json",
                        "floating": False,
                    },
                    "verifyRegistryRef": {
                        "kind": "file",
                        "uri": "./registry.json",
                        "pinType": "manifest",
                        "pinValue": "registry.json",
                        "floating": False,
                    },
                    "toolchain": [
                        {"name": "go", "version": "1.22.x", "manager": "system"},
                    ],
                },
            )

            doctor_proc = subprocess.run(
                [str(binary), "doctor", "--lock=false"],
                cwd=repo,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=120,
            )
            self.assertEqual(doctor_proc.returncode, 0, "clean-room trimpath doctor failed\n" + doctor_proc.stdout)
            self.assertIn("status: OK", doctor_proc.stdout)


if __name__ == "__main__":
    unittest.main()
