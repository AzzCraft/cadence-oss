import hashlib
import json
import re
import sys
import unittest
from datetime import date
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
COMPAT_WINDOW_RE = re.compile(
    r"^(current|until \d{4}-\d{2}-\d{2}|from \d{4}-\d{2}-\d{2} to \d{4}-\d{2}-\d{2})$"
)
EXAMPLES_ROOT = ROOT.parent / "cadence-examples"


def _file_digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _registry_digest_errors(source_path: Path) -> list[str]:
    payload = json.loads(source_path.read_text(encoding="utf-8"))
    errors: list[str] = []
    for entry in payload["entries"]:
        if entry["status"] != "active" or entry["kind"] not in {"plugin", "policyPack"}:
            continue
        target = (source_path.parent / entry["ref"]).resolve()
        actual = _file_digest(target)
        expected = entry["digest"]
        if expected != actual:
            errors.append(
                f"{source_path.relative_to(ROOT)} {entry['kind']}/{entry['id']}: "
                f"digest mismatch for {target.relative_to(ROOT.parent)}: "
                f"expected {expected} actual {actual}"
            )
    return errors


def _collect_policy_ids(path: Path) -> list[str]:
    policy_ids: list[str] = []
    in_policies = False
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.rstrip()
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped == "policies:":
            in_policies = True
            continue
        if in_policies and stripped.startswith("-"):
            policy_ids.append(stripped.removeprefix("-").strip().strip("\"'"))
            continue
        if in_policies and not line.startswith(" "):
            in_policies = False
    return policy_ids


class RegistrySemanticsTests(unittest.TestCase):
    def test_index_refs_exist_and_status_metadata_is_consistent(self) -> None:
        for path in sorted((ROOT / "indexes").glob("*.json")):
            payload = json.loads(path.read_text())
            seen = set()
            for entry in payload["entries"]:
                key = (entry["kind"], entry["id"])
                self.assertNotIn(key, seen)
                seen.add(key)

                target = (path.parent / entry["ref"]).resolve()
                self.assertTrue(target.exists(), f"missing target for {path.name}: {entry['ref']}")
                for required in (
                    "id",
                    "kind",
                    "version",
                    "status",
                    "digest",
                    "ref",
                    "trust",
                    "deprecatedAt",
                    "deprecationReason",
                    "compatWindow",
                ):
                    self.assertIn(required, entry, f"{path.name} entry missing {required}: {entry}")

                self.assertIn(entry["status"], {"active", "deprecated", "removed"})
                self.assertRegex(entry["digest"], SHA256_RE)
                self.assertRegex(entry["compatWindow"], COMPAT_WINDOW_RE)

                trust = entry["trust"]
                self.assertIsInstance(trust, dict)
                self.assertTrue(trust.get("signer"))
                self.assertIsInstance(trust.get("allowlisted"), bool)

                if entry["status"] == "active":
                    self.assertIsNone(entry.get("deprecatedAt"))
                    self.assertIsNone(entry.get("deprecationReason"))
                else:
                    self.assertTrue(entry.get("deprecatedAt"))
                    self.assertTrue(entry.get("deprecationReason"))

    def test_root_registry_entries_resolve_into_indexed_entries(self) -> None:
        registry = json.loads((ROOT / "registry.json").read_text())
        indexed = {}
        for path in sorted((ROOT / "indexes").glob("*.json")):
            payload = json.loads(path.read_text())
            for entry in payload["entries"]:
                indexed[(entry["kind"], entry["id"])] = {
                    "entry": entry,
                    "resolved_ref": (path.parent / entry["ref"]).resolve(),
                }

        for entry in registry["entries"]:
            key = (entry["kind"], entry["id"])
            self.assertIn(key, indexed)
            resolved_root = (ROOT / entry["ref"]).resolve()
            self.assertEqual(resolved_root, indexed[key]["resolved_ref"])
            indexed_entry = indexed[key]["entry"]
            for field in ("version", "status", "digest", "deprecatedAt", "deprecationReason", "compatWindow"):
                self.assertEqual(entry.get(field), indexed_entry.get(field))
            self.assertEqual(entry.get("trust"), indexed_entry.get("trust"))

    def test_active_plugin_and_policy_pack_digests_match_artifacts(self) -> None:
        errors: list[str] = []
        for source_path in (
            ROOT / "registry.json",
            ROOT / "indexes" / "plugins.json",
            ROOT / "indexes" / "policy-packs.json",
        ):
            errors.extend(_registry_digest_errors(source_path))

        self.assertEqual(errors, [], "registry digest drift:\n" + "\n".join(errors))

    def test_root_registry_covers_example_policy_runtime_and_sandbox_usage(self) -> None:
        registry = json.loads((ROOT / "registry.json").read_text())
        plugins = {entry["id"] for entry in registry["entries"] if entry["kind"] == "plugin"}
        policies = {entry["id"] for entry in registry["entries"] if entry["kind"] == "policyPack"}
        runtime_ids = {entry["id"] for entry in registry["entries"] if entry["kind"] == "runtimeProfile"}
        sandbox_ids = {entry["id"] for entry in registry["entries"] if entry["kind"] == "sandboxProfile"}

        used_policies = set()
        for path in sorted(EXAMPLES_ROOT.rglob("cadence.yaml")):
            used_policies.update(_collect_policy_ids(path))

        self.assertTrue(used_policies)
        self.assertTrue(used_policies.issubset(policies), f"missing policy ids: {sorted(used_policies - policies)}")
        self.assertIn("cadence-plugin-ts", plugins)
        self.assertIn("cadence-plugin-python", plugins)
        self.assertIn("strict_offline", runtime_ids)
        self.assertIn("local_offline", sandbox_ids)




class ResolverTests(unittest.TestCase):
    """Tests for the standalone resolver module."""

    def test_load_registry(self) -> None:
        from resolver.resolve import load

        registry = load(ROOT / "registry.json")
        self.assertEqual(registry.registryId, "cadence-oss-local")
        self.assertGreater(len(registry.entries), 0)

    def test_lookup_existing_entry(self) -> None:
        from resolver.resolve import load, lookup

        registry = load(ROOT / "registry.json")
        entry = lookup(registry, "plugin", "cadence-plugin-ts")
        self.assertEqual(entry.kind, "plugin")
        self.assertEqual(entry.id, "cadence-plugin-ts")
        self.assertEqual(entry.status, "active")
        self.assertTrue(entry.trust.allowlisted)

    def test_lookup_missing_entry_raises(self) -> None:
        from resolver.resolve import load, lookup

        registry = load(ROOT / "registry.json")
        with self.assertRaises(ValueError) as ctx:
            lookup(registry, "plugin", "nonexistent")
        self.assertIn("not found", str(ctx.exception))

    def test_resolve_entry_succeeds(self) -> None:
        from resolver.resolve import load, resolve_entry

        registry_path = ROOT / "registry.json"
        registry = load(registry_path)
        resolution = resolve_entry(registry_path, registry, "plugin", "cadence-plugin-ts")
        self.assertIn("cadence-plugin-ts", resolution.resolved_ref)
        self.assertEqual(resolution.entry.status, "active")
        self.assertEqual(resolution.warnings, [])

    def test_resolve_entry_checks_digest(self) -> None:
        from resolver.resolve import load, resolve_entry

        registry_path = ROOT / "registry.json"
        registry = load(registry_path)
        # All active entries should resolve with matching digests
        for entry in registry.entries:
            if entry.status == "active":
                resolution = resolve_entry(registry_path, registry, entry.kind, entry.id)
                self.assertEqual(resolution.entry.digest, entry.digest)

    def test_resolve_entry_with_date(self) -> None:
        from resolver.resolve import load, resolve_entry

        registry_path = ROOT / "registry.json"
        registry = load(registry_path)
        # Active entries with "current" compat window should resolve at any date
        resolution = resolve_entry(
            registry_path, registry, "plugin", "cadence-plugin-ts",
            reference_date=date(2025, 1, 1),
        )
        self.assertEqual(resolution.entry.status, "active")

    def test_parse_compat_window_current(self) -> None:
        from resolver.resolve import parse_compat_window

        policy = parse_compat_window("current")
        self.assertEqual(policy.kind, "current")
        self.assertTrue(policy.contains(date.today()))

    def test_parse_compat_window_until(self) -> None:
        from resolver.resolve import parse_compat_window

        policy = parse_compat_window("until 2026-12-31")
        self.assertEqual(policy.kind, "until")
        self.assertTrue(policy.contains(date(2026, 6, 15)))
        self.assertFalse(policy.contains(date(2027, 1, 1)))

    def test_parse_compat_window_range(self) -> None:
        from resolver.resolve import parse_compat_window

        policy = parse_compat_window("from 2025-01-01 to 2026-12-31")
        self.assertEqual(policy.kind, "range")
        self.assertFalse(policy.contains(date(2024, 12, 31)))
        self.assertTrue(policy.contains(date(2025, 6, 15)))
        self.assertFalse(policy.contains(date(2027, 1, 1)))

    def test_parse_compat_window_invalid_raises(self) -> None:
        from resolver.resolve import parse_compat_window

        with self.assertRaises(ValueError):
            parse_compat_window("invalid")

    def test_list_entries_by_kind(self) -> None:
        from resolver.resolve import load, list_entries

        registry = load(ROOT / "registry.json")
        plugins = list_entries(registry, kind="plugin")
        self.assertTrue(all(e.kind == "plugin" for e in plugins))
        self.assertGreater(len(plugins), 0)

    def test_search_by_digest(self) -> None:
        from resolver.resolve import load, search_by_digest

        registry = load(ROOT / "registry.json")
        # Search for the first entry's digest
        entry = registry.entries[0]
        found = search_by_digest(registry, entry.digest)
        self.assertGreater(len(found), 0)
        self.assertEqual(found[0].id, entry.id)

    def test_list_deprecated_on_clean_registry(self) -> None:
        from resolver.resolve import load, list_deprecated

        registry = load(ROOT / "registry.json")
        deprecated = list_deprecated(registry)
        # All current entries are active, so no deprecated
        self.assertEqual(len(deprecated), 0)


class ValidatorTests(unittest.TestCase):
    """Tests for the standalone validator module."""

    def test_validate_real_registry(self) -> None:
        from resolver.resolve import load
        from resolver.validate import validate

        registry = load(ROOT / "registry.json")
        errors = validate(registry)
        self.assertEqual(errors, [], f"validation errors: {errors}")

    def test_validate_integrity_real_registry(self) -> None:
        from resolver.resolve import load
        from resolver.validate import validate_integrity

        registry = load(ROOT / "registry.json")
        errors = validate_integrity(registry, str(ROOT))
        self.assertEqual(errors, [], f"integrity errors: {errors}")

    def test_validate_index_consistency(self) -> None:
        from resolver.validate import validate_index_consistency

        errors = validate_index_consistency(
            ROOT / "registry.json",
            ROOT / "indexes",
        )
        self.assertEqual(errors, [], f"index consistency errors: {errors}")

    def test_validate_rejects_missing_registry_id(self) -> None:
        from resolver.resolve import Registry
        from resolver.validate import validate

        registry = Registry(schemaVersion="1.0.0", registryId="", entries=[])
        errors = validate(registry)
        self.assertTrue(any("registryId" in e for e in errors))

    def test_validate_rejects_invalid_kind(self) -> None:
        from resolver.resolve import Entry, Registry, Trust
        from resolver.validate import validate

        registry = Registry(
            schemaVersion="1.0.0",
            registryId="test",
            entries=[
                Entry(
                    kind="invalidKind",
                    id="test",
                    ref="./test",
                    status="active",
                    digest="sha256:" + "a" * 64,
                    compatWindow="current",
                    trust=Trust(signer="test", allowlisted=True),
                )
            ],
        )
        errors = validate(registry)
        self.assertTrue(any("invalid kind" in e for e in errors))

    def test_validate_rejects_invalid_digest(self) -> None:
        from resolver.resolve import Entry, Registry, Trust
        from resolver.validate import validate

        registry = Registry(
            schemaVersion="1.0.0",
            registryId="test",
            entries=[
                Entry(
                    kind="plugin",
                    id="test",
                    ref="./test",
                    status="active",
                    digest="md5:invalid",
                    compatWindow="current",
                    trust=Trust(signer="test", allowlisted=True),
                )
            ],
        )
        errors = validate(registry)
        self.assertTrue(any("digest must be sha256" in e for e in errors))

    def test_validate_rejects_deprecated_without_reason(self) -> None:
        from resolver.resolve import Entry, Registry, Trust
        from resolver.validate import validate

        registry = Registry(
            schemaVersion="1.0.0",
            registryId="test",
            entries=[
                Entry(
                    kind="plugin",
                    id="test",
                    ref="./test",
                    status="deprecated",
                    digest="sha256:" + "a" * 64,
                    compatWindow="until 2026-12-31",
                    deprecatedAt=None,
                    deprecationReason=None,
                    trust=Trust(signer="test", allowlisted=True),
                )
            ],
        )
        errors = validate(registry)
        self.assertTrue(any("requires deprecatedAt" in e for e in errors))

    def test_check_deprecation_gates_clean(self) -> None:
        from resolver.resolve import load
        from resolver.validate import check_deprecation_gates

        registry = load(ROOT / "registry.json")
        messages = check_deprecation_gates(registry)
        # All current entries are active, so no deprecation issues
        self.assertEqual(messages, [])


class ResolverCLITests(unittest.TestCase):
    """Tests for the CLI entry point."""

    def test_cli_validate_passes(self) -> None:
        import subprocess

        result = subprocess.run(
            ["python3", "-m", "resolver.cli", "validate"],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("passed", result.stdout.lower())

    def test_cli_check_integrity_passes(self) -> None:
        import subprocess

        result = subprocess.run(
            ["python3", "-m", "resolver.cli", "check-integrity"],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("passed", result.stdout.lower())

    def test_cli_resolve_plugin(self) -> None:
        import subprocess

        result = subprocess.run(
            ["python3", "-m", "resolver.cli", "resolve", "plugin", "cadence-plugin-ts"],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(result.stdout)
        self.assertEqual(data["kind"], "plugin")
        self.assertEqual(data["id"], "cadence-plugin-ts")
        self.assertEqual(data["status"], "active")

    def test_cli_list(self) -> None:
        import subprocess

        result = subprocess.run(
            ["python3", "-m", "resolver.cli", "list"],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("entries", result.stdout.lower())

    def test_cli_list_deprecated(self) -> None:
        import subprocess

        result = subprocess.run(
            ["python3", "-m", "resolver.cli", "list-deprecated"],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
