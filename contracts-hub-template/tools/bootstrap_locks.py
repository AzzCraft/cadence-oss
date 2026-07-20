#!/usr/bin/env python3
"""Bootstrap template lock files with release version values.

Usage:
    python3 tools/bootstrap_locks.py --suite-version 1.0.0 --cadence-version 1.0.0
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main() -> None:
    parser = argparse.ArgumentParser(description="Bootstrap contracts-hub-template lock files")
    parser.add_argument("--suite-version", required=True, help="Suite version to pin (e.g. 1.0.0)")
    parser.add_argument("--cadence-version", required=True, help="Cadence CLI version to pin (e.g. 1.0.0)")
    args = parser.parse_args()

    # Update cadence_lock.json
    cadence_lock_path = ROOT / "cadence_lock.json"
    cadence_lock = json.loads(cadence_lock_path.read_text(encoding="utf-8"))
    cadence_lock["cadence_cli"]["version"] = args.cadence_version
    cadence_lock.pop("note", None)
    cadence_lock_path.write_text(json.dumps(cadence_lock, indent=2) + "\n", encoding="utf-8")

    # Update suite_version_closure.json if it exists
    closure_path = ROOT / "suite_version_closure.json"
    if closure_path.exists():
        closure = json.loads(closure_path.read_text(encoding="utf-8"))
        closure["suiteVersion"] = args.suite_version
        closure.pop("note", None)
        closure_path.write_text(json.dumps(closure, indent=2) + "\n", encoding="utf-8")

    tooling_lock_path = ROOT / "tooling_lock.json"
    tooling_lock = json.loads(tooling_lock_path.read_text(encoding="utf-8"))
    tooling_lock["pins"] = {
        "suiteVersion": args.suite_version,
        "cadenceCliVersion": args.cadence_version,
    }
    tooling_lock.pop("note", None)
    tooling_lock_path.write_text(json.dumps(tooling_lock, indent=2) + "\n", encoding="utf-8")

    print(f"Bootstrapped locks: cadence={args.cadence_version}, suite={args.suite_version}")


if __name__ == "__main__":
    main()
