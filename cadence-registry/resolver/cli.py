"""CLI entry point for cadence-registry resolver/validator.

Usage:
    python3 -m resolver.cli resolve <kind> <id> [--registry <path>] [--date <YYYY-MM-DD>]
    python3 -m resolver.cli validate [--registry <path>]
    python3 -m resolver.cli check-integrity [--registry <path>]
    python3 -m resolver.cli list-deprecated [--registry <path>] [--date <YYYY-MM-DD>]
    python3 -m resolver.cli list [--kind <kind>] [--status <status>] [--registry <path>]
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import date, datetime
from pathlib import Path

from .resolve import load, resolve_entry, list_entries, list_deprecated, search_by_digest
from .validate import validate, validate_integrity, validate_index_consistency, check_deprecation_gates


def _default_registry_path() -> Path:
    return Path(__file__).resolve().parents[1] / "registry.json"


def _default_indexes_dir() -> Path:
    return Path(__file__).resolve().parents[1] / "indexes"


def cmd_resolve(args: argparse.Namespace) -> int:
    registry_path = Path(args.registry) if args.registry else _default_registry_path()
    registry = load(registry_path)
    ref_date = None
    if args.date:
        ref_date = datetime.strptime(args.date, "%Y-%m-%d").date()
    try:
        resolution = resolve_entry(
            registry_path, registry, args.kind, args.id, reference_date=ref_date
        )
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    result = {
        "kind": resolution.entry.kind,
        "id": resolution.entry.id,
        "version": resolution.entry.version,
        "status": resolution.entry.status,
        "digest": resolution.entry.digest,
        "resolvedRef": resolution.resolved_ref,
        "compatWindow": resolution.entry.compatWindow,
        "warnings": resolution.warnings,
    }
    print(json.dumps(result, indent=2))
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    registry_path = Path(args.registry) if args.registry else _default_registry_path()
    registry = load(registry_path)
    errors = validate(registry)
    if errors:
        for err in errors:
            print(f"ERROR: {err}", file=sys.stderr)
        return 1
    print("Registry validation passed.")
    return 0


def cmd_check_integrity(args: argparse.Namespace) -> int:
    registry_path = Path(args.registry) if args.registry else _default_registry_path()
    registry = load(registry_path)
    registry_dir = registry_path.parent
    errors = validate_integrity(registry, registry_dir)
    if errors:
        for err in errors:
            print(f"ERROR: {err}", file=sys.stderr)
        return 1
    print("Integrity check passed — all digests match.")
    return 0


def cmd_list_deprecated(args: argparse.Namespace) -> int:
    registry_path = Path(args.registry) if args.registry else _default_registry_path()
    registry = load(registry_path)
    ref_date = None
    if args.date:
        ref_date = datetime.strptime(args.date, "%Y-%m-%d").date()
    messages = check_deprecation_gates(registry, reference_date=ref_date)
    if not messages:
        print("No deprecated or removed entries.")
        return 0
    for msg in messages:
        print(msg)
    return 1 if any(msg.startswith("ERROR:") for msg in messages) else 0


def cmd_list(args: argparse.Namespace) -> int:
    registry_path = Path(args.registry) if args.registry else _default_registry_path()
    registry = load(registry_path)
    entries = list_entries(registry, kind=args.kind, status=args.status)
    for e in entries:
        trust_info = f" signer={e.trust.signer}" if e.trust else ""
        print(f"  {e.kind}/{e.id}  v{e.version}  [{e.status}]  {e.compatWindow}{trust_info}")
    print(f"\n{len(entries)} entries.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="cadence-registry-resolver",
        description="Cadence registry resolver and validator CLI",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # resolve
    p_resolve = subparsers.add_parser("resolve", help="Resolve a registry entry")
    p_resolve.add_argument("kind", help="Entry kind (plugin, policyPack, runtimeProfile, sandboxProfile)")
    p_resolve.add_argument("id", help="Entry ID")
    p_resolve.add_argument("--registry", help="Path to registry.json")
    p_resolve.add_argument("--date", help="Reference date for compat window (YYYY-MM-DD)")

    # validate
    p_validate = subparsers.add_parser("validate", help="Validate registry structure")
    p_validate.add_argument("--registry", help="Path to registry.json")

    # check-integrity
    p_integrity = subparsers.add_parser("check-integrity", help="Check digest integrity")
    p_integrity.add_argument("--registry", help="Path to registry.json")

    # list-deprecated
    p_deprecated = subparsers.add_parser("list-deprecated", help="List deprecated entries")
    p_deprecated.add_argument("--registry", help="Path to registry.json")
    p_deprecated.add_argument("--date", help="Reference date (YYYY-MM-DD)")

    # list
    p_list = subparsers.add_parser("list", help="List entries")
    p_list.add_argument("--kind", help="Filter by kind")
    p_list.add_argument("--status", help="Filter by status")
    p_list.add_argument("--registry", help="Path to registry.json")

    args = parser.parse_args()
    dispatch = {
        "resolve": cmd_resolve,
        "validate": cmd_validate,
        "check-integrity": cmd_check_integrity,
        "list-deprecated": cmd_list_deprecated,
        "list": cmd_list,
    }
    return dispatch[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
