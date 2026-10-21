"""Registry validator — structural and semantic validation of registry data.

Provides standalone validation matching cadence-core/internal/registry Validate()
and ValidateIntegrity() semantics.
"""

from __future__ import annotations

import json
from datetime import date, datetime
from pathlib import Path
from typing import Any

from .resolve import (
    ALLOWED_KINDS,
    ALLOWED_STATUSES,
    SHA256_RE,
    CompatPolicy,
    Entry,
    Registry,
    file_digest,
    load,
    parse_compat_window,
)


def validate(registry: Registry) -> list[str]:
    """Validate registry structure and semantic consistency.

    Returns a list of error messages. Empty list means valid.
    """
    errors: list[str] = []

    for name in ("registryId", "schemaVersion"):
        if not isinstance(getattr(registry, name), str) or not getattr(registry, name).strip():
            errors.append(f"{name} must be a nonempty string")

    seen: set[str] = set()
    for i, entry in enumerate(registry.entries):
        prefix = f"entry[{i}]"
        bad_type = False
        for name in ("kind", "id", "ref", "version", "status", "digest", "compatWindow"):
            if not isinstance(getattr(entry, name), str):
                errors.append(f"{prefix}: {name} must be a string")
                bad_type = True
        for name in ("deprecatedAt", "deprecationReason"):
            if getattr(entry, name) is not None and not isinstance(getattr(entry, name), str):
                errors.append(f"{prefix}: {name} must be a string or null")
                bad_type = True
        if entry.trust is not None and (not isinstance(entry.trust.signer, str) or type(entry.trust.allowlisted) is not bool):
            errors.append(f"{prefix}: trust requires a string signer and boolean allowlisted")
            bad_type = True
        if bad_type:
            continue
        if not entry.version.strip():
            errors.append(f"{prefix}: version is required")

        if not entry.kind:
            errors.append(f"{prefix}: missing kind")
        elif entry.kind not in ALLOWED_KINDS:
            errors.append(f"{prefix}: invalid kind {entry.kind!r}")

        if not entry.id:
            errors.append(f"{prefix}: missing id")

        if not entry.ref.strip():
            errors.append(f"{prefix}: missing ref")

        if entry.status not in ALLOWED_STATUSES:
            errors.append(f"{prefix}: invalid status {entry.status!r}")

        if not entry.digest.strip():
            errors.append(f"{prefix}: digest is required")
        elif not SHA256_RE.match(entry.digest):
            errors.append(f"{prefix}: digest must be sha256:..., got {entry.digest!r}")

        if not entry.compatWindow.strip():
            errors.append(f"{prefix}: compatWindow is required")
        else:
            try:
                policy = parse_compat_window(entry.compatWindow)
            except ValueError:
                errors.append(f"{prefix}: invalid compatWindow {entry.compatWindow!r}")
                policy = None

            # Status/compat consistency
            if policy is not None:
                if entry.status == "active" and policy.kind != "current":
                    errors.append(f"{prefix}: active status requires compatWindow=current")
                if entry.status in ("deprecated", "removed") and policy.kind == "current":
                    errors.append(
                        f"{prefix}: {entry.status} status requires a bounded compatWindow"
                    )

        if entry.trust is None:
            errors.append(f"{prefix}: trust metadata is required")
        elif not entry.trust.signer.strip():
            errors.append(f"{prefix}: trust.signer is required")

        # Deprecation consistency
        if entry.status == "active":
            if entry.deprecatedAt is not None and entry.deprecatedAt.strip():
                errors.append(f"{prefix}: active status requires deprecatedAt=null")
            if entry.deprecationReason is not None and entry.deprecationReason.strip():
                errors.append(f"{prefix}: active status requires deprecationReason=null")
        elif entry.status in ("deprecated", "removed"):
            if not entry.deprecatedAt or not entry.deprecatedAt.strip():
                errors.append(f"{prefix}: {entry.status} status requires deprecatedAt")
            if not entry.deprecationReason or not entry.deprecationReason.strip():
                errors.append(f"{prefix}: {entry.status} status requires deprecationReason")

        key = f"{entry.kind}:{entry.id}"
        if key in seen:
            errors.append(f"duplicate entry {key}")
        seen.add(key)

    return errors


def validate_integrity(registry: Registry, registry_dir: str | Path) -> list[str]:
    """Validate that all entry digests match the actual files on disk.

    Returns a list of error messages. Empty list means all digests match.
    """
    errors: list[str] = []
    base = Path(registry_dir)

    for entry in registry.entries:
        if not entry.digest:
            continue
        art_path = base / entry.ref
        if not art_path.exists():
            errors.append(
                f"{entry.kind}/{entry.id}: cannot read artifact {entry.ref}"
            )
            continue
        if art_path.is_dir():
            errors.append(
                f"{entry.kind}/{entry.id}: digest requires file target, got directory"
            )
            continue
        actual = file_digest(str(art_path))
        if actual != entry.digest:
            errors.append(
                f"{entry.kind}/{entry.id}: digest mismatch: expected {entry.digest}, got {actual}"
            )

    return errors


def validate_index_consistency(
    registry_path: str | Path,
    indexes_dir: str | Path,
) -> list[str]:
    """Validate that root registry entries are consistent with index entries.

    Checks that each root registry entry has a matching index entry with
    consistent metadata (version, status, digest, trust, deprecation, compatWindow).
    """
    errors: list[str] = []
    registry = load(registry_path)
    indexes_dir = Path(indexes_dir)

    # Collect all indexed entries
    indexed: dict[tuple[str, str], dict[str, Any]] = {}
    for index_path in sorted(indexes_dir.glob("*.json")):
        data = json.loads(index_path.read_text(encoding="utf-8"))
        for entry_data in data.get("entries", []):
            key = (entry_data["kind"], entry_data["id"])
            indexed[key] = entry_data

    for entry in registry.entries:
        key = (entry.kind, entry.id)
        if key not in indexed:
            errors.append(f"{entry.kind}/{entry.id}: not found in any index")
            continue
        idx_entry = indexed[key]
        for field_name in ("version", "status", "digest", "deprecatedAt", "deprecationReason", "compatWindow"):
            reg_val = getattr(entry, field_name)
            idx_val = idx_entry.get(field_name)
            if reg_val != idx_val:
                errors.append(
                    f"{entry.kind}/{entry.id}: {field_name} mismatch: "
                    f"registry={reg_val!r}, index={idx_val!r}"
                )

    return errors


def check_deprecation_gates(
    registry: Registry,
    reference_date: date | None = None,
) -> list[str]:
    """Check deprecation gate enforcement.

    Returns warnings for deprecated entries and errors for entries whose
    compat window has expired.
    """
    messages: list[str] = []
    ref = reference_date or date.today()

    for entry in registry.entries:
        if entry.status == "deprecated":
            messages.append(
                f"WARNING: {entry.kind}/{entry.id} deprecated "
                f"since {entry.deprecatedAt}: {entry.deprecationReason}"
            )
            try:
                policy = parse_compat_window(entry.compatWindow)
                if not policy.contains(ref):
                    messages.append(
                        f"ERROR: {entry.kind}/{entry.id} compat window "
                        f"{entry.compatWindow} has expired as of {ref.isoformat()}"
                    )
            except ValueError:
                messages.append(
                    f"ERROR: {entry.kind}/{entry.id} has invalid compatWindow "
                    f"{entry.compatWindow!r}"
                )
        elif entry.status == "removed":
            messages.append(
                f"ERROR: {entry.kind}/{entry.id} is removed and cannot be used"
            )

    return messages
