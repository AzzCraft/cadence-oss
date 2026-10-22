"""Registry resolver — load, lookup, and resolve registry entries.

Mirrors the semantics of cadence-core/internal/registry/registry.go
as a standalone Python module within cadence-registry itself.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field, fields
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
COMPAT_WINDOW_RE = re.compile(
    r"^(current|until \d{4}-\d{2}-\d{2}|from \d{4}-\d{2}-\d{2} to \d{4}-\d{2}-\d{2})$"
)

ALLOWED_KINDS = {"plugin", "policyPack", "runtimeProfile", "sandboxProfile"}
ALLOWED_STATUSES = {"active", "deprecated", "removed"}


def _closed_fields(cls, data):
    allowed = {item.name for item in fields(cls)}
    if not isinstance(data, dict) or set(data) != allowed:
        raise ValueError(f"{cls.__name__} has missing, unknown or incorrectly cased fields")


def _unique_members(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate decoded registry field")
        result[key] = value
    return result


def _invalid_constant(value):
    raise ValueError("invalid JSON constant in registry")


@dataclass
class Trust:
    signer: str = ""
    allowlisted: bool = False

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> Trust | None:
        if data is None:
            return None
        _closed_fields(cls, data)
        return cls(signer=data.get("signer", ""), allowlisted=data.get("allowlisted", False))


@dataclass
class Entry:
    kind: str = ""
    id: str = ""
    ref: str = ""
    version: str = ""
    status: str = ""
    digest: str = ""
    deprecatedAt: str | None = None
    deprecationReason: str | None = None
    compatWindow: str = ""
    trust: Trust | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Entry:
        _closed_fields(cls, data)
        return cls(
            kind=data.get("kind", ""),
            id=data.get("id", ""),
            ref=data.get("ref", ""),
            version=data.get("version", ""),
            status=data.get("status", ""),
            digest=data.get("digest", ""),
            deprecatedAt=data.get("deprecatedAt"),
            deprecationReason=data.get("deprecationReason"),
            compatWindow=data.get("compatWindow", ""),
            trust=Trust.from_dict(data.get("trust")),
        )


@dataclass
class Resolution:
    entry: Entry
    resolved_ref: str
    warnings: list[str] = field(default_factory=list)


@dataclass
class Registry:
    schemaVersion: str = ""
    registryId: str = ""
    entries: list[Entry] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Registry:
        _closed_fields(cls, data)
        if not isinstance(data.get("entries"), list):
            raise ValueError("registry must be an object with an entries array")
        return cls(
            schemaVersion=data.get("schemaVersion", ""),
            registryId=data.get("registryId", ""),
            entries=[Entry.from_dict(e) for e in data.get("entries", [])],
        )


def load(path: str | Path) -> Registry:
    """Load a registry from a JSON file."""
    from .validate import validate
    data = json.loads(Path(path).read_text(encoding="utf-8"),
                      object_pairs_hook=_unique_members, parse_constant=_invalid_constant)
    registry = Registry.from_dict(data)
    errors = validate(registry)
    if errors:
        raise ValueError("; ".join(errors))
    return registry


def lookup(registry: Registry, kind: str, entry_id: str) -> Entry:
    """Find an entry by kind and ID. Raises ValueError if not found."""
    for e in registry.entries:
        if e.kind == kind and e.id == entry_id:
            return e
    raise ValueError(f"registry: entry not found: kind={kind} id={entry_id}")


def lookup_by_kind(registry: Registry, kind: str) -> list[Entry]:
    """Return all entries of the given kind."""
    return [e for e in registry.entries if e.kind == kind]


def file_digest(path: str | Path) -> str:
    """Compute sha256 digest of a file."""
    data = Path(path).read_bytes()
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _parse_date(raw: str) -> date:
    return datetime.strptime(raw.strip(), "%Y-%m-%d").date()


@dataclass
class CompatPolicy:
    kind: str  # "current", "until", "range"
    start: date | None = None
    end: date | None = None

    def contains(self, ref_date: date) -> bool:
        if self.kind == "current":
            return True
        if self.start and ref_date < self.start:
            return False
        if self.end and ref_date > self.end:
            return False
        return True


def parse_compat_window(raw: str) -> CompatPolicy:
    """Parse a compatWindow string into a CompatPolicy."""
    value = raw.strip()
    if not COMPAT_WINDOW_RE.match(value):
        raise ValueError(f"invalid compatWindow: {value!r}")
    if value == "current":
        return CompatPolicy(kind="current")
    if value.startswith("until "):
        end = _parse_date(value.removeprefix("until "))
        return CompatPolicy(kind="until", end=end)
    if value.startswith("from "):
        body = value.removeprefix("from ")
        parts = body.split(" to ")
        if len(parts) != 2:
            raise ValueError(f"invalid range: {value!r}")
        start = _parse_date(parts[0])
        end = _parse_date(parts[1])
        if end < start:
            raise ValueError(f"range end before start: {value!r}")
        return CompatPolicy(kind="range", start=start, end=end)
    raise ValueError(f"unsupported compatWindow: {value!r}")


def resolve_entry(
    registry_path: str | Path,
    registry: Registry,
    kind: str,
    entry_id: str,
    reference_date: date | None = None,
) -> Resolution:
    """Resolve an entry by kind+ID, validate digest, and check compat window."""
    from .validate import validate
    errors = validate(registry)
    if errors:
        raise ValueError("; ".join(errors))
    entry = lookup(registry, kind, entry_id)
    return _resolve_entry(Path(registry_path), entry, reference_date or datetime.now(timezone.utc).date())


def _resolve_entry(
    registry_path: Path,
    entry: Entry,
    reference_date: date | None = None,
) -> Resolution:
    """Internal resolve for a single entry."""
    resolved_ref = str((registry_path.parent / entry.ref).resolve())
    resolution = Resolution(entry=entry, resolved_ref=resolved_ref)

    if entry.status == "removed":
        raise ValueError(f"registry: {entry.kind}/{entry.id} is removed and cannot be used")
    if entry.status == "deprecated":
        reason = entry.deprecationReason or "no reason given"
        resolution.warnings.append(
            f"registry dependency {entry.kind}/{entry.id} is deprecated: {reason} "
            f"(compatWindow={entry.compatWindow})"
        )

    # Check target exists
    target = Path(resolved_ref)
    if not target.exists():
        raise ValueError(f"registry: {entry.kind}/{entry.id} target missing: {resolved_ref}")

    # Trust check
    if entry.trust is None:
        raise ValueError(f"registry: {entry.kind}/{entry.id} missing trust metadata")
    if not entry.trust.allowlisted:
        raise ValueError(
            f"registry: {entry.kind}/{entry.id} signer {entry.trust.signer!r} is not allowlisted"
        )

    # Digest check
    if entry.digest:
        if target.is_dir():
            raise ValueError(
                f"registry: {entry.kind}/{entry.id} digest requires a file target, got directory"
            )
        actual = file_digest(resolved_ref)
        if actual != entry.digest:
            raise ValueError(
                f"registry: {entry.kind}/{entry.id} digest mismatch: want {entry.digest} got {actual}"
            )

    # Compat window enforcement
    if reference_date is not None and entry.compatWindow:
        policy = parse_compat_window(entry.compatWindow)
        if policy.kind != "current" and not policy.contains(reference_date):
            raise ValueError(
                f"registry: {entry.kind}/{entry.id} compatWindow {entry.compatWindow!r} "
                f"does not cover reference date {reference_date.isoformat()}"
            )

    return resolution


def list_entries(
    registry: Registry,
    kind: str | None = None,
    status: str | None = None,
) -> list[Entry]:
    """List entries, optionally filtered by kind and/or status."""
    result = []
    for e in registry.entries:
        if kind and e.kind != kind:
            continue
        if status and e.status != status:
            continue
        result.append(e)
    return result


def search_by_digest(registry: Registry, digest: str) -> list[Entry]:
    """Find entries by digest value."""
    return [e for e in registry.entries if e.digest == digest]


def list_deprecated(registry: Registry) -> list[Entry]:
    """Return all deprecated entries."""
    return list_entries(registry, status="deprecated")
