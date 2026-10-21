#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path


def stable_key(item: dict) -> str:
    return f"{item.get('severity')}|{item.get('ruleId')}|{item.get('file')}|{item.get('line')}"


def scan(content: str) -> list[dict]:
    violations: list[dict] = []
    for idx, line in enumerate(content.splitlines(), start=1):
        if re.search(r"^\s*print\(", line):
            violations.append(
                {
                    "ruleId": "RUFF_T201",
                    "severity": "P2",
                    "message": "print() should not ship in production Python code",
                    "line": idx,
                }
            )
        if re.search(r"^\s*from\s+[\w\.]+\s+import\s+\*", line):
            violations.append(
                {
                    "ruleId": "RUFF_F403",
                    "severity": "P1",
                    "message": "wildcard imports are not allowed",
                    "line": idx,
                }
            )
    return violations


def validate_request(req):
    allowed = {"schemaVersion", "protocolVersion", "repoRoot", "files", "mode", "changedFiles", "config", "constraints", "compat"}
    if not isinstance(req, dict) or set(req) - allowed:
        raise ValueError("invalid plugin request object")
    if req.get("schemaVersion") != "1.0.0" or req.get("protocolVersion") != "1.0.0" or req.get("mode") not in ("scan", "verify"):
        raise ValueError("unsupported plugin schema/protocol version or mode")
    if not isinstance(req.get("repoRoot"), str) or not Path(req["repoRoot"]).is_dir():
        raise ValueError("repoRoot must identify an existing directory")
    for key in ("files", "changedFiles"):
        value = req.get(key, [] if key == "changedFiles" else None)
        if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
            raise ValueError(f"{key} must be an array of strings")
    for key in ("config", "constraints", "compat"):
        if key in req and not isinstance(req[key], dict):
            raise ValueError(f"{key} must be an object")

def main() -> None:
    raw = sys.stdin.read()
    req = json.loads(raw)
    validate_request(req)
    repo_root = Path(req["repoRoot"])
    files = req["files"]
    violations: list[dict] = []
    for rel in files:
        abs_path = repo_root / rel
        content = abs_path.read_text(encoding="utf-8")
        violations.extend({**item, "file": rel.replace("\\", "/")} for item in scan(content))
    response = {
        "schemaVersion": "1.0.0",
        "protocolVersion": str(req.get("protocolVersion") or "1.0.0"),
        "ir": {"irVersion": "1", "modules": [], "edges": []},
        "violations": sorted(violations, key=stable_key),
        "metrics": {"filesScanned": len(files), "bridge": "ruff"},
    }
    sys.stdout.write(json.dumps(response, indent=2) + "\n")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError) as exc:
        print(f"plugin request failed: {exc}", file=sys.stderr)
        raise SystemExit(2)
