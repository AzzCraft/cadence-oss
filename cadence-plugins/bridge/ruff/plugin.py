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


def main() -> None:
    raw = sys.stdin.read()
    req = json.loads(raw) if raw.strip() else {}
    repo_root = Path(str(req.get("repoRoot") or os.getcwd()))
    files = [str(item) for item in (req.get("files") or []) if isinstance(item, str)]
    violations: list[dict] = []
    for rel in files:
        abs_path = repo_root / rel
        if not abs_path.exists() or not abs_path.is_file():
            continue
        content = abs_path.read_text(encoding="utf-8")
        violations.extend({**item, "file": rel.replace("\\", "/")} for item in scan(content))
    response = {
        "protocolVersion": str(req.get("protocolVersion") or "1.0.0"),
        "ir": {"irVersion": "1", "modules": [], "edges": []},
        "violations": sorted(violations, key=stable_key),
        "metrics": {"filesScanned": len(files), "bridge": "ruff"},
    }
    sys.stdout.write(json.dumps(response, indent=2) + "\n")


if __name__ == "__main__":
    main()
