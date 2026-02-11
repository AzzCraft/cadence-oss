#!/usr/bin/env python3
"""Cadence Python plugin (stdlib-only runnable demo)

Reads a PluginRequest JSON on stdin and outputs a PluginResponse JSON on stdout.

This plugin performs a minimal boundary lint:
- flags deep imports that reference /internal/ or /src/ in Python import statements.

It also emits a minimal IR (irVersion=1) that groups modules by top-level folder under src/.

Design goals:
- deterministic output
- no network access
- zero third-party dependencies
"""

import json
import os
import re
import sys
from pathlib import Path

def stable_sorted(items, key):
    return sorted(list(items), key=key)

def scan_imports(text: str):
    violations = []
    lines = text.splitlines()
    for idx, line in enumerate(lines, start=1):
        m = re.search(r"^\s*(from\s+([\w\.]+)\s+import|import\s+([\w\.]+))", line)
        if not m:
            continue
        mod = m.group(2) or m.group(3) or ""
        if ".internal." in mod or mod.endswith(".internal") or ".src." in mod or mod.endswith(".src"):
            violations.append({
                "ruleId": "SDMM_DEEP_IMPORT",
                "severity": "P1",
                "message": f"Deep import detected: {mod}",
                "line": idx,
            })
    return violations

def build_ir(files):
    modules = {}
    for rel in files:
        rel_norm = rel.replace("\\", "/")
        parts = rel_norm.split("/")
        mod = "root"
        if "src" in parts:
            i = parts.index("src")
            if len(parts) > i + 1:
                mod = parts[i + 1]
        mod_id = f"py:{mod}"
        modules.setdefault(mod_id, {"id": mod_id, "path": mod, "type": "module", "owner": "unknown"})
    return {
        "irVersion": "1",
        "modules": stable_sorted(modules.values(), key=lambda m: m["id"]),
        "edges": [],
    }

def main():
    raw = sys.stdin.read()
    try:
        req = json.loads(raw) if raw.strip() else {}
    except Exception:
        req = {"_invalidJson": True}

    repo_root = Path(str(req.get("repoRoot") or os.getcwd()))
    files = [str(x) for x in (req.get("files") or []) if isinstance(x, str)]

    out_violations = []
    for rel in files:
        abs_path = repo_root / rel
        if not abs_path.exists() or not abs_path.is_file():
            continue
        try:
            text = abs_path.read_text(encoding="utf-8")
        except Exception:
            continue
        for v in scan_imports(text):
            v["file"] = rel.replace("\\", "/")
            out_violations.append(v)

    resp = {
        "protocolVersion": str(req.get("protocolVersion") or "1.0.0"),
        "ir": build_ir(files),
        "violations": stable_sorted(out_violations, key=lambda v: f"{v.get('severity')}|{v.get('ruleId')}|{v.get('file')}|{v.get('line')}|{v.get('message')}"),
        "metrics": {"filesScanned": len(files)},
    }
    sys.stdout.write(json.dumps(resp, indent=2) + "\n")

if __name__ == "__main__":
    main()
