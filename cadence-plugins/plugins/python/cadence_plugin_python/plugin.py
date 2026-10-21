#!/usr/bin/env python3
"""Cadence Python plugin.

Reads a PluginRequest JSON on stdin and outputs a PluginResponse JSON on stdout.

This plugin performs a deterministic boundary lint:
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

def main():
    req = json.loads(sys.stdin.read())
    validate_request(req)
    repo_root = Path(req["repoRoot"])
    files = req["files"]

    out_violations = []
    for rel in files:
        abs_path = repo_root / rel
        text = abs_path.read_text(encoding="utf-8")
        for v in scan_imports(text):
            v["file"] = rel.replace("\\", "/")
            out_violations.append(v)

    resp = {
        "schemaVersion": "1.0.0",
        "protocolVersion": str(req.get("protocolVersion") or "1.0.0"),
        "ir": build_ir(files),
        "violations": stable_sorted(out_violations, key=lambda v: f"{v.get('severity')}|{v.get('ruleId')}|{v.get('file')}|{v.get('line')}|{v.get('message')}"),
        "metrics": {"filesScanned": len(files)},
    }
    sys.stdout.write(json.dumps(resp, indent=2) + "\n")

def cli():
    try:
        main()
    except (ValueError, OSError) as exc:
        print(f"plugin request failed: {exc}", file=sys.stderr)
        return 2
    return 0

if __name__ == "__main__":
    raise SystemExit(cli())
