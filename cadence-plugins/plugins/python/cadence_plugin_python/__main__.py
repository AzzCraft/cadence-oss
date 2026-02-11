import json, sys, time

def main():
    raw = sys.stdin.read()
    req = json.loads(raw) if raw.strip() else {}
    res = {
        "protocolVersion": req.get("protocolVersion", "1.0"),
        "ir": {"kind": "python", "note": "stub"},
        "violations": [],
        "metrics": {"files": len(req.get("files", [])), "parseMs": 0},
    }
    sys.stdout.write(json.dumps(res))

if __name__ == "__main__":
    main()
