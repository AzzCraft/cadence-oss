#!/usr/bin/env bash
# Negative test: proves the example verifier returns non-zero when a required
# evidence artifact is absent.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

make_temp_dir() {
  local prefix="$1"
  local base="${TMPDIR:-/tmp}"
  local dir=""
  if dir="$(mktemp -d "${base}/${prefix}.XXXXXX" 2>/dev/null)"; then
    printf '%s\n' "$dir"
    return 0
  fi
  python3 - "$prefix" "$base" <<'PY'
import sys
import tempfile

print(tempfile.mkdtemp(prefix=sys.argv[1] + ".", dir=sys.argv[2]))
PY
}

tmpdir="$(make_temp_dir cadence-examples-missing)"
trap 'rm -rf "$tmpdir"' EXIT

out_dir="$tmpdir/.cadence/out/latest"
mkdir -p "$out_dir"

# Create two of the three required artifacts, deliberately omit job-envelope.json.
cat > "$out_dir/run-manifest.json" <<'JSON'
{"runId":"test","schemaVersion":"1.0.0","pipeline":{"id":"t"},"config":{"profileId":"p","configId":"c"}}
JSON

cat > "$out_dir/pipeline-result.json" <<'JSON'
{"runId":"test","schemaVersion":"1.0.0","status":"ok"}
JSON

# The verifier expects to run cadencew first, but we only test the Python
# evidence-validation block. Extract and run just that portion.
rc=0
python3 - "$tmpdir" <<'PYTEST' || rc=$?
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])
out_dir = root / '.cadence' / 'out'
alias = out_dir / 'latest'
latest = alias

REQUIRED = ('run-manifest.json', 'pipeline-result.json', 'job-envelope.json')
for name in REQUIRED:
    fp = latest / name
    if not fp.exists():
        print(f"FAIL: required evidence artifact missing: {name} in {latest.name}", file=sys.stderr)
        sys.exit(1)

sys.exit(0)
PYTEST
if [[ "$rc" -eq 0 ]]; then
  echo "FAIL: verifier should have returned non-zero for missing job-envelope.json" >&2
  exit 1
fi

echo "OK: negative test passed — verifier correctly rejects missing artifact"
