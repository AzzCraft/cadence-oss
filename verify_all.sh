#!/usr/bin/env bash
set -euo pipefail
export PYTEST_ADDOPTS=

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export PYTHONDONTWRITEBYTECODE=1

step() { echo "[$1] $2"; }

command -v go >/dev/null 2>&1 || {
  echo "Go is required; refusing to substitute a verification shim." >&2
  exit 127
}

step 1 "cadence-protocol"
(cd "$ROOT_DIR/cadence-protocol" && bash ./scripts/verify)

step 2 "cadence-plugins"
(cd "$ROOT_DIR/cadence-plugins" && bash ./scripts/verify)

step 3 "cadence-policy-packs"
(cd "$ROOT_DIR/cadence-policy-packs" && bash ./scripts/verify)

step 4 "contracts-hub-template"
(cd "$ROOT_DIR/contracts-hub-template" && bash ./scripts/verify)

step 6 "cadence-core full"
(cd "$ROOT_DIR/cadence-core" && bash ./scripts/verify-full)

step 7 "cadence-examples"
(cd "$ROOT_DIR/cadence-examples" && bash ./scripts/verify)

step 8 "cadence-sandbox"
(cd "$ROOT_DIR/cadence-sandbox" && bash ./scripts/verify)

step 9 "cadence-registry"
(cd "$ROOT_DIR/cadence-registry" && bash ./scripts/verify)

(cd "$ROOT_DIR" && python3 -B -m pytest -q -p no:cacheprovider tests/test_cross_unit.py tests/test_root_verify_modes.py)

echo "ALL OK"
