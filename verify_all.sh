#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

step() { echo "[$1] $2"; }

step 1 "cadence-oss/cadence-protocol"
(cd "$ROOT_DIR/cadence-oss/cadence-protocol" && bash ./scripts/verify)

step 2 "cadence-oss/cadence-core"
(cd "$ROOT_DIR/cadence-oss/cadence-core" && bash ./scripts/verify)

step 3 "cadence-oss/cadence-plugins"
(cd "$ROOT_DIR/cadence-oss/cadence-plugins" && bash ./scripts/verify)

step 4 "cadence-oss/cadence-policy-packs"
(cd "$ROOT_DIR/cadence-oss/cadence-policy-packs" && bash ./scripts/verify)

step 5 "cadence-oss/contracts-hub-template"
(cd "$ROOT_DIR/cadence-oss/contracts-hub-template" && bash ./scripts/verify)

step 6 "cadence-oss/cadence-examples (consumer repo)"
(cd "$ROOT_DIR/cadence-oss/cadence-examples" && bash ./scripts/verify)

step 7 "cadence-pro/cadence-ui"
(cd "$ROOT_DIR/cadence-pro/cadence-ui" && bash ./scripts/verify)

step 8 "cadence-pro/cadence-control-plane"
(cd "$ROOT_DIR/cadence-pro/cadence-control-plane" && bash ./scripts/verify)

step 9 "cadence-forge-enterprise/cadence-forge"
(cd "$ROOT_DIR/cadence-forge-enterprise/cadence-forge" && bash ./scripts/verify)

step 10 "cadence-forge-enterprise/cadence-data-evals"
(cd "$ROOT_DIR/cadence-forge-enterprise/cadence-data-evals" && bash ./scripts/verify)

echo "ALL OK"
