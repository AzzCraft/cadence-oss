# Cadence OSS

Cadence OSS is an offline verification command-line runtime. The current source
candidate is **1.2.0-beta.1**, with reference support for DAS Standard 1.5.0-beta.1.
It includes exact contract consumers, applicability resolution and Linux reference
samples. Final installed beta acceptance and publication remain unfinished.

## What is included

- `cadence-core/` — Go CLI, contract checks, applicability resolution, evidence and replay checks
- `cadence-protocol/` — versioned schemas, fixtures and contract tests
- `cadence-sandbox/reference/das-v1.5/` — controlled Linux execution reference and installation instructions
- `cadence-examples/` — minimal HTTP and UI reference samples
- `scripts/verify` — standalone Go checks and full public-source verification


## Verification

```bash
bash ./scripts/verify
```

## Quickstart

Build both commands from this repository root:

```bash
(cd cadence-core
 go build -mod=vendor -o ../cadence ./cmd/cadence
 go build -mod=vendor -o ../evidence-verify ./cmd/evidence-verify)
./cadence version --json
```

Run verification inside the project containing `cadence.yaml`. When switching
projects, use absolute binary paths (the build does not install anything on PATH):

```bash
CADENCE_BIN="$PWD/cadence"
EVIDENCE_VERIFY_BIN="$PWD/evidence-verify"
cd "$PROJECT_DIR"  # set to the project containing cadence.yaml
"$CADENCE_BIN" verify
RUN_BUNDLE="$PWD/.cadence/out/latest/evidence-bundle.json"
"$EVIDENCE_VERIFY_BIN" --profile cadence-run/v2 --bundle "$RUN_BUNDLE"
```

For an existing bundle while still at this repository root, use
`./evidence-verify --profile cadence-run/v2 --bundle "$RUN_BUNDLE"`.
Default verify runs use a stable input-derived prefix and a fresh random suffix;
repeated inputs get independent attempt directories. Explicit duplicate `--run-id`
values still fail. Input hashes, snapshot identity and replay-plan hashes remain
stable for the same inputs; attempt IDs and time-bearing evidence may differ.

Run `bash ./scripts/verify --standalone` for the Go checks. The default full
verification also covers protocol and sandbox tests; actual Linux runtime tests
need the explicit prerequisites described in the reference installation guide.
A skipped runtime test does not prove installed isolation.

The core CLI does not execute arbitrary third-party plugins. The separate Linux
reference controller runs only its declared bounded workloads and requires
installation-side configuration and permissions. Contract checks and a successful
source test do not authorize an operation or qualify a deployment. Replay
comparison requires separate expected and actual bundles.

DAS Standard remains independently readable and distributable. These tools check
machine-verifiable conditions; developers implement changes, and the adopting
project supplies any required approvals and deployment controls.

## Native evidence profiles and delivery

`./evidence-verify --profile cadence-run/v2 --bundle <run>/evidence-bundle.json`
consumes current native inventory `cadence-evidence-bundle/v2`. It uses bounded,
root-confined reads and per-file SHA-256 hashes with sorted path/NUL/digest/LF
aggregation. The inventory binds the legacy native step-chain profile plus all
primary files. Derived replay/signature files are excluded to avoid circular
hashes; they have their own bindings. Explicit `cadence-run/v1` reads historical
native inventories under the historical digest semantics. Default `cad002/v1`
is the separate CAD-002 chain diagnostic; it does not consume native inventories
or the protocol bundle descriptor. Unknown/mixed formats and empty chains fail.
Integrity checks do not authenticate signers, approve a run or grant authority.

With `cadence-protocol/requirements-verify.txt` installed, the Python helper
`python3 cadence-protocol/tools/validate_artifacts.py --profile native-inventory/v2 <run>`
checks only the inventory schema. Use the Go reader above for file/chain integrity.
The Python helper's default `protocol/v1` retains the historical protocol objects'
timestamp/budget requirements; those objects are not the native CLI's run profile.
No input selects a weaker check implicitly.

A verify run requires complete primary evidence and both replay files. Any required
write/check/signature failure exits nonzero and retains diagnostics. `latest`
advances only after successful checks and delivery, using an atomic symlink to an
immutable fresh run. Existing run IDs are not overwritten. When upgrading an old
directory-form alias, stop writers and move the old directory to a retained backup
before using the new pointer. A refusal preserves the previous directory unchanged.

Persisted waivers must satisfy the current policy, role order, record binding and
distinct-principal metadata. Required stage orders are requester/approver (check),
requester/manager/security[-lead] (tier1), and requester/manager/security[-lead]/
approver-or-exec (tier2/profile). Self-reported identities or signature text do not
authenticate approval. Governed mode refuses this metadata-only override; use a
trusted protected approval consumer. Explicit legacy inline break-glass retains
its warning/non-compliant semantics and is not authenticated production approval.

A root-anchor URI is configuration, not proof of an active HSM/KMS. Current writers
emit a v1 software anchor only after using and verifying a concrete local software
signer. External signer hardware custody is unknown and produces no hardware anchor.
This release does not implement a verified hardware-provider attestation adapter;
installations requiring hardware must not treat an absent anchor as satisfying it.

### Product and Suite tooling locks

A closure with `repoToolingLock` selects the product lock for native alignment;
legacy closures without it retain their single-lock behavior. The preserved
Suite tooling lock and its local references are validated in the Suite subtree.
The `scaffold-v15` policy entry is explicitly metadata-only: it selects the
existing core checks and adds no DAS compliance or UI execution capability.
