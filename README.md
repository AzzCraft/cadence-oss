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

Build the CLI from this repository:

```bash
cd cadence-core
go build -mod=vendor -o ../cadence ./cmd/cadence
../cadence version --json
```

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
