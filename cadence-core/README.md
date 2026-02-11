# cadence-core

Cadence **offline deterministic** Core CLI (Go).

## Goals
- Provide a single canonical entrypoint per repo: `./cadencew verify`
- Deterministic, reproducible, auditable results
- Plugin-driven language support (batch protocol)
- Evidence artifacts aligned to DAS: RunManifest / PipelineResult / JobEnvelope

## Non-goals
- Embedding browsers / Playwright (belongs to cadence-ui `ui-runner`)
- Letting LLM decide pass/fail (AI can only propose patches, governed by Cassette replay)

## Quick start (dev)
```bash
go test ./...
go run ./cmd/cadence --help
```

Generated: 2026-01-26 (UTC)
