# Build Requirements — Cadence OSS Core v1.0.0

| Tool | Minimum | Purpose |
| --- | --- | --- |
| `go` | 1.25.12 | build, vet, and test Cadence Core using vendored modules |
| `python3` | 3.10 | public helper scripts and the complete test suite |
| `pytest` | current compatible release | only `scripts/verify --full` |
| `bash` | 3.2 | verifier and helper scripts |

No Node.js, external Cadence unit, sibling checkout, network access, or Git
metadata is required to build or verify the core-only source archive.
