# Build Requirements — Cadence OSS v1.1.0

| Tool | Minimum | Purpose |
| --- | --- | --- |
| `go` | 1.25.12 | build, vet, and test Cadence Core using vendored modules |
| `python3` | 3.10 | public helper scripts and the complete test suite |
| `pytest` | 9.0.3 | shipped Python test suites (pinned in `requirements-verify.txt`) |
| `node` | current LTS | TypeScript plugin/example smoke checks in `--full` mode |
| `bash` | 3.2 | verifier and helper scripts |

Once the listed prerequisites are installed, no sibling checkout, network
access, or Git metadata is required. Node.js is only needed for the expanded
all-unit `--full` gate; the v1.0-compatible fast core gate requires no Node.js
or optional Cadence unit.
