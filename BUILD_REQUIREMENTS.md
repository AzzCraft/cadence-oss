# Build Requirements — cadence-oss

## Toolchain

| Tool | Minimum | Purpose |
|------|---------|---------|
| `go` | 1.25.12+ | cadence-core build and security-patched standard library |
| `python3` | 3.10+ | protocol tools, plugin bridge |
| `node` | 20+ | plugin bridge (TS) |
| `bash` | 3.2+ | verify scripts |
| `git` | 2.30+ | version pinning |

## Optional

| Tool | Purpose |
|------|---------|
| `rg` (ripgrep) | accelerated path-safety scans |

If `rg` is not available, verify scripts must fall back to `grep` or fail with an explicit message — never silently skip checks.
