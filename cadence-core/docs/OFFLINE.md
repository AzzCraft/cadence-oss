# Offline posture (Core)

Cadence Core v1.0.0 does not require network access for its documented
`verify`, `scan`, `adopt`, `report`, `lock`, or `doctor` commands. The Go
verification gate uses the checked-in vendor directory with `GOPROXY=off` and
`GOSUMDB=off`.

This source release does not implement or ship cloud, private-link, intranet
egress-allowlist, registry-mirroring, or Egress Guard modes. Those are not
security guarantees of v1.0.0.

When Cadence starts a supported sandbox or plugin subprocess, it reduces the
environment to the declared allowlist and rejects reserved parent environment
keys. Third-party plugin execution is fail-closed unless an approved isolated
runner is available.
