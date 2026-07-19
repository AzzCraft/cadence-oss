# Security notes

Cadence Core is designed to run offline and emit deterministic evidence. The maintained security posture for this repo includes:
- supply chain signing verification for binaries/plugins (e.g. cosign)
- SBOM generation (CycloneDX/SPDX)
- secret/PII scrubbing before any artifact egress
- deterministic hashing & canonical JSON
- registry mirroring for enterprises (no direct public fetch in restricted networks)

## Threat Model

| Threat                          | Mitigation                                              |
|---------------------------------|---------------------------------------------------------|
| Tampered evidence               | HMAC-SHA256 signing + hash chain verification           |
| Replay without re-execution     | Deterministic RunID derived from governed inputs        |
| Secret leakage in evidence      | Secret scan rules (SEC_*) reject detected credentials   |
| Key compromise                  | Key hierarchy with rotation-ready structure             |
| Waiver abuse                    | Scope constraints, max duration, no self-approval       |
| Sandbox escape                  | Escape classification + runtime isolation probe + namespace proof chain |
| Non-reproducible runs           | Environment spec captures OS, arch, compiler, cgroup    |
| Stale dependencies              | Compat-window enforcement via ResolveEntryAt            |

## Secret Scanning Rules

The built-in baseline scanner detects:
- AWS access keys (`AKIA...`)
- GCP API keys (`AIza...`)
- GitHub tokens (`ghp_...`, `ghs_...`)
- Private key material (PEM headers)
- Hardcoded passwords/secrets/tokens
- JWT tokens

See `internal/checks/rules.go` for the full rule set.

## Evidence Integrity

Every verify run produces:
- `input-identity.json` — governed input hash over source tree, config, env-spec
- `isolation-probe.json` — kernel-level fence detection evidence plus namespace proof descriptors
- `key-hierarchy.json` — signing key chain-of-trust
- `job-envelope.json` — HMAC-signed result envelope
- `sandbox-result.json` — sandbox execution attestation

The hash chain (`internal/signing.Chain`) links steps so tampering with any
intermediate artifact invalidates the chain.
