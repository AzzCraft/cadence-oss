# Security notes (scaffold)

This repo is a scaffold. Production-grade Cadence Core should include:
- supply chain signing verification for binaries/plugins (e.g. cosign)
- SBOM generation (CycloneDX/SPDX)
- secret/PII scrubbing before any artifact egress
- deterministic hashing & canonical JSON
- registry mirroring for enterprises (no direct public fetch in restricted networks)
