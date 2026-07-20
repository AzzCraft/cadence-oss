# Canonical JSON & Hashing

Cadence relies on content hashes for:
- CAS blobs
- RunManifest/PipelineResult/JobEnvelope integrity
- Remote execution taskId derivation
- Cassette replay integrity

## Rules (recommended)
1. Canonical JSON serialization:
   - stable key ordering
   - UTF-8
   - no insignificant whitespace
2. Hash: `sha256:<hex>`
3. Signatures:
   - may be attached as detached signatures
   - schema keeps `signature` as an opaque string; signing format is an implementation detail (e.g. cosign, x509, JWT)

NOTE: The DAS spec requires that `manifestHash` is **NOT** embedded in the RunManifest payload; it lives in referencing objects (e.g. PipelineResult.manifestRef).
