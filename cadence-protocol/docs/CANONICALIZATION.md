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

## Exact JSON consumer boundary

Generic JCS inputs accept exact IEEE-754 integers and canonical decimal integer
spellings emitted by JCS, so parsing and canonicalizing a finite numeric value
is idempotent. An integer that would silently round to a different value is
rejected; protocol fields declared as safe integers keep their original bounds.
The ordered cassette identity is separately named
`cadence-cassette-ordered/v2:sha256:<hex>`: interaction order affects replay,
whereas object/header key order does not. Do not reinterpret an older sorted
cassette hash as this identity. Ordinary content digests still use `sha256:`.
