# Release Process — Cadence OSS v1.1.0

1. Run `bash ./scripts/verify` and `bash ./scripts/verify --full` from an
   arbitrary checkout basename. The default gate preserves the v1.0 Cadence
   Core contract; the full gate verifies every v1.1 public unit.
2. Build the source archive, extract it beneath a fresh arbitrary parent, and
   run the same full verifier inside the extracted `cadence-oss-v1.1.0` root.
3. Generate the SPDX SBOM, provenance, checksums, and export receipt from the
   pinned source commit and descriptor.
4. Run the public-boundary, license, dependency, vulnerability, and
   reproducibility checks twice. The two generated candidates and artifacts
   must match.
5. Obtain the required independent, legal, hosted-CI, signing, and publication
   approvals before pushing, tagging, or publishing.

The v1.1.0 positive export boundary is the eight units listed in
`RELEASE_UNITS.md`. Source-workspace demos, deployment material, pilots,
training, product scripts, and other non-product areas are deliberately not
part of the public archive.
