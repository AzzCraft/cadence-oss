# Release Process — Core-only v1.0.0

1. Run `bash ./scripts/verify --full` from an arbitrary checkout basename.
2. Build the source archive, extract it beneath a fresh arbitrary parent, and
   run the same full verifier inside the extracted `cadence-oss-v1.0.0` root.
3. Generate the SPDX SBOM, provenance, checksums, and export receipt from the
   pinned source commit and descriptor.
4. Run the public-boundary, license, dependency, vulnerability, and
   reproducibility checks twice. The two generated candidates and artifacts
   must match.
5. Obtain the required independent, legal, hosted-CI, signing, and publication
   approvals before pushing, tagging, or publishing.

This release procedure applies only to Cadence Core. It does not claim an
all-unit Cadence bundle.
