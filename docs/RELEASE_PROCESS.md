# Release Process

## Validation gate

`.github/workflows/release.yml` is manual-dispatch only. The dispatch must run
the workflow itself from the default branch and name the exact annotated `v*`
tag in `ref`; the workflow resolves that tag, its tag object, target commit,
and `VERSION` before it runs target code. Tag-source validation has read-only
contents permission only. A separate fresh trusted job re-resolves the same
tag, rebuilds and extracts the source archive without executing tag code, and
only then receives the attestation permissions.
It verifies the public source, runs `govulncheck` for `cadence-core`,
`pip-audit` against the pinned verification lock, and high-severity Bandit
analysis of the public Python surfaces, then produces immutable review
artifacts for that exact commit:

- a deterministic `git archive` source tarball (`gzip -n`),
- a deterministic SPDX 2.3 source inventory generated from the exact commit,
  with tracked-file checksums and a package-verification code,
- a canonical release manifest identifying the tag object, commit, and version, and
- `SHA256SUMS` covering those files.

The workflow uploads those files as a retained Actions artifact and creates a
GitHub artifact provenance attestation for the independently rebuilt source
archive. The attestation is not a substitute for a maintainer's release-tag
signature.

The workflow proves that the tag is annotated and bound to the requested
commit; it does not choose or verify an approved GPG, SSH, or Sigstore signer.
Cryptographic tag verification remains a protected publication gate until the
release owner publishes the approved signer trust policy and evidence.

The generated source inventory records source-tree identity only. It is not a
third-party dependency or license-compliance SBOM, and cannot by itself satisfy
a release-truth-pack dependency or license SBOM requirement.

## Publication

The workflow has read-only repository contents permission and deliberately does
not create a tag, GitHub Release, or remote publication. An authorized release
owner must create the signed immutable `v<version>` tag through the protected
review path first; validation then binds its evidence to that exact tag. After
a green validation run, the owner verifies the uploaded checksums and
provenance and separately creates the GitHub Release. Never publish solely
because a local or CI validation run completed.
