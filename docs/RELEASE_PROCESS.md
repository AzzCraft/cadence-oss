# Release Process

Cadence OSS releases are root-bundled but subunit-verified.

Release checklist:

1. Run `bash ./scripts/verify` from the repo root.
2. Ensure `cadence-core/scripts/verify-full` is green.
3. Ensure protocol schema/examples/compat tooling are green.
4. Ensure policy packs and examples no longer reference the legacy unified baseline name.
5. Publish the root bundle only after all local subunits pass.
