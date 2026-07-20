# Release Units

Cadence OSS v1.1.0 is an eight-unit public source bundle. The positive export
boundary is limited to these unit roots and the root release files:

- `cadence-core` — offline verification runtime and CLI.
- `cadence-protocol` — schemas, canonicalization, and migrations.
- `cadence-plugins` — reviewed, opt-in plugin implementations and manifests.
- `cadence-policy-packs` — reviewed policy packs.
- `contracts-hub-template` — self-verifying contract-hub starter.
- `cadence-examples` — clean-room consumer examples.
- `cadence-sandbox` — sandbox profiles and adapters.
- `cadence-registry` — reviewed local registry indexes and resolver.

The source workspace also contains demos, deployment material, pilots,
training, product scripts, and other non-product areas. They are not part of
the v1.1.0 public export. `scripts/verify` preserves the v1.0 core-only fast
contract; `scripts/verify --full` verifies every listed unit.
