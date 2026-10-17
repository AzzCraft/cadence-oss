# Changelog — cadence-sandbox

All notable changes to cadence-sandbox will be documented in this file.

## Unreleased

- Removed the mutable container-image fallback and hardened container launch
  controls: digest-only image identity, non-root/read-only execution, dropped
  capabilities, no-new-privileges, no network, bounded resources, explicit
  environment allowlists, and validated workspace/output mounts.
- Marked the microVM profile as a disabled compatibility specification until a
  guest-executed, trusted receipt implementation is available. Host post-exit
  probes are no longer documented as guest evidence.

## [1.0.0] — 2026-04-09

### Added
- Initial release as internal unit within cadence-oss.
- scripts/verify and verification surfaces.
- Docs and schema definitions.
