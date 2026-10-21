# Security notes

Core performs offline built-in checks and emits evidence for the selected profile.
A passing scan is not proof of production isolation, a fresh execution, or an
identified approver. See [signing](SIGNING.md), [replay](REPLAY.md), and
[waiver boundaries](WAIVERS.md) for the supported contracts.

## Evidence integrity and authentication

- Automatic run IDs combine an input-derived prefix with a fresh attempt suffix.
  Neither the ID nor matching hashes proves that work was re-executed.
- Native evidence inventory binds listed artifact bytes. The v2 reader also binds
  fixed step outputs and defined step inputs to the corresponding run artifacts.
  An unsigned attacker can rebuild hashes; integrity alone is not authentication.
- Development mode may be unsigned or use the documented development HMAC mode.
  Governed signing uses Ed25519 or the configured external signer and trust inputs;
  successful signing must not be inferred from the presence of a JSON filename.
- `key-hierarchy.json` records declared key configuration. It is not itself a
  verified certificate chain. Signature/anchor artifacts are conditional on the
  actual selected signing mode and its success.
- Sandbox results and isolation probes report their observed backend and failures.
  Host-local/configuration-only results do not prove container or microVM isolation.

## Built-in scanning

The baseline scanner checks private key material, common AWS/GCP/GitHub token
patterns, hardcoded credentials, JWT patterns, deep imports and contract fixture
presence. These conservative checks can miss secrets and can produce false
positives; they do not scrub all files or authorize artifact egress. Review the
actual export allowlist and public-content checks before publishing.

Registry checks bind selected dependency bytes and compatibility windows. Policy
pack metadata is not an executed policy engine; see [configuration](CONFIG.md).
Source and binary release attestations are separate from individual verify-run
signatures. This repository does not supply adopter production operations.
