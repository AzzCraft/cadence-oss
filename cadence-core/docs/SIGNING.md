# Signing and Step Hash Chain

## Overview

The signing package provides two signing modes for evidence envelopes:

- **Dev mode** (`CADENCE_SIGNING_MODE=dev`): HMAC-SHA256 with a shared key — suitable for local development and CI.
- **Governed mode** (`CADENCE_SIGNING_MODE=governed`): Ed25519 asymmetric signing with configured key hierarchy references.

A step hash chain links individual check/plugin execution steps into a verifiable chain.

## Signing Modes

### Dev Mode (HMAC-SHA256)

Uses `HMACSigner` with a pre-shared key passed via `CADENCE_SIGNING_KEY`.

```json
{
  "schemaVersion": "1.0.0",
  "signatureId": "<unique-id>",
  "algorithm": "hmac-sha256",
  "signer": "<signer-identity>",
  "payloadHash": "sha256:<hex-of-payload>",
  "signature": "<hex-hmac>"
}
```

### Governed Mode (Ed25519)

Uses a local `Ed25519Signer` or an external signer with an explicitly configured verification key. Choosing this mode does not establish production approval or hardware custody.

```json
{
  "schemaVersion": "1.0.0",
  "signatureId": "<unique-id>",
  "algorithm": "ed25519",
  "keyId": "<leaf-key-id>",
  "issuer": "<issuer-identity>",
  "payloadHash": "sha256:<hex-of-payload>",
  "signature": "<hex-ed25519-sig>"
}
```

Signer selection is controlled by `SelectSigner()` which reads `CADENCE_SIGNING_MODE`:

| CADENCE_SIGNING_MODE | Signer | Algorithm | Key Source |
|---|---|---|---|
| `dev` (default) | `HMACSigner` | hmac-sha256 | `CADENCE_SIGNING_KEY` env var |
| `governed` | `Ed25519Signer` or `ExternalCommandSigner` | ed25519 | Explicit key material or an external HSM/KMS wrapper command |

Governed mode is fail-closed:

- `CADENCE_ROOT_ANCHOR` or `cadence.yaml#rootAnchor` must be explicitly set; `operator-local` is rejected.
- One of the following signer paths must be configured:
  - `CADENCE_GOVERNED_SIGNING_PRIVATE_KEY` or `CADENCE_GOVERNED_SIGNING_PRIVATE_KEY_FILE`
  - `CADENCE_GOVERNED_SIGNER_COMMAND` plus `CADENCE_GOVERNED_SIGNING_PUBLIC_KEY` or `CADENCE_GOVERNED_SIGNING_PUBLIC_KEY_FILE`
- Optional overrides:
  - `CADENCE_GOVERNED_ROOT_KEY_ID`
  - `CADENCE_GOVERNED_INTERMEDIATE_KEY_ID`
  - `CADENCE_GOVERNED_LEAF_KEY_ID`

Key material may be provided as raw 32/64-byte data, hex, or base64.

### External HSM/KMS Signer Command

`ExternalCommandSigner` is the concrete runtime integration path for hardware-backed or managed signers.
The configured command is invoked once per signature with the payload hash as argv[1], and these environment
variables are set:

- `CADENCE_PAYLOAD_HASH`
- `CADENCE_KEY_ID`
- `CADENCE_ISSUER`

The command must print a single hex-encoded Ed25519 signature to stdout and exit `0`.
This allows operators to front HSM/KMS providers with a governed wrapper binary while keeping local verification
bound to the configured public key.

## Step Hash Chain

The step hash chain links each execution step (check rule, plugin invocation) into a
tamper-evident chain:

```
Step 0: chainHash = SHA256(genesisHash + ":" + inputHash + ":" + outputHash)
Step 1: chainHash = SHA256(step0.chainHash + ":" + inputHash + ":" + outputHash)
...
```

- The genesis hash is a zero-padded SHA-256 string.
- Each step records: stepIndex, stepID, inputHash, outputHash, previousHash, chainHash.
- `signing.VerifyChain()` re-computes every chain hash and validates linkage.

## Key Hierarchy

### Dev Hierarchy (depth 1)

In dev mode, the hierarchy is flat — a single operator-managed key serves as both root and leaf:

```json
{
  "schemaVersion": "1.0.0",
  "depth": 1,
  "levels": [
    {
      "level": 0,
      "role": "root-and-leaf",
      "algorithm": "hmac-sha256",
      "keyId": "<runner-binary-digest>",
      "anchor": "operator-local"
    }
  ],
  "leafKeyId": "<runner-binary-digest>",
  "rootAnchor": "operator-local"
}
```

### Governed Hierarchy (depth 3)

In governed mode, `BuildGovernedKeyHierarchy()` records configured root/intermediate/leaf references. It does not verify a certificate chain or prove the issuers authorized those relationships:

```json
{
  "schemaVersion": "1.0.0",
  "depth": 3,
  "levels": [
    { "level": 0, "role": "root", "algorithm": "ed25519", "keyId": "<root-key-id>", "anchor": "<root-anchor>" },
    { "level": 1, "role": "intermediate", "algorithm": "ed25519", "keyId": "<intermediate-key-id>", "issuerKeyId": "<root-key-id>" },
    { "level": 2, "role": "leaf", "algorithm": "ed25519", "keyId": "<leaf-key-id>", "issuerKeyId": "<intermediate-key-id>" }
  ],
  "leafKeyId": "<leaf-key-id>",
  "rootAnchor": "<root-anchor>"
}
```

`ValidateKeyHierarchy()` checks:
- Depth matches level count
- Levels are in index order
- Non-root levels have an `issuerKeyId`
- Leaf and root references are consistent

The hierarchy is written to `key-hierarchy.json` in the evidence output.
The root anchor comes from `cadence.yaml` (`rootAnchor`) and may be overridden
by `CADENCE_ROOT_ANCHOR`; both paths are part of the governed input identity.

## Root anchor and actual key source

A configured root URI is a reference, not hardware attestation. The writer calls
`VerifiedSoftwareAnchor` only when using a concrete signer and emits software
anchor evidence after a real signature and local verification succeed.

| Actual signer | Anchor behavior |
|---|---|
| Unsigned / URI-only configuration | No active anchor |
| Local HMAC | `software-hmac`, `hardwareBacked=false`, `env:CADENCE_SIGNING_KEY` |
| Local Ed25519 private-key file | `software-ed25519`, `hardwareBacked=false`, `env:CADENCE_GOVERNED_SIGNING_PRIVATE_KEY_FILE` |
| Local Ed25519 inline material | `software-ed25519`, `hardwareBacked=false`, `env:CADENCE_GOVERNED_SIGNING_PRIVATE_KEY` |
| In-memory Ed25519 signer | Key-ID reference when available; no invented environment source |
| External command | No v1 anchor: signature verification does not prove hardware storage |

Source labels are captured when the key is loaded; they never contain a private
key or its filesystem path. `CADENCE_GOVERNED_SIGNER_COMMAND` takes precedence
over local signing. In the local path, `_PRIVATE_KEY_FILE` takes precedence over
`_PRIVATE_KEY`; a broken file does not fall back to inline material. Changing the
environment after selection cannot relabel the selected signer.

An external command can front an operator's provider, but this release has no
verified hardware-provider attestation adapter. `hsm://` / `kms://` strings do
not set `hardwareBacked=true`. Installations requiring hardware must obtain that
evidence separately; absent anchors cannot satisfy that requirement. Structural
`ValidateHSMAnchor` validation and hierarchy references are not proof of custody.

## Dual-Layer Signatures

`BuildDualLayerSignature()` produces two detached signatures per run:

1. **Manifest signature**: signs the run manifest payload
2. **Bundle signature**: signs the evidence bundle hash

This ensures both the execution declaration and the evidence corpus are
independently verifiable. In governed mode the runtime writes these as:

- `run-manifest.json.signature.json` and `manifest-signature.json`
- `bundle-signature.json` containing:
  - `bundleHash`
  - `entries`
  - `signature` (the bundle-layer detached signature)
  - `manifestLayer`
  - `bundleLayer`
  - `dualHash`
  - `dualSignature`

## Key Rotation Ceremony

`PerformKeyRotation()` supports leaf-key rotation with issuer continuity:
- The new leaf key must be issued by the same intermediate
- The ceremony is recorded with `rotatedAt` timestamp and `reason`
- The updated hierarchy preserves the root anchor and intermediate chain
