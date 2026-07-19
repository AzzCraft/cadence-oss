# Signing and Step Hash Chain

## Overview

The signing package provides two signing modes for evidence envelopes:

- **Dev mode** (`CADENCE_SIGNING_MODE=dev`): HMAC-SHA256 with a shared key — suitable for local development and CI.
- **Governed mode** (`CADENCE_SIGNING_MODE=governed`): Ed25519 asymmetric signing with a multi-depth key hierarchy — the production-grade path.

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

Uses `Ed25519Signer` with asymmetric keys. This is the required mode for production deployments.

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

In governed/production mode, `BuildGovernedKeyHierarchy()` produces a full chain-of-trust:

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

## Root Anchor

### Dev Anchor

Dev mode uses `BuildHSMAnchor()` to record an active `software-hmac` anchor pointing to
`env:CADENCE_SIGNING_KEY`. Status: `active`.

### Governed Anchor

Governed mode uses `BuildGovernedAnchor()` which produces an active anchor.
Status: `active`. The anchor provider is determined by the anchor ID prefix:

| Anchor ID Prefix | Provider | Hardware-Backed | Attestation |
|---|---|---|---|
| `hsm://...` | `hsm` | yes | `external-hsm-anchor-active` |
| `kms://...` | `kms` | yes | `external-kms-anchor-active` |
| (default) | `software-ed25519` | no | `software-ed25519-active` |

### Production HSM/KMS Configuration

To deploy with hardware-backed signing:

1. Set `CADENCE_SIGNING_MODE=governed`
2. Set `CADENCE_ROOT_ANCHOR` to the HSM/KMS URI (e.g., `hsm://vendor/key-id` or `kms://aws/key-arn`)
3. Configure one of:
   - `CADENCE_GOVERNED_SIGNER_COMMAND=/path/to/hsm-wrapper`
   - `CADENCE_GOVERNED_SIGNING_PRIVATE_KEY_FILE=/path/to/ed25519-private-key`
4. Provide the verification key via `CADENCE_GOVERNED_SIGNING_PUBLIC_KEY(_FILE)` when using an external signer command.
5. The runtime will:
   - Record `hardwareBacked: true` in the anchor evidence for `hsm://` / `kms://` roots
   - Use the configured root anchor for the depth-3 governed key hierarchy
   - Emit governed detached signatures for each signed artifact
   - Emit `bundle-signature.json` with both legacy-compatible bundle fields and the governed `manifestLayer`, `bundleLayer`, `dualHash`, and `dualSignature`

The `HSMAnchor` evidence record is emitted regardless of mode, ensuring
downstream audit tools can verify the declared anchor path. The status field is
`active` for every emitted release evidence record.

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
