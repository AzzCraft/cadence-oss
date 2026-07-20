# Replay Package

## Overview

The replay package provides deterministic re-execution capability for cadence verify runs.
A replay bundle captures all inputs, outputs, and file snapshots from a run so that the same
result can be reproduced independently.

## Bundle Structure

```json
{
  "schemaVersion": "1.0.0",
  "replayId": "<unique-replay-id>",
  "runManifestRef": "<path-to-run-manifest>",
  "pipelineResultRef": "<path-to-pipeline-result>",
  "snapshots": [
    { "relPath": "manifest.json", "size": 1234, "fileHash": "sha256:..." }
  ],
  "inputs": { "config": "sha256:...", "source": "sha256:..." },
  "bundleHash": "sha256:..."
}
```

## Lifecycle

1. **Build**: After a verify run completes, `replay.Build()` walks the output directory and
   records the hash of every artifact. Snapshots are sorted by path for deterministic ordering.
2. **Save**: The bundle is written as canonical JSON to the output directory.
3. **Load**: A previously saved bundle can be loaded from disk.
4. **Verify**: `replay.VerifyBundle()` re-hashes every file in the output directory and compares
   against the recorded snapshot hashes.

## Determinism Guarantees

- File snapshots are sorted by relative path before hashing.
- The `bundleHash` is computed from the ordered concatenation of all snapshot hashes.
- A replay bundle from one machine should produce identical `bundleHash` on another machine
  given the same inputs and sandbox profile.
