# Replay Package

## Overview

The replay package records selected output files from a Cadence verify run and compares
their snapshots. It does not itself re-execute the run or capture every external input.
Reproduction also requires the original inputs, configuration and execution environment.

## Bundle Structure

```json
{
  "schemaVersion": "1.0.0",
  "replayId": "<unique-replay-id>",
  "runManifestRef": "<path-to-run-manifest>",
  "pipelineResultRef": "<path-to-pipeline-result>",
  "snapshots": [
    { "relPath": "run-manifest.json", "mode": "0644", "size": 1234, "fileHash": "sha256:..." }
  ],
  "inputs": { "config": "sha256:...", "source": "sha256:..." },
  "bundleHash": "sha256:..."
}
```

## Lifecycle

1. **Build**: `replay.Build()` walks the output directory at the time it is called and
   records regular files, excluding locators, replay/evidence bundles, signatures,
   attestations and report summaries listed in `internal/replay/replay.go`.
   Non-regular artifacts are rejected. Snapshots are sorted by relative path.
   The `inputs` map starts empty; callers must supply any input references they need.
2. **Save**: The bundle is written as indented JSON with a trailing newline.
3. **Load**: A previously saved bundle can be loaded from disk.
4. **Verify**: `replay.VerifyBundle()` checks each recorded path, file type, size,
   permission mode when recorded, and content hash. It does not discover unlisted files
   or recompute `bundleHash`; it is not the complete evidence verification entry point.
   Use `evidence-verify` for the native evidence inventory and its associated checks.

## Determinism Guarantees

- File snapshots are sorted by relative path before hashing.
- The `bundleHash` hashes each sorted snapshot's relative path, permission mode,
  size and file hash, separated by NUL bytes and terminated by a newline.
- Default `cadence verify` invocations allocate separate attempt IDs. Their input hashes
  can match while files containing the run ID and their replay bundle hashes differ.
- To compare a controlled replay, pass the same explicit `--run-id` to runs in separate
  fresh output roots. Reusing an existing run directory is rejected. The integration test
  `TestDeterminism` checks this explicit-ID case, including artifact bytes and `bundleHash`.
- Equal bundle hashes require equal recorded paths, modes, sizes and content hashes.
  Matching inputs and sandbox profile alone do not guarantee this across machines;
  runtime observations, clocks and file permissions may also differ.
