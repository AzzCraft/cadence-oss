# Plugin Subprocess Protocol

## Overview

Plugin manifests and their protocol schema are retained for compatibility and
inspection. The public v1 runtime does **not** execute plugin subprocesses.
Any configured plugin causes verification to fail closed because a capability
declaration alone cannot enforce filesystem, network, process, or environment
isolation.

## Plugin Manifest

```json
{
  "schemaVersion": "1.0.0",
  "pluginId": "my-custom-check",
  "entryPoint": "./plugins/my-custom-check",
  "capabilities": ["check", "scan"],
  "timeoutMs": 30000
}
```

## Reserved protocol

The following messages document the reserved interface. They do not imply an
available executor in this release.

### RunRequest

```json
{
  "pluginId": "my-custom-check",
  "runId": "20260409T...",
  "inputHash": "sha256:...",
  "parameters": { "key": "value" }
}
```

### RunResult

```json
{
  "pluginId": "my-custom-check",
  "status": "pass",
  "outputHash": "sha256:...",
  "violations": 0,
  "diagnostics": {}
}
```

## Timeouts

`timeoutMs` is validated as metadata but is not acted on while execution is
disabled.

## Security

- Plugin execution is disabled and returns a non-success result.
- A future executor must enforce the declared filesystem, network, process,
  runtime, and environment policy before this feature can be enabled.
