# Bridge plugin (stub)

A bridge plugin adapts an existing ecosystem tool (e.g. ESLint, Prettier, Ruff) to the Cadence plugin protocol.

Expected behavior:
- accept a batch file set from stdin
- run the underlying tool in a deterministic, pinned version
- translate findings into Cadence violations (ruleId/severity/message/evidence)
