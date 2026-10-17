# Verify Requirements — cadence-oss

```bash
./scripts/verify
```

## Prerequisites

- `go` on PATH (1.25.12+; this is the minimum security-patched baseline)
- `python3` on PATH (3.10+)
- `node` on PATH (20+)
- `bash` on PATH

## What verify checks

1. cadence-protocol schema validation and compatibility.
2. cadence-core build, vet, tests.
3. cadence-plugins validation.
4. cadence-policy-packs pack integrity.
5. cadence-examples end-to-end verify.
6. contracts-hub-template self-consistency.
7. Root aggregation of all subunit results.
