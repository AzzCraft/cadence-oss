# contracts-hub-consumer

Example showing how a product repo consumes and validates contracts from a contracts-hub-template instance.

## Purpose

Demonstrates the consumer side of the contracts-hub pattern:
- Pulling contract schemas from a contracts-hub-template
- Validating local data against contract schemas
- Running contract compliance checks as part of verify

## Structure

```
cadence.yaml        # references contracts-hub for schema source
tooling_lock.json   # locked tooling versions
contracts/          # local contract binding
  bindings.json     # maps local data to contract schemas
```

## Usage

1. Copy this example into your product repo's cadence configuration.
2. Update `cadence.yaml` to point to your contracts-hub instance.
3. Update `contracts/bindings.json` to map your local data paths to contract schemas.
4. Run `cadence-core verify` to validate contract compliance.
