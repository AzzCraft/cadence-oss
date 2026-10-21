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

1. Install this example's declared dependencies: `python3 -m pip install -r requirements.txt`.
2. Run `python3 scripts/verify_bindings.py` from this directory (or call its absolute path).
   This standalone step validates the bundled payment data against its schema.
3. Replace the entries in `contracts/bindings.json` with your local data and schema paths.
   Keep schemas local; missing data, broken schemas, invalid bindings and invalid data fail.
4. In a configured product, run the binding script first, then `cadence verify --profile ci`.
   Make both commands required in the product's existing verify script, using `set -e`.
   Core checks its built-in rules and fixture presence; it does **not** read bindings or
   certify business-data schema compliance. Success of either step alone is insufficient
   to claim both checks passed.

The shipped `cadence.yaml` illustrates reference configuration and must be adapted
before running Core in a separate product. It is not required for the standalone
binding check. No server or production deployment is needed.
