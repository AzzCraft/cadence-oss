# Cadence OSS Core

Cadence OSS v1.0.0 is an offline, deterministic verification runtime. This
public source archive contains only `cadence-core` and the root release files
needed to build and verify it.

## Verify the source

```bash
bash ./scripts/verify
bash ./scripts/verify --full
```

Both commands are standalone: they work from any clone directory and from the
extracted source archive, without a sibling repository or network access.

## Run the CLI

```bash
cd cadence-core
go run -mod=vendor -buildvcs=false ./cmd/cadence --help
```

`cadence verify` operates on a product repository containing a valid
`cadence.yaml` and its declared local closure, tooling, runtime, registry, and
sandbox inputs. The shipped tests construct and exercise a complete example of
that contract. Third-party plugin execution is fail-closed in v1.0.0.

The broader protocol, plugin, policy-pack, sandbox, registry, contract-hub,
and examples units are planned separately and are not included or implied by
this release.
