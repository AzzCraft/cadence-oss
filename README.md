# Cadence OSS

Cadence OSS v1.1.0 is a backward-compatible expansion of the v1.0.0 offline,
deterministic verification runtime. It retains `cadence-core` unchanged as the
default verifier and additionally ships reviewed protocol, plugin, policy-pack,
contract-hub, example, sandbox, and registry units.

## Verify the source

```bash
bash ./scripts/verify          # v1.0-compatible core verification
bash ./scripts/verify --full   # complete eight-unit verification
```

Both commands are standalone: they work from any clone directory and from the
extracted source archive, without a sibling repository or network access. The
default command remains the v1.0 core contract; expanded-unit checks require
the explicit `--full` opt-in.

## Run the CLI

```bash
cd cadence-core
go run -mod=vendor -buildvcs=false ./cmd/cadence --help
```

`cadence verify` operates on a repository containing a valid
`cadence.yaml` and its declared local closure, tooling, runtime, registry, and
sandbox inputs. The shipped tests construct and exercise a complete example of
that contract. Third-party plugin execution is fail-closed by default.

See [the release-unit inventory](docs/RELEASE_UNITS.md) and
[the compatibility matrix](docs/COMPATIBILITY_MATRIX.md) before consuming an
optional unit. Third-party plugins remain fail-closed unless a product
explicitly opts in through its governed configuration.
