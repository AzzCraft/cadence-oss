# headless-minimal

Minimal cadence setup with no UI, no signing, no replay. Suitable for CI-only verification.

## Structure

```
cadence.yaml      # mode: strict_offline, no ui
tooling_lock.json # locked tooling versions
```

Optional [controlled HTTP reference](http/README.md) demonstrates the declaration
probe and DASOps's durable version-resource adapter. Its TEST control setup and
three-component integration are separate from this legacy configuration.
