# standard-ui-minimal

Standard Cadence setup with a separate, explicit browser verification sample.
Core verification checks source contracts; it does not execute UI checks.

## Structure

```
cadence.yaml      # mode: strict_offline, core UI execution disabled
tooling_lock.json # locked tooling versions
```

The optional [controlled document workspace](ui/UI_SPEC.md) is a real browser
behavior sample for the 1.5 source development lane. It uses no UI framework,
introduces no production service or
qualification. Its original A27 source drivers require explicit Node/Chrome
pins; absent browser selection remains skipped, never a product pass.
Follow its pinned runner instructions separately. Setting `ui.enabled: true`
in the core configuration is rejected rather than reporting unchecked UI work as passed.
