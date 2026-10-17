# standard-ui-minimal

Standard cadence setup with UI enabled. Demonstrates the typical developer workflow.

## Structure

```
cadence.yaml      # mode: strict_offline, ui enabled
tooling_lock.json # locked tooling versions
```

The optional [controlled document workspace](ui/UI_SPEC.md) is a real browser
behavior sample for the 1.5 source development lane. It uses no UI framework,
keeps the legacy example unchanged, and introduces no production service or
qualification. Its original A27 source drivers require explicit Node/Chrome
pins; absent browser selection remains skipped, never a product pass.
