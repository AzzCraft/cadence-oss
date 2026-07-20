# Authoring policy packs

A policy pack SHOULD define:
- `id`, `version`, `description`
- `rules[]` where each rule references a ruleId implemented by a plugin or by core
- parameters (thresholds, allowlists, module boundaries, etc.)
- default severities and enforcement tiers (Tier1/Tier2/Tier3)

Recommendation:
- keep ruleIds stable
- use SemVer for pack versioning
