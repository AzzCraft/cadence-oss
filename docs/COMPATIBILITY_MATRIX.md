# Cadence OSS v1.1.0 Compatibility Matrix

| Surface | v1.1.0 policy |
| --- | --- |
| Cadence Core CLI, configuration, and emitted schemas | Backward compatible with v1.0.0. |
| Default `scripts/verify` | Preserves the v1.0 core-only fast contract. |
| Expanded units | Verified only by the explicit `scripts/verify --full` gate. |
| Plugins | Disabled unless a governed product configuration explicitly opts in. |
| Policy packs | `cadenceCore` and `protocol` use their own v1 compatibility ranges; `dasStandard` records DAS Standard v1.4 compatibility separately. |
| DAS Standard | v1.4.0; independent of the Cadence OSS bundle version. |

The Cadence OSS bundle version does not mechanically change component,
protocol, schema, plugin, or policy-pack versions. Those contracts change only
when their own compatibility rules require it.
