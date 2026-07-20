# Registry Deprecation Policy

## Overview

This document defines the rules for deprecating packs, plugins, and trust entries in the Cadence registry.

## Deprecation Lifecycle

```
ACTIVE → DEPRECATED → REMOVED
```

### ACTIVE → DEPRECATED

1. Add `"deprecated": true` and `"deprecationNotice": "reason"` to the index entry.
2. Increment the registry version.
3. Update CHANGELOG.md.
4. Consumers receive a warning on `cadence-core registry resolve` but the pack/plugin remains functional.

### DEPRECATED → REMOVED

1. Minimum deprecation period: **90 days** (tracked via `deprecatedAt` timestamp).
2. Remove the entry from the index.
3. Move the entry to `archive/deprecated.json` for audit trail.
4. Increment the registry version.
5. Consumers that reference the removed entry will get a hard error.

## Deprecation Criteria

A pack or plugin MAY be deprecated when:

- A newer version supersedes it.
- A security vulnerability is discovered with no available fix.
- The maintainer requests removal.
- It depends on a deprecated or removed protocol schema version.

## Consumer Impact

| State | resolve | verify | install |
|-------|---------|--------|---------|
| ACTIVE | ✅ | ✅ | ✅ |
| DEPRECATED | ⚠️ warning | ⚠️ warning | ✅ |
| REMOVED | ❌ error | ❌ error | ❌ error |

## Trust Entry Revocation

Trust entries follow a stricter lifecycle:

```
full → limited → revoked
```

- **limited**: Signatures verified but flagged. New signing blocked.
- **revoked**: All signatures from this signer are rejected. Immediate effect.

Trust revocations have no minimum waiting period.

## Audit Trail

All deprecation and revocation actions are recorded in `audit/deprecation_log.json`:

```json
{
  "action": "deprecate | remove | revoke",
  "target": "pack-name@version | plugin-name | signer-id",
  "reason": "string",
  "actor": "string",
  "timestamp": "ISO-8601"
}
```
