# Waiver Handling

## Overview

Waivers provide a formal mechanism for temporarily accepting known violations that cannot
be immediately resolved. Unlike inline comments or ad-hoc suppression, waivers are
tracked objects with required metadata, expiration, and audit trail.

## Waiver Record

```json
{
  "reason": "Legacy dependency cannot be updated until Q3",
  "ticket": "JIRA-1234",
  "owner": "team-lead@example.com",
  "approvedBy": "release-manager@example.com",
  "createdAt": "2026-04-09T00:00:00Z",
  "expiresAt": "2026-07-01T00:00:00Z",
  "referenceTime": "2026-04-09T00:00:00Z",
  "signature": "unsigned-local-break-glass",
  "scope": "profile"
}
```

## Required Fields

- `reason`: Human-readable justification for the waiver.
- `ticket`: Reference to an external tracking system (e.g., JIRA, GitHub Issue).
- `owner`: The person or team responsible for resolving the underlying issue.
- `approvedBy`: The actor that approved the waiver.
- `referenceTime`: The explicit replay-stable decision time used for expiry checks.
- `signature`: The persisted waiver-signature field for downstream audit handling.

## Validation

- `reason`, `ticket`, `owner`, `approvedBy`, `referenceTime`, and `signature`
  must be non-empty.
- `scope` must be one of `check`, `policy-pack`, or `profile`.
- If `createdAt`, `referenceTime`, or `expiresAt` is set, it must be valid RFC3339.
- Expired waivers are rejected against `referenceTime`, not implicit wall-clock time.
- Broader scopes trigger deeper governance requirements:
  - `check`: standard requester + approver chain
  - `policy-pack`: Tier-1 escalation
  - `profile`: Tier-2 escalation

## Waiver File

Multiple waivers can be stored in a waiver file:

```json
{
  "schemaVersion": "1.0.0",
  "waivers": [
    { "reason": "...", "ticket": "...", "owner": "..." }
  ]
}
```

The approval depth for a persisted waiver is supplied separately through an
approval-chain metadata file:

```json
{
  "waiverTicket": "JIRA-1234",
  "entries": [
    { "role": "requester", "identity": "team-lead@example.com", "timestamp": "2026-04-09T00:00:00Z" },
    { "role": "manager", "identity": "manager@example.com", "timestamp": "2026-04-09T00:05:00Z" },
    { "role": "security", "identity": "security@example.com", "timestamp": "2026-04-09T00:10:00Z" },
    { "role": "approver", "identity": "release-manager@example.com", "timestamp": "2026-04-09T00:15:00Z" }
  ],
  "depth": 4
}
```

## CLI Integration

The `--break-glass` flag in `cadence verify` creates a waiver record inline.
`CADENCE_SIGNING_MODE` defaults to `dev`. In dev mode, `--waiver-file` plus
`--approval-chain-file` provides policy-checked metadata, not authenticated
approval: names, roles and a `signature` string can be self-reported.

In `governed` mode, a failed verification that needs this persisted override is
refused. This CLI has no trusted approval-import command. Use an independently
authenticated approval consumer when such approval is required; merely changing
the signing mode or supplying these files does not create one. Explicit inline
`--break-glass` is the legacy warning/non-compliant path, not a production grant.
A successful verification needs no override; use a genuinely failing check when
validating refusal behavior, otherwise the waiver path may never be exercised.

Each inline or persisted waiver run also emits:
- `waiver.json`
- `approval-chain.json`
- `waiver-audit-trail.json`

The verify path requires:
- `--ticket` with `--waiver-file`
- `--approval-chain-file` with `--waiver-file`
- `--break-glass` and `--waiver-file` are mutually exclusive
- persisted verify-bypass waivers must use `scope: "profile"`

Each waiver run records:
- the approval chain captured for the waiver
- the derived escalation tier
- the required approval-chain depth
- pass/fail decisions for record, scope, duration, approval-chain, and escalation checks

Policy checks retain ticket/record binding, explicit reference-time expiry,
profile scope for verify bypass, duration/escalation requirements, ordered roles
and distinct principals. Metadata passing those checks is separate from identity
and signature authentication. Check `waiver-audit-trail.json` and the process
exit status; do not treat the existence of waiver files as acceptance.
