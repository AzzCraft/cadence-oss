package main

import (
	"encoding/json"
	"testing"

	"github.com/AzzCraft/cadence-oss/cadence-core/internal/exactjson"
)

// Full success is checked with the independent Python/OpenSSL producer at root.
// Malformed probes must fail normally, never panic or infer missing state safe.
func TestActionProbeMalformedInputsAreClosedAndDoNotPanic(t *testing.T) {
	current := map[string]any{"earliest": "2026-10-06T00:00:01Z", "latest": "2026-10-06T00:00:02Z", "observedAt": "2026-10-06T00:00:00Z", "maxStalenessSeconds": 1, "authorityEpoch": 1, "actor": "TEST-actor", "audience": "TEST-consumer", "action": "integrate", "verificationPlanDigest": "unused", "verificationEvidenceDigest": "unused", "decisionDigest": "unused", "bindings": map[string]any{}, "targetGeneration": 1, "targetCandidateDigest": "unused", "integrationReceiptDigest": nil, "policyRevoked": false, "evidenceRevoked": false, "decisionRevoked": false}
	current["collectedResultsDigest"] = "unused"
	value := map[string]any{"plan": map[string]any{}, "evidenceEnvelope": map[string]any{}, "decisionEnvelope": map[string]any{}, "trust": map[string]any{"issuer": "TEST-issuer", "threshold": 1, "keys": []any{}}, "current": current, "originals": []any{}}
	for _, kind := range []string{"empty-plan", "null-bindings", "null-time", "bad-time", "missing-revocation", "null-policy-revocation", "null-evidence-revocation", "null-decision-revocation", "case-alias", "fractional-epoch", "unsafe-epoch", "null-current", "unknown-root"} {
		t.Run(kind, func(t *testing.T) {
			b, e := json.Marshal(value)
			if e != nil {
				t.Fatal(e)
			}
			parsed, e := exactjson.Parse(b)
			if e != nil {
				t.Fatal(e)
			}
			v := parsed.(map[string]any)
			c := v["current"].(map[string]any)
			switch kind {
			case "null-bindings":
				c["bindings"] = nil
			case "null-time":
				c["earliest"] = nil
			case "bad-time":
				c["latest"] = "not time"
			case "missing-revocation":
				delete(c, "policyRevoked")
			case "null-policy-revocation":
				c["policyRevoked"] = nil
			case "null-evidence-revocation":
				c["evidenceRevoked"] = nil
			case "null-decision-revocation":
				c["decisionRevoked"] = nil
			case "case-alias":
				c["Actor"] = c["actor"]
				delete(c, "actor")
			case "fractional-epoch":
				c["authorityEpoch"] = json.Number("1.000000000000000001")
			case "unsafe-epoch":
				c["authorityEpoch"] = json.Number("9007199254740992")
			case "null-current":
				v["current"] = nil
			case "unknown-root":
				v["authorized"] = true
			}
			if _, e = checkActionProbe(v); e == nil {
				t.Fatal("malformed public probe accepted")
			}
		})
	}
}
