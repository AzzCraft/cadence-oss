package main

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/AzzCraft/cadence-oss/cadence-core/internal/exactjson"
)

func grantProbeFixture(t *testing.T) map[string]any {
	t.Helper()
	raw, err := os.ReadFile("../../../cadence-protocol/fixtures/das_v1_5/action_authorization_vector.json")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := exactjson.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	vector := parsed.(map[string]any)
	payload := vector["payload"].(map[string]any)
	request := map[string]any{"cost": int64(5)}
	for _, field := range []string{"actor", "representedSubject", "audience", "taskKey", "taskRevision", "taskCycle", "leaseGeneration", "resourceId", "resourceInstance", "action", "businessActionId", "targetGeneration", "requestDigest", "toolDigest", "policyDigest", "budgetId"} {
		request[field] = payload[field]
	}
	return map[string]any{"grantEnvelope": vector["envelope"], "parentEnvelopes": map[string]any{}, "request": request,
		"trust":   map[string]any{"issuer": "authority:fixture", "threshold": int64(1), "keys": []any{map[string]any{"publicKeyBase64": vector["publicKeyBase64"], "principal": "TEST-independent-approver", "issuer": "authority:fixture", "roles": []any{"action_authorizer"}}}},
		"current": map[string]any{"earliest": "2026-10-05T00:05:00Z", "latest": "2026-10-05T00:05:01Z", "observedAt": "2026-10-05T00:04:59Z", "maxStalenessSeconds": int64(5), "authorityEpoch": int64(1), "grants": map[string]any{"grant-1": map[string]any{"generation": int64(2), "revoked": false}}}}
}

func TestAuthorizationProbeConsumesIndependentProducerAndRejectsUncertainBindings(t *testing.T) {
	for _, kind := range []string{"legal", "actor", "request", "lease", "revoked", "generation", "null-revocation", "text-revocation", "missing-revocation", "case-alias", "fraction", "unsafe", "unknown-request", "unknown-root", "null-current", "null-task", "missing-parents", "bad-time", "stale", "self-approval", "wrong-role"} {
		t.Run(kind, func(t *testing.T) {
			v := grantProbeFixture(t)
			r := v["request"].(map[string]any)
			c := v["current"].(map[string]any)
			g := c["grants"].(map[string]any)["grant-1"].(map[string]any)
			key := v["trust"].(map[string]any)["keys"].([]any)[0].(map[string]any)
			switch kind {
			case "actor":
				r["actor"] = "other"
			case "request":
				r["requestDigest"] = r["toolDigest"]
			case "lease":
				r["leaseGeneration"] = int64(4)
			case "revoked":
				g["revoked"] = true
			case "generation":
				g["generation"] = int64(3)
			case "null-revocation":
				g["revoked"] = nil
			case "text-revocation":
				g["revoked"] = "false"
			case "missing-revocation":
				delete(g, "revoked")
			case "case-alias":
				r["Actor"] = r["actor"]
				delete(r, "actor")
			case "fraction":
				r["taskRevision"] = json.Number("1.00000000000000001")
			case "unsafe":
				r["cost"] = json.Number("9007199254740992")
			case "unknown-request":
				r["approved"] = true
			case "unknown-root":
				v["authority"] = true
			case "null-current":
				v["current"] = nil
			case "null-task":
				r["taskKey"] = nil
			case "missing-parents":
				delete(v, "parentEnvelopes")
			case "bad-time":
				c["earliest"] = "not-time"
			case "stale":
				c["observedAt"] = "2026-10-05T00:00:00Z"
			case "self-approval":
				key["principal"] = r["actor"]
			case "wrong-role":
				key["roles"] = []any{"evidence_issuer"}
			}
			result, err := checkAuthorizationProbe(v)
			if (err == nil) != (kind == "legal") {
				t.Fatal(kind, err, result)
			}
			if err == nil {
				out := result.(map[string]any)
				if out["authority"] != false || out["qualification"] != false || out["checkedRefs"].(map[string]any)["authorizationId"] != "grant-1" {
					t.Fatal("public supplied context acquired authority", out)
				}
			}
		})
	}
}
