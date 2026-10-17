package authz

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AzzCraft/cadence-oss/cadence-core/internal/dsse"
)

func fixture(t *testing.T) (map[string]any, []byte, Trust, Request, Snapshot) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "cadence-protocol", "fixtures", "das_v1_5", "action_authorization_vector.json"))
	if err != nil {
		t.Fatal(err)
	}
	var value struct {
		Payload         map[string]any
		Envelope        json.RawMessage
		PublicKeyBase64 string
	}
	if err = json.Unmarshal(raw, &value); err != nil {
		t.Fatal(err)
	}
	public, err := base64.StdEncoding.DecodeString(value.PublicKeyBase64)
	if err != nil {
		t.Fatal(err)
	}
	trust := Trust{"authority:fixture", []dsse.Key{{Public: public, Principal: "independent:approver", Issuer: "authority:fixture", Roles: []string{"action_authorizer"}}}, 1}
	request := Request{Actor: "peer:worker", RepresentedSubject: "subject:fixture", Audience: "resource-gateway:fixture", Task: TaskKey{"fixture", "project", "change", "task"}, Revision: 1, Cycle: 1, LeaseGeneration: 3, ResourceID: "resource-1", ResourceInstance: "instance-1", Action: "integrate", BusinessActionID: "business-1", TargetGeneration: 4, RequestDigest: "sha256:" + strings.Repeat("1", 64), ToolDigest: "sha256:" + strings.Repeat("2", 64), PolicyDigest: "sha256:" + strings.Repeat("3", 64), BudgetID: "budget-1", Cost: 5}
	now := time.Date(2026, 10, 5, 0, 5, 0, 0, time.UTC)
	current := Snapshot{Earliest: now, Latest: now.Add(time.Second), ObservedAt: now.Add(-time.Second), MaxStaleness: 5 * time.Second, AuthorityEpoch: 1, Grants: map[string]GrantState{"grant-1": {2, false}}}
	return value.Payload, value.Envelope, trust, request, current
}
func signed(t *testing.T, value map[string]any) []byte {
	t.Helper()
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	pae, err := dsse.PAE(PayloadType, payload)
	if err != nil {
		t.Fatal(err)
	}
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32))
	envelope := map[string]any{"payloadType": PayloadType, "payload": base64.StdEncoding.EncodeToString(payload), "signatures": []any{map[string]any{"sig": base64.StdEncoding.EncodeToString(ed25519.Sign(private, pae))}}}
	raw, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func TestIndependentPythonProducerGoConsumer(t *testing.T) {
	_, envelope, trust, request, current := fixture(t)
	checked, err := Authorize(envelope, nil, trust, request, current)
	if err != nil || checked.AuthorizationID != "grant-1" || len(checked.Principals) != 1 || checked.AuthorizationGeneration != 2 {
		t.Fatal(err, checked)
	}
}

func TestLeaseIndependentAuditCannotAuthorizeBusinessWork(t *testing.T) {
	for _, action := range []string{"audit", "integrate", "complete", "apply", "rollback"} {
		t.Run(action, func(t *testing.T) {
			payload, _, trust, request, current := fixture(t)
			payload["action"], payload["leaseGeneration"] = action, int64(0)
			request.Action, request.LeaseGeneration = action, 0
			_, err := Authorize(signed(t, payload), nil, trust, request, current)
			if (err == nil) != (action == "audit") {
				t.Fatal("zero-lease audit profile escaped its purpose", action, err)
			}
		})
	}
	// Existing legal audit grants with an actual lease remain readable. The
	// installed completed-task verifier separately requires the zero-lease profile.
	payload, _, trust, request, current := fixture(t)
	payload["action"], request.Action = "audit", "audit"
	if _, err := Authorize(signed(t, payload), nil, trust, request, current); err != nil {
		t.Fatal("existing audit grant rejected", err)
	}
}

func TestControlledAccountsCannotApproveEachOther(t *testing.T) {
	payload, _, trust, request, current := fixture(t)
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	pae, err := dsse.PAE(PayloadType, raw)
	if err != nil {
		t.Fatal(err)
	}
	p1 := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32))
	p2 := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, 32))
	envelope := map[string]any{"payloadType": PayloadType, "payload": base64.StdEncoding.EncodeToString(raw),
		"signatures": []any{
			map[string]any{"keyid": "self-reported-owner-account", "sig": base64.StdEncoding.EncodeToString(ed25519.Sign(p1, pae))},
			map[string]any{"keyid": "self-reported-approver-account", "sig": base64.StdEncoding.EncodeToString(ed25519.Sign(p2, pae))},
		}}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	// The installed control map, not account names or keyids, supplies the
	// effective approving principals. These are TEST control relationships.
	trust.Keys = []dsse.Key{
		{Public: p1.Public().(ed25519.PublicKey), Principal: "TEST-one-controller", Issuer: trust.Issuer, Roles: []string{"action_authorizer"}},
		{Public: p2.Public().(ed25519.PublicKey), Principal: "TEST-one-controller", Issuer: trust.Issuer, Roles: []string{"action_authorizer"}},
	}
	trust.Threshold = 2
	if _, err := Authorize(encoded, nil, trust, request, current); err == nil {
		t.Fatal("two controlled accounts became independent approvals")
	}
	// Also collapse the caller and both accounts to their installed effective
	// controlling identity: no threshold can turn its own keys into outsiders.
	trust.Keys[0].Principal, trust.Keys[1].Principal = request.Actor, request.Actor
	for _, threshold := range []int{1, 2} {
		trust.Threshold = threshold
		if _, err := Authorize(encoded, nil, trust, request, current); err == nil {
			t.Fatal("actor-controlled accounts satisfied an external threshold", threshold)
		}
	}
	trust.Threshold = 2
	trust.Keys[0].Principal = "TEST-one-controller"
	trust.Keys[1].Principal = "TEST-independent-external-approver"
	checked, err := Authorize(encoded, nil, trust, request, current)
	if err != nil || len(checked.Principals) != 2 {
		t.Fatal("approved independent control mapping rejected", err, checked)
	}
	trust.Keys[0].Principal = request.Actor
	if _, err := Authorize(encoded, nil, trust, request, current); err == nil {
		t.Fatal("the actor counted as an independent external approver")
	}
	trust.Keys[0].Principal = "TEST-one-controller"
	trust.Keys[1].Roles = []string{"unapproved-self-reported-role"}
	if _, err := Authorize(encoded, nil, trust, request, current); err == nil {
		t.Fatal("unapproved account role satisfied the external threshold")
	}
	// A superfluous actor signature must neither count nor invalidate two
	// sufficient external approvals. Filtering must not mutate installed keys.
	trust.Keys[1].Roles = []string{"action_authorizer"}
	p3 := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, 32))
	trust.Keys = append(trust.Keys, dsse.Key{Public: p3.Public().(ed25519.PublicKey), Principal: request.Actor,
		Issuer: trust.Issuer, Roles: []string{"action_authorizer"}})
	envelope["signatures"] = append(envelope["signatures"].([]any), map[string]any{
		"sig": base64.StdEncoding.EncodeToString(ed25519.Sign(p3, pae))})
	encoded, err = json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	checked, err = Authorize(encoded, nil, trust, request, current)
	if err != nil || len(checked.Principals) != 2 || member(checked.Principals, request.Actor) || len(trust.Keys[2].Roles) != 1 {
		t.Fatal("extra actor signature counted, invalidated external approval or mutated trust", err, checked)
	}
}

func TestCurrentAuthenticationAndBindings(t *testing.T) {
	for _, kind := range []string{"actor", "audience", "subject", "task-domain", "task-project", "task-change", "task-id", "revision", "cycle", "lease", "resource", "instance", "target-generation", "action", "business", "parameters", "tool", "policy", "budget", "cost", "epoch", "authorization-generation", "revoked", "unavailable", "stale", "backwards-time", "expired", "uncertain-expiry", "not-before"} {
		t.Run(kind, func(t *testing.T) {
			_, envelope, trust, request, current := fixture(t)
			switch kind {
			case "actor":
				request.Actor = "self-reported:admin"
			case "audience":
				request.Audience = "other"
			case "subject":
				request.RepresentedSubject = "other"
			case "task-domain":
				request.Task.AuthorityDomain = "other"
			case "task-project":
				request.Task.ProjectID = "other"
			case "task-change":
				request.Task.ChangeID = "other"
			case "task-id":
				request.Task.TaskID = "other"
			case "revision":
				request.Revision++
			case "cycle":
				request.Cycle++
			case "lease":
				request.LeaseGeneration++
			case "resource":
				request.ResourceID = "other"
			case "instance":
				request.ResourceInstance = "rebuilt:same-name"
			case "target-generation":
				request.TargetGeneration += 2
			case "action":
				request.Action = "complete"
			case "business":
				request.BusinessActionID = "other"
			case "parameters":
				request.RequestDigest = "sha256:" + strings.Repeat("4", 64)
			case "tool":
				request.ToolDigest = "sha256:" + strings.Repeat("4", 64)
			case "policy":
				request.PolicyDigest = "sha256:" + strings.Repeat("4", 64)
			case "budget":
				request.BudgetID = "other"
			case "cost":
				request.Cost = 11
			case "epoch":
				current.AuthorityEpoch++
			case "authorization-generation":
				current.Grants["grant-1"] = GrantState{3, false}
			case "revoked":
				current.Grants["grant-1"] = GrantState{2, true}
			case "unavailable":
				current.Grants = nil
			case "stale":
				current.ObservedAt = current.Earliest.Add(-time.Minute)
			case "backwards-time":
				current.Latest = current.Earliest.Add(-time.Second)
			case "expired":
				current.Earliest = current.Earliest.Add(5 * time.Minute)
				current.Latest = current.Earliest
				current.ObservedAt = current.Earliest
			case "uncertain-expiry":
				current.Earliest = current.Earliest.Add(299 * time.Second)
				current.Latest = current.Earliest.Add(time.Second)
				current.ObservedAt = current.Earliest
			case "not-before":
				current.Earliest = current.Earliest.Add(-6 * time.Minute)
				current.Latest = current.Earliest
				current.ObservedAt = current.Earliest
			}
			if _, err := Authorize(envelope, nil, trust, request, current); err == nil {
				t.Fatal("unbound/stale authority accepted")
			}
		})
	}
}
func TestClosedPayloadAndExactNumbers(t *testing.T) {
	for _, kind := range []string{"unknown", "case", "fraction", "unsafe", "bad-date", "issuer", "cycle", "repeated-ancestor"} {
		t.Run(kind, func(t *testing.T) {
			payload, _, trust, request, current := fixture(t)
			switch kind {
			case "unknown":
				payload["approved"] = true
			case "case":
				payload["Actor"] = payload["actor"]
				delete(payload, "actor")
			case "fraction":
				payload["authorityEpoch"] = json.Number("1.0000000000000000001")
			case "unsafe":
				payload["maxCost"] = json.Number("9007199254740992")
			case "bad-date":
				payload["expiresAt"] = "2026-02-31T00:00:00Z"
			case "issuer":
				payload["issuer"] = "self-reported:issuer"
			case "cycle":
				payload["ancestors"] = []any{"grant-1"}
			case "repeated-ancestor":
				payload["ancestors"] = []any{"parent", "parent"}
			}
			if _, err := Authorize(signed(t, payload), nil, trust, request, current); err == nil {
				t.Fatal("invalid signed payload accepted")
			}
		})
	}
	payload, _, trust, request, current := fixture(t)
	payload["authorityEpoch"] = json.Number("1.0")
	if _, err := Authorize(signed(t, payload), nil, trust, request, current); err != nil {
		t.Fatal("exact integer value rejected", err)
	}
}
func TestAttenuatedDelegationAndAncestorRevocation(t *testing.T) {
	for _, kind := range []string{"legal", "missing", "revoked", "expanded-actor", "expanded-scope", "expanded-budget", "expanded-time", "expanded-delegates", "wrong-parent-chain"} {
		t.Run(kind, func(t *testing.T) {
			parent, _, trust, request, current := fixture(t)
			child, _, _, _, _ := fixture(t)
			parent["authorizationId"] = "parent"
			parent["actor"] = "peer:owner"
			parent["delegateActors"] = []any{"peer:worker"}
			child["ancestors"] = []any{"parent"}
			child["maxCost"] = 5
			current.Grants["parent"] = GrantState{2, false}
			switch kind {
			case "revoked":
				current.Grants["parent"] = GrantState{2, true}
			case "expanded-actor":
				parent["delegateActors"] = []any{}
			case "expanded-scope":
				parent["resourceId"] = "different"
			case "expanded-budget":
				parent["maxCost"] = 4
			case "expanded-time":
				parent["expiresAt"] = "2026-10-05T00:09:00Z"
			case "expanded-delegates":
				child["delegateActors"] = []any{"peer:third"}
			case "wrong-parent-chain":
				parent["ancestors"] = []any{"missing"}
			}
			parents := map[string][]byte{"parent": signed(t, parent)}
			if kind == "missing" {
				parents = nil
			}
			_, err := Authorize(signed(t, child), parents, trust, request, current)
			if (err == nil) != (kind == "legal") {
				t.Fatal(kind, err)
			}
		})
	}
}
