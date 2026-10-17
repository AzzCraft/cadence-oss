// Package authz checks signed grants against an authenticated request and a
// current control-plane snapshot. It does not perform resource commits, reserve
// budgets or provide a public signing API. Callers still enforce the resource
// linearization point, including current state and atomic shared reservations.
package authz

import (
	"bytes"
	_ "embed"
	"errors"
	"io"
	"reflect"
	"sync"
	"time"

	"github.com/AzzCraft/cadence-oss/cadence-core/internal/dsse"
	"github.com/AzzCraft/cadence-oss/cadence-core/internal/exactjson"
	"github.com/santhosh-tekuri/jsonschema/v5"
)

const Identity = "das-action-authorization/v1"
const PayloadType = "application/vnd.das.action-authorization.v1+json"

//go:embed action_authorization.schema.json
var schemaBytes []byte
var once sync.Once
var schema *jsonschema.Schema
var schemaError error

func compile() error {
	once.Do(func() {
		compiler := jsonschema.NewCompiler()
		compiler.Draft = jsonschema.Draft2020
		compiler.AssertFormat = true
		compiler.LoadURL = func(string) (io.ReadCloser, error) {
			return nil, errors.New("authz: external schema loading forbidden")
		}
		if schemaError = compiler.AddResource("https://cadence.das.dev/embedded/action", bytes.NewReader(schemaBytes)); schemaError == nil {
			schema, schemaError = compiler.Compile("https://cadence.das.dev/embedded/action")
		}
	})
	return schemaError
}

type TaskKey struct{ AuthorityDomain, ProjectID, ChangeID, TaskID string }

func (key TaskKey) value() map[string]any {
	return map[string]any{"authorityDomain": key.AuthorityDomain, "projectId": key.ProjectID, "changeId": key.ChangeID, "taskId": key.TaskID}
}

type Request struct {
	// Actor comes from the authenticated server channel, never request JSON.
	Actor, RepresentedSubject, Audience                    string
	Task                                                   TaskKey
	Revision, Cycle, LeaseGeneration                       int64
	ResourceID, ResourceInstance, Action, BusinessActionID string
	TargetGeneration                                       int64
	RequestDigest, ToolDigest, PolicyDigest, BudgetID      string
	Cost                                                   int64
}

type GrantState struct {
	Generation int64
	Revoked    bool
}

type Snapshot struct {
	// Both ends of the trusted uncertainty interval must satisfy every validity
	// window. ObservedAt is the control-plane observation, not signed issuedAt.
	Earliest, Latest, ObservedAt time.Time
	MaxStaleness                 time.Duration
	AuthorityEpoch               int64
	Grants                       map[string]GrantState
}

type Trust struct {
	Issuer    string
	Keys      []dsse.Key
	Threshold int
}

type Checked struct {
	AuthorizationID                         string
	Principals, KeyFingerprints             []string
	AuthorityEpoch, AuthorizationGeneration int64
	AncestorIDs                             []string
}

type grant struct {
	value      map[string]any
	signature  dsse.Result
	start, end time.Time
}

func integer(value any) (int64, error) {
	if result, ok := value.(int64); ok {
		return result, nil
	}
	return exactjson.SafeInteger(value)
}

func parse(envelope []byte, trust Trust) (grant, error) {
	var empty grant
	verified, err := dsse.Verify(envelope, PayloadType, trust.Issuer, "action_authorizer", trust.Keys, trust.Threshold)
	if err != nil {
		return empty, err
	}
	value, err := exactjson.Parse(verified.Payload)
	if err != nil {
		return empty, err
	}
	if err = compile(); err != nil {
		return empty, err
	}
	if err = schema.Validate(value); err != nil {
		return empty, err
	}
	object := value.(map[string]any)
	for _, name := range []string{"taskRevision", "taskCycle", "authorityEpoch", "authorizationGeneration", "leaseGeneration", "targetGeneration", "maxCost"} {
		parsed, parseErr := integer(object[name])
		if parseErr != nil {
			return empty, parseErr
		}
		object[name] = parsed
	}
	if object["issuer"] != verified.Issuer {
		return empty, errors.New("authz: signed issuer mismatch")
	}
	start, err := time.Parse(time.RFC3339, object["notBefore"].(string))
	if err != nil {
		return empty, err
	}
	end, err := time.Parse(time.RFC3339, object["expiresAt"].(string))
	if err != nil || !end.After(start) {
		return empty, errors.New("authz: invalid validity interval")
	}
	return grant{object, verified, start, end}, nil
}

func stringsOf(value any) []string {
	result := []string{}
	for _, element := range value.([]any) {
		result = append(result, element.(string))
	}
	return result
}
func member(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

// Authorize requires parent envelopes from the protected authorization store.
// It cannot trust an actor history embedded by the client. Missing or stale
// current state, unsupported delegation and malformed inputs all fail closed.
func Authorize(envelope []byte, parents map[string][]byte, trust Trust, request Request, current Snapshot) (Checked, error) {
	var empty Checked
	if current.Earliest.IsZero() || current.Latest.Before(current.Earliest) || current.ObservedAt.IsZero() ||
		current.ObservedAt.After(current.Earliest) || current.MaxStaleness <= 0 || current.MaxStaleness > 30*time.Second ||
		current.Latest.Sub(current.ObservedAt) > current.MaxStaleness || current.AuthorityEpoch < 1 {
		return empty, errors.New("authz: unavailable, uncertain or stale current authority")
	}
	if len(parents) > 8 || request.Cost < 1 || request.Cost > exactjson.MaxSafeInteger {
		return empty, errors.New("authz: bounded request required")
	}
	// As with facts/qualification, the actor cannot approve its own action.
	// Preserve every key for duplicate-key checks; ignore only its eligibility.
	trust.Keys = append([]dsse.Key(nil), trust.Keys...)
	for i := range trust.Keys {
		if trust.Keys[i].Principal == request.Actor {
			trust.Keys[i].Roles = nil
		}
	}
	child, err := parse(envelope, trust)
	if err != nil {
		return empty, err
	}
	v := child.value
	expected := map[string]any{"actor": request.Actor, "representedSubject": request.RepresentedSubject, "audience": request.Audience,
		"resourceId": request.ResourceID, "resourceInstance": request.ResourceInstance, "action": request.Action,
		"businessActionId": request.BusinessActionID, "requestDigest": request.RequestDigest, "toolDigest": request.ToolDigest,
		"policyDigest": request.PolicyDigest, "budgetId": request.BudgetID}
	for name, value := range expected {
		if v[name] != value {
			return empty, errors.New("authz: request binding mismatch: " + name)
		}
	}
	if !reflect.DeepEqual(v["taskKey"], request.Task.value()) {
		return empty, errors.New("authz: task identity mismatch")
	}
	for name, expected := range map[string]int64{"taskRevision": request.Revision, "taskCycle": request.Cycle, "leaseGeneration": request.LeaseGeneration,
		"targetGeneration": request.TargetGeneration, "authorityEpoch": current.AuthorityEpoch} {
		actual, _ := integer(v[name])
		if actual != expected {
			return empty, errors.New("authz: current generation mismatch: " + name)
		}
	}
	maxCost, _ := integer(v["maxCost"])
	if request.Cost > maxCost {
		return empty, errors.New("authz: grant cost exceeded")
	}
	chain := []grant{child}
	ids := stringsOf(v["ancestors"])
	childID := v["authorizationId"].(string)
	if member(ids, childID) {
		return empty, errors.New("authz: authorization cycle")
	}
	for i, id := range ids {
		raw, ok := parents[id]
		if !ok {
			return empty, errors.New("authz: missing ancestor")
		}
		parent, err := parse(raw, trust)
		if err != nil {
			return empty, err
		}
		if parent.value["authorizationId"] != id || !reflect.DeepEqual(stringsOf(parent.value["ancestors"]), ids[i+1:]) {
			return empty, errors.New("authz: parent authority relationship mismatch")
		}
		descendant := chain[len(chain)-1]
		// The first reference path permits actor delegation and interval/cost
		// attenuation only. Resource, task, operation and exact parameters remain
		// unchanged. Broader delegation requires a separately versioned contract.
		for name := range expected {
			if name != "actor" && !reflect.DeepEqual(descendant.value[name], parent.value[name]) {
				return empty, errors.New("authz: delegated scope expanded: " + name)
			}
		}
		for _, name := range []string{"taskKey", "taskRevision", "taskCycle", "leaseGeneration", "targetGeneration", "authorityEpoch"} {
			if !reflect.DeepEqual(descendant.value[name], parent.value[name]) {
				return empty, errors.New("authz: delegated binding mismatch")
			}
		}
		delegates := stringsOf(parent.value["delegateActors"])
		if descendant.value["actor"] != parent.value["actor"] && !member(delegates, descendant.value["actor"].(string)) {
			return empty, errors.New("authz: actor delegation not approved")
		}
		for _, actor := range stringsOf(descendant.value["delegateActors"]) {
			if !member(delegates, actor) {
				return empty, errors.New("authz: delegation expanded")
			}
		}
		parentCost, _ := integer(parent.value["maxCost"])
		childCost, _ := integer(descendant.value["maxCost"])
		if childCost > parentCost || descendant.start.Before(parent.start) || descendant.end.After(parent.end) {
			return empty, errors.New("authz: ancestor limits exceeded")
		}
		chain = append(chain, parent)
	}
	for _, item := range chain {
		id := item.value["authorizationId"].(string)
		state, ok := current.Grants[id]
		generation, _ := integer(item.value["authorizationGeneration"])
		epoch, _ := integer(item.value["authorityEpoch"])
		if !ok || state.Revoked || state.Generation != generation || epoch != current.AuthorityEpoch {
			return empty, errors.New("authz: unavailable or revoked current grant")
		}
		if current.Earliest.Before(item.start) || !current.Latest.Before(item.end) {
			return empty, errors.New("authz: validity interval not proven")
		}
	}
	generation, _ := integer(v["authorizationGeneration"])
	return Checked{childID, child.signature.Principals, child.signature.KeyFingerprints, current.AuthorityEpoch, generation, ids}, nil
}
