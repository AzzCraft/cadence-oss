package main

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"time"

	"github.com/AzzCraft/cadence-oss/cadence-core/internal/authz"
	"github.com/AzzCraft/cadence-oss/cadence-core/internal/dsse"
	"github.com/AzzCraft/cadence-oss/cadence-core/internal/exactjson"
)

// A supplied-context diagnostic uses the existing grant checker. Installation
// must supply authenticated request/current originals at the resource boundary.
func checkAuthorizationProbe(value any) (any, error) {
	if err := closedProbe(value, "grantEnvelope", "parentEnvelopes", "trust", "current", "request"); err != nil {
		return nil, err
	}
	checked, err := exactReferenceNumbers(value)
	if err != nil {
		return nil, err
	}
	v := checked.(map[string]any)
	if err = closedProbe(v["request"], "actor", "representedSubject", "audience", "taskKey", "taskRevision", "taskCycle", "leaseGeneration", "resourceId", "resourceInstance", "action", "businessActionId", "targetGeneration", "requestDigest", "toolDigest", "policyDigest", "budgetId", "cost"); err != nil {
		return nil, err
	}
	r := v["request"].(map[string]any)
	if err = closedProbe(r["taskKey"], "authorityDomain", "projectId", "changeId", "taskId"); err != nil {
		return nil, err
	}
	if err = closedProbe(v["trust"], "issuer", "threshold", "keys"); err != nil {
		return nil, err
	}
	keys, ok := v["trust"].(map[string]any)["keys"].([]any)
	if !ok || len(keys) > dsse.MaxKeys {
		return nil, errors.New("invalid grant probe keys")
	}
	for _, key := range keys {
		if err = closedProbe(key, "publicKeyBase64", "principal", "issuer", "roles"); err != nil {
			return nil, err
		}
	}
	if err = closedProbe(v["current"], "earliest", "latest", "observedAt", "maxStalenessSeconds", "authorityEpoch", "grants"); err != nil {
		return nil, err
	}
	grants, ok := v["current"].(map[string]any)["grants"].(map[string]any)
	if !ok || len(grants) > 9 {
		return nil, errors.New("invalid current grant chain")
	}
	for _, grant := range grants {
		if err = closedProbe(grant, "generation", "revoked"); err != nil {
			return nil, err
		}
		if _, ok := grant.(map[string]any)["revoked"].(bool); !ok {
			return nil, errors.New("unknown current grant revocation")
		}
	}
	parents, ok := v["parentEnvelopes"].(map[string]any)
	if !ok || len(parents) > 8 {
		return nil, errors.New("invalid original grant parents")
	}
	encoded, err := exactjson.Canonical(checked)
	if err != nil {
		return nil, err
	}
	var wire struct {
		GrantEnvelope   json.RawMessage
		ParentEnvelopes map[string]json.RawMessage
		Trust           struct {
			Issuer    string
			Threshold int
			Keys      []struct {
				PublicKeyBase64, Principal, Issuer string
				Roles                              []string
			}
		}
		Request struct {
			Actor, RepresentedSubject, Audience                    string
			TaskKey                                                authz.TaskKey
			TaskRevision, TaskCycle, LeaseGeneration               int64
			ResourceID, ResourceInstance, Action, BusinessActionID string
			TargetGeneration                                       int64
			RequestDigest, ToolDigest, PolicyDigest, BudgetID      string
			Cost                                                   int64
		}
		Current struct {
			Earliest, Latest, ObservedAt        string
			MaxStalenessSeconds, AuthorityEpoch int64
			Grants                              map[string]authz.GrantState
		}
	}
	if err = json.Unmarshal(encoded, &wire); err != nil {
		return nil, err
	}
	if wire.Current.MaxStalenessSeconds < 1 || wire.Current.MaxStalenessSeconds > 30 {
		return nil, errors.New("invalid grant freshness")
	}
	current := authz.Snapshot{AuthorityEpoch: wire.Current.AuthorityEpoch,
		MaxStaleness: time.Duration(wire.Current.MaxStalenessSeconds) * time.Second, Grants: wire.Current.Grants}
	current.Earliest, err = time.Parse(time.RFC3339Nano, wire.Current.Earliest)
	if err != nil {
		return nil, err
	}
	current.Latest, err = time.Parse(time.RFC3339Nano, wire.Current.Latest)
	if err != nil {
		return nil, err
	}
	current.ObservedAt, err = time.Parse(time.RFC3339Nano, wire.Current.ObservedAt)
	if err != nil {
		return nil, err
	}
	trust := authz.Trust{Issuer: wire.Trust.Issuer, Threshold: wire.Trust.Threshold}
	for _, entry := range wire.Trust.Keys {
		key, e := dsse.Decode(entry.PublicKeyBase64, ed25519.PublicKeySize)
		if e != nil || len(key) != ed25519.PublicKeySize {
			return nil, errors.New("invalid grant key")
		}
		roles := entry.Roles
		if entry.Principal == wire.Request.Actor {
			roles = nil // the caller's own key cannot count as independent approval
		}
		trust.Keys = append(trust.Keys, dsse.Key{Public: key, Principal: entry.Principal, Issuer: entry.Issuer, Roles: roles})
	}
	originals := map[string][]byte{}
	for id, raw := range wire.ParentEnvelopes {
		originals[id] = raw
	}
	w := wire.Request
	request := authz.Request{Actor: w.Actor, RepresentedSubject: w.RepresentedSubject, Audience: w.Audience,
		Task: w.TaskKey, Revision: w.TaskRevision, Cycle: w.TaskCycle, LeaseGeneration: w.LeaseGeneration,
		ResourceID: w.ResourceID, ResourceInstance: w.ResourceInstance, Action: w.Action,
		BusinessActionID: w.BusinessActionID, TargetGeneration: w.TargetGeneration,
		RequestDigest: w.RequestDigest, ToolDigest: w.ToolDigest, PolicyDigest: w.PolicyDigest,
		BudgetID: w.BudgetID, Cost: w.Cost}
	result, err := authz.Authorize(wire.GrantEnvelope, originals, trust, request, current)
	if err != nil {
		return nil, err
	}
	// Internal structs/slices are converted through the exact wire parser; they
	// do not acquire authority by being a public checker result.
	resultBytes, err := json.Marshal(map[string]any{"authorizationId": result.AuthorizationID,
		"principals": result.Principals, "keyFingerprints": result.KeyFingerprints,
		"authorityEpoch": result.AuthorityEpoch, "authorizationGeneration": result.AuthorizationGeneration,
		"ancestorIds": result.AncestorIDs})
	if err != nil {
		return nil, err
	}
	refs, err := exactjson.Parse(resultBytes)
	if err != nil {
		return nil, err
	}
	return map[string]any{"checkedRefs": refs, "authority": false, "qualification": false}, nil
}
