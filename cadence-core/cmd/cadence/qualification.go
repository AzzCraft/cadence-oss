package main

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"time"

	"github.com/AzzCraft/cadence-oss/cadence-core/internal/dsse"
	"github.com/AzzCraft/cadence-oss/cadence-core/internal/exactjson"
	"github.com/AzzCraft/cadence-oss/cadence-core/internal/qualification"
)

func closedProbe(value any, names ...string) error {
	object, ok := value.(map[string]any)
	if !ok || len(object) != len(names) {
		return errors.New("invalid closed probe object")
	}
	for _, name := range names {
		if _, ok := object[name]; !ok {
			return errors.New("missing probe field")
		}
	}
	return nil
}

// Supplied contexts and collection records are diagnostic inputs, not an
// authenticated control plane. An installed consumer must obtain ALL of them
// independently and recheck at its resource transaction, never from an RPC body.
func checkActionProbe(value any) (any, error) {
	if err := closedProbe(value, "plan", "evidenceEnvelope", "decisionEnvelope", "trust", "current", "originals"); err != nil {
		return nil, err
	}
	checked, err := exactReferenceNumbers(value)
	if err != nil {
		return nil, err
	}
	object := checked.(map[string]any)
	if err = closedProbe(object["trust"], "issuer", "threshold", "keys"); err != nil {
		return nil, err
	}
	if err = closedProbe(object["current"], "earliest", "latest", "observedAt", "maxStalenessSeconds", "authorityEpoch", "actor", "audience", "action", "verificationPlanDigest", "verificationEvidenceDigest", "decisionDigest", "collectedResultsDigest", "bindings", "targetGeneration", "targetCandidateDigest", "integrationReceiptDigest", "policyRevoked", "evidenceRevoked", "decisionRevoked"); err != nil {
		return nil, err
	}
	for _, name := range []string{"policyRevoked", "evidenceRevoked", "decisionRevoked"} {
		if _, ok := object["current"].(map[string]any)[name].(bool); !ok {
			return nil, errors.New("unknown current qualification revocation")
		}
	}
	trustObject := object["trust"].(map[string]any)
	keys, ok := trustObject["keys"].([]any)
	if !ok || len(keys) > dsse.MaxKeys {
		return nil, errors.New("invalid probe trust")
	}
	for _, key := range keys {
		if err = closedProbe(key, "publicKeyBase64", "principal", "issuer", "roles"); err != nil {
			return nil, err
		}
	}
	originals, ok := object["originals"].([]any)
	if !ok || len(originals) > 512 {
		return nil, errors.New("invalid probe originals")
	}
	for _, original := range originals {
		if err = closedProbe(original, "digest", "bytesBase64", "producer", "principal", "runId", "verificationPlanDigest", "bindingDigest", "configDigest", "shard", "attempt", "assertionIds", "collectionIntact", "domainStopped"); err != nil {
			return nil, err
		}
	}
	encoded, err := exactjson.Canonical(checked)
	if err != nil {
		return nil, err
	}
	var request struct {
		Plan, EvidenceEnvelope, DecisionEnvelope json.RawMessage
		Trust                                    struct {
			Issuer    string
			Threshold int
			Keys      []struct {
				PublicKeyBase64, Principal, Issuer string
				Roles                              []string
			}
		}
		Current struct {
			Earliest, Latest, ObservedAt                                       string
			MaxStalenessSeconds, AuthorityEpoch                                int64
			Actor, Audience, Action                                            string
			VerificationPlanDigest, VerificationEvidenceDigest, DecisionDigest string
			CollectedResultsDigest                                             string
			Bindings                                                           map[string]any
			TargetGeneration                                                   int64
			TargetCandidateDigest                                              string
			IntegrationReceiptDigest                                           *string
			PolicyRevoked, EvidenceRevoked, DecisionRevoked                    bool
		}
		Originals []struct {
			Digest, BytesBase64, Producer, Principal, RunID, VerificationPlanDigest, BindingDigest, ConfigDigest, Shard string
			Attempt                                                                                                     int64
			AssertionIDs                                                                                                []string
			CollectionIntact, DomainStopped                                                                             bool
		}
	}
	if err = json.Unmarshal(encoded, &request); err != nil {
		return nil, err
	}
	// Bindings have already been parsed/checked without float conversion. Keep
	// that exact value instead of encoding/json's map[string]float64 defaults.
	currentMap := object["current"].(map[string]any)
	bindings, ok := currentMap["bindings"].(map[string]any)
	if !ok {
		return nil, errors.New("invalid expected bindings")
	}
	current := qualification.Current{AuthorityEpoch: request.Current.AuthorityEpoch, Actor: request.Current.Actor, Audience: request.Current.Audience, Action: request.Current.Action, PlanDigest: request.Current.VerificationPlanDigest, EvidenceDigest: request.Current.VerificationEvidenceDigest, DecisionDigest: request.Current.DecisionDigest, Bindings: bindings, TargetGeneration: request.Current.TargetGeneration, TargetCandidateDigest: request.Current.TargetCandidateDigest, IntegrationReceiptDigest: request.Current.IntegrationReceiptDigest, PolicyRevoked: request.Current.PolicyRevoked, EvidenceRevoked: request.Current.EvidenceRevoked, DecisionRevoked: request.Current.DecisionRevoked}
	if request.Current.MaxStalenessSeconds < 1 || request.Current.MaxStalenessSeconds > 30 {
		return nil, errors.New("invalid freshness")
	}
	current.CollectedResultsDigest = request.Current.CollectedResultsDigest
	current.MaxStaleness = time.Duration(request.Current.MaxStalenessSeconds) * time.Second
	for name, target := range map[string]*time.Time{"earliest": &current.Earliest, "latest": &current.Latest, "observedAt": &current.ObservedAt} {
		stamp := map[string]string{"earliest": request.Current.Earliest, "latest": request.Current.Latest, "observedAt": request.Current.ObservedAt}[name]
		*target, err = time.Parse(time.RFC3339Nano, stamp)
		if err != nil {
			return nil, err
		}
	}
	trust := qualification.Trust{Issuer: request.Trust.Issuer, Threshold: request.Trust.Threshold}
	for _, entry := range request.Trust.Keys {
		key, e := dsse.Decode(entry.PublicKeyBase64, ed25519.PublicKeySize)
		if e != nil || len(key) != ed25519.PublicKeySize {
			return nil, errors.New("invalid probe key")
		}
		roles := entry.Roles
		if entry.Principal == request.Current.Actor {
			roles = nil // proposing actor cannot supply independent evidence/Decision approval
		}
		trust.Keys = append(trust.Keys, dsse.Key{Public: key, Principal: entry.Principal, Issuer: entry.Issuer, Roles: roles})
	}
	// Decoding is bounded by the same fixed input and per-object limits. Missing
	// records are distinct from collection errors; never fetch a caller's URL.
	indexed := map[qualification.OriginalRef]qualification.Original{}
	for _, v := range request.Originals {
		ref := qualification.OriginalRef{Digest: v.Digest, RunID: v.RunID, Attempt: v.Attempt}
		if _, ok := indexed[ref]; ok {
			return nil, errors.New("duplicate original provenance record")
		}
		b, e := dsse.Decode(v.BytesBase64, exactjson.MaxBytes)
		if e != nil {
			return nil, e
		}
		indexed[ref] = qualification.Original{Bytes: b, Producer: v.Producer, Principal: v.Principal, RunID: v.RunID, PlanDigest: v.VerificationPlanDigest, BindingDigest: v.BindingDigest, ConfigDigest: v.ConfigDigest, Shard: v.Shard, Attempt: v.Attempt, AssertionIDs: v.AssertionIDs, CollectionIntact: v.CollectionIntact, DomainStopped: v.DomainStopped}
	}
	current.ReadOriginal = func(ref qualification.OriginalRef) (qualification.Original, error) {
		v, ok := indexed[ref]
		if !ok {
			return qualification.Original{}, qualification.ErrOriginalMissing
		}
		return v, nil
	}
	result, err := qualification.Check(request.Plan, request.EvidenceEnvelope, request.DecisionEnvelope, trust, current)
	if err != nil {
		return nil, err
	}
	// Convert the typed internal result to the codec's explicit wire domain.
	// JCS intentionally does not accept arbitrary host structs or []string.
	resultBytes, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}
	refs, err := exactjson.Parse(resultBytes)
	if err != nil {
		return nil, err
	}
	return map[string]any{"checkedRefs": refs, "authority": false, "qualification": false}, nil
}
