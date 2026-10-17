// Package qualification consumes action-specific native signed evidence. The
// caller must supply an authenticated current control context and a scoped,
// bounded ORIGINAL-byte reader. Supplying these dependencies is not proof of
// an installed trust boundary. No function here signs, authorizes or commits.
package qualification

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"sort"
	"sync"
	"time"

	"github.com/AzzCraft/cadence-oss/cadence-core/internal/dsse"
	"github.com/AzzCraft/cadence-oss/cadence-core/internal/exactjson"
	"github.com/santhosh-tekuri/jsonschema/v5"
)

const EvidenceType = "application/vnd.das.verification-evidence.v1+json"
const DecisionType = "application/vnd.das.action-decision.v1+json"

// Only a scoped, known absent artifact may become an observation exception.
// Read errors, invalid bytes, wrong bindings and collector faults fail closed.
var ErrOriginalMissing = errors.New("qualification: original absent")

// Original metadata is supplied by the installed protected collection store,
// not by an envelope or candidate. Its bytes and metadata must share the same
// immutable, authorized record. The reader must do no network/candidate work.
type Original struct {
	Bytes                                                                      []byte
	Producer, Principal, RunID, PlanDigest, BindingDigest, ConfigDigest, Shard string
	Attempt                                                                    int64
	AssertionIDs                                                               []string
	CollectionIntact, DomainStopped                                            bool
}

// Identical raw bytes may come from distinct real runs. A digest alone cannot
// select their protected provenance records or manufacture independent runs.
type OriginalRef struct {
	Digest, RunID string
	Attempt       int64
}

type Trust struct {
	Issuer    string
	Keys      []dsse.Key
	Threshold int
}
type Current struct {
	Earliest, Latest, ObservedAt               time.Time
	MaxStaleness                               time.Duration
	AuthorityEpoch                             int64
	Actor, Audience, Action                    string
	PlanDigest, EvidenceDigest, DecisionDigest string
	// Complete collected run/attempt history from the protected collection store,
	// never an expected digest derived from the submitted envelope.
	CollectedResultsDigest                          string
	Bindings                                        map[string]any
	TargetGeneration                                int64
	TargetCandidateDigest                           string
	IntegrationReceiptDigest                        *string
	PolicyRevoked, EvidenceRevoked, DecisionRevoked bool
	ReadOriginal                                    func(OriginalRef) (Original, error)
}
type Checked struct {
	VerificationPlanDigest     string   `json:"verificationPlanDigest"`
	VerificationEvidenceDigest string   `json:"verificationEvidenceDigest"`
	DecisionDigest             string   `json:"decisionDigest"`
	ObservationExceptions      []string `json:"observationExceptions"`
}

//go:embed verification_plan.schema.json
var planSchema []byte

//go:embed verification_evidence.schema.json
var evidenceSchema []byte

//go:embed action_decision.schema.json
var decisionSchema []byte

// The published report author remains the Standard; this is a generated copy.
//
//go:embed verify_report.schema.json
var reportSchema []byte

// Separate analysis identities preserve the published integration contracts.
// They share the SAME original-report, run-history and signature consumer.
//
//go:embed analysis_task_binding.schema.json
var analysisTaskSchema []byte

//go:embed analysis_verification_plan.schema.json
var analysisPlanSchema []byte

//go:embed analysis_verification_evidence.schema.json
var analysisEvidenceSchema []byte

//go:embed analysis_action_decision.schema.json
var analysisDecisionSchema []byte

//go:embed analysis_completion.schema.json
var analysisCompletionSchema []byte

// Version switches have no integration receipt or analysis task exemption.
//
//go:embed version_verification_plan.schema.json
var versionPlanSchema []byte

//go:embed version_verification_evidence.schema.json
var versionEvidenceSchema []byte

//go:embed version_action_decision.schema.json
var versionDecisionSchema []byte
var once sync.Once
var schemas map[string]*jsonschema.Schema
var schemaError error

func compile() error {
	once.Do(func() {
		schemas = map[string]*jsonschema.Schema{}
		for identity, data := range map[string][]byte{"das-verification-plan/v1": planSchema, "das-verification-evidence/v1": evidenceSchema, "das-action-decision/v1": decisionSchema, "report": reportSchema,
			"das-analysis-task-binding/v1": analysisTaskSchema, "das-analysis-verification-plan/v1": analysisPlanSchema,
			"das-analysis-verification-evidence/v1": analysisEvidenceSchema, "das-analysis-action-decision/v1": analysisDecisionSchema,
			"das-analysis-completion/v1":           analysisCompletionSchema,
			"das-version-verification-plan/v1":     versionPlanSchema,
			"das-version-verification-evidence/v1": versionEvidenceSchema,
			"das-version-action-decision/v1":       versionDecisionSchema} {
			c := jsonschema.NewCompiler()
			c.Draft = jsonschema.Draft2020
			c.AssertFormat = true
			c.LoadURL = func(string) (io.ReadCloser, error) {
				return nil, errors.New("qualification: external schema forbidden")
			}
			uri := "https://cadence.das.dev/embedded/" + identity
			if schemaError = c.AddResource(uri, bytes.NewReader(data)); schemaError != nil {
				return
			}
			schemas[identity], schemaError = c.Compile(uri)
			if schemaError != nil {
				return
			}
		}
	})
	return schemaError
}
func exactNumbers(value any) (any, error) {
	switch v := value.(type) {
	case json.Number:
		return exactjson.SafeInteger(v)
	case []any:
		for i, x := range v {
			n, e := exactNumbers(x)
			if e != nil {
				return nil, e
			}
			v[i] = n
		}
	case map[string]any:
		for k, x := range v {
			n, e := exactNumbers(x)
			if e != nil {
				return nil, e
			}
			v[k] = n
		}
	}
	return value, nil
}

// Validate preserves the independent exact-parser boundary before any numeric
// JCS conversion. It validates wire shape; it grants no evidence authority.
func Validate(data []byte, identity string) (map[string]any, error) {
	if err := compile(); err != nil {
		return nil, err
	}
	schema, ok := schemas[identity]
	if !ok {
		return nil, errors.New("qualification: unsupported contract")
	}
	value, err := exactjson.Parse(data)
	if err != nil {
		return nil, err
	}
	value, err = exactNumbers(value)
	if err != nil {
		return nil, err
	}
	if err = schema.Validate(value); err != nil {
		return nil, err
	}
	return value.(map[string]any), nil
}
func digestBytes(b []byte) string  { return fmt.Sprintf("sha256:%x", sha256.Sum256(b)) }
func rejected(reason string) error { return errors.New("qualification: " + reason) }
func member(values any, want string) bool {
	for _, v := range values.([]any) {
		if v == want {
			return true
		}
	}
	return false
}
func validWindow(v map[string]any, current Current) bool {
	start, e := time.Parse(time.RFC3339Nano, v["notBefore"].(string))
	if e != nil {
		return false
	}
	end, e := time.Parse(time.RFC3339Nano, v["expiresAt"].(string))
	return e == nil && end.After(start) && !current.Earliest.Before(start) && current.Latest.Before(end)
}
func signed(data []byte, identity, payloadType, role, expected string, trust Trust, current Current) (map[string]any, error) {
	// The actor's own signatures cannot count as independent approval. Preserve
	// all keys for the DSSE duplicate-key checks, including ineligible keys.
	keys := append([]dsse.Key(nil), trust.Keys...)
	for i := range keys {
		if keys[i].Principal == current.Actor {
			keys[i].Roles = nil
		}
	}
	verified, err := dsse.Verify(data, payloadType, trust.Issuer, role, keys, trust.Threshold)
	if err != nil {
		return nil, err
	}
	v, err := Validate(verified.Payload, identity)
	if err != nil {
		return nil, err
	}
	d, err := exactjson.Digest(v)
	if err != nil || d != expected || v["issuer"] != verified.Issuer || v["audience"] != current.Audience || v["authorityEpoch"] != current.AuthorityEpoch || !validWindow(v, current) {
		return nil, rejected("signed context mismatch")
	}
	return v, nil
}

// Check verifies the SAME payload bytes supplied to DSSE, then evaluates the
// approved denominator. Original reports are never rewritten and their old
// expected/overallOutcome semantics remain distinct from action qualification.
// This reference profile supports all-attempts-pass with NO evidence reuse;
// unsupported aggregation is rejected, never interpreted as a waiver.
func Check(planBytes, evidenceEnvelope, decisionEnvelope []byte, trust Trust, current Current) (Checked, error) {
	var empty Checked
	planIdentity, evidenceIdentity, decisionIdentity := "das-verification-plan/v1", "das-verification-evidence/v1", "das-action-decision/v1"
	evidenceType, decisionType := EvidenceType, DecisionType
	analysis := current.Bindings["completionMode"] == "analysis"
	version := current.Bindings["versionPlanDigest"] != nil
	if analysis {
		planIdentity, evidenceIdentity, decisionIdentity = "das-analysis-verification-plan/v1", "das-analysis-verification-evidence/v1", "das-analysis-action-decision/v1"
		evidenceType, decisionType = "application/vnd.das.analysis-verification-evidence.v1+json", "application/vnd.das.analysis-action-decision.v1+json"
	} else if version {
		planIdentity, evidenceIdentity, decisionIdentity = "das-version-verification-plan/v1", "das-version-verification-evidence/v1", "das-version-action-decision/v1"
		evidenceType, decisionType = "application/vnd.das.version-verification-evidence.v1+json", "application/vnd.das.version-action-decision.v1+json"
	}
	if current.Earliest.IsZero() || current.Latest.Before(current.Earliest) || current.ObservedAt.IsZero() || current.ObservedAt.After(current.Earliest) || current.MaxStaleness <= 0 || current.MaxStaleness > 30*time.Second || current.Latest.Sub(current.ObservedAt) > current.MaxStaleness || current.AuthorityEpoch < 1 || current.Actor == "" || current.Audience == "" || current.ReadOriginal == nil || current.PolicyRevoked || current.EvidenceRevoked || current.DecisionRevoked {
		return empty, rejected("unavailable or revoked current context")
	}
	plan, err := Validate(planBytes, planIdentity)
	if err != nil {
		return empty, rejected("verification plan encoding rejected")
	}
	d, err := exactjson.Digest(plan)
	if err != nil || d != current.PlanDigest || !member(plan["actions"], current.Action) {
		return empty, rejected("unapproved plan or action")
	}
	// Comparison uses the full exact tuple, not a selected subset of fields.
	bindings := plan["bindings"].(map[string]any)
	bindingBytes, err := exactjson.Canonical(bindings)
	if err != nil {
		return empty, err
	}
	expected, err := exactjson.Canonical(current.Bindings)
	if err != nil || !bytes.Equal(bindingBytes, expected) {
		return empty, rejected("current binding mismatch")
	}
	if current.Action == "audit" {
		// Reverification is a separate purpose, bound to original Completion
		// and the exact noncircular audit scope. Never infer it from complete.
		if version || bindings["completionDigest"] == nil || bindings["verificationScopeDigest"] == nil ||
			current.TargetGeneration != bindings["targetGeneration"].(int64) ||
			current.TargetCandidateDigest != bindings["baselineCandidateDigest"] ||
			current.IntegrationReceiptDigest != nil ||
			(!analysis && current.TargetCandidateDigest != bindings["integratedCandidateDigest"]) {
			return empty, rejected("verification-only current target or purpose mismatch")
		}
	} else if bindings["completionDigest"] != nil || bindings["verificationScopeDigest"] != nil {
		return empty, rejected("verification-only evidence cannot authorize business work")
	} else if version {
		if (current.Action != "apply" && current.Action != "rollback") || current.IntegrationReceiptDigest != nil || current.TargetGeneration != bindings["targetGeneration"].(int64) || current.TargetCandidateDigest != bindings["baselineCandidateDigest"] {
			return empty, rejected("version switch preimage or purpose mismatch")
		}
	} else if analysis {
		if current.Action != "complete" || current.IntegrationReceiptDigest != nil || current.TargetGeneration != bindings["targetGeneration"].(int64) || current.TargetCandidateDigest != bindings["baselineCandidateDigest"] {
			return empty, rejected("analysis current baseline or purpose mismatch")
		}
	} else if current.Action == "integrate" {
		if current.IntegrationReceiptDigest != nil || current.TargetGeneration != bindings["targetGeneration"].(int64) || current.TargetCandidateDigest != bindings["baselineCandidateDigest"] {
			return empty, rejected("integration preimage mismatch")
		}
	} else if current.Action == "complete" {
		if current.IntegrationReceiptDigest == nil || current.TargetGeneration != bindings["targetGeneration"].(int64)+1 || current.TargetCandidateDigest != bindings["integratedCandidateDigest"] {
			return empty, rejected("Completion postimage mismatch")
		}
	} else {
		return empty, rejected("unsupported action")
	}
	evidence, err := signed(evidenceEnvelope, evidenceIdentity, evidenceType, "evidence_issuer", current.EvidenceDigest, trust, current)
	if err != nil {
		return empty, rejected("native evidence verification rejected")
	}
	decision, err := signed(decisionEnvelope, decisionIdentity, decisionType, "decision_issuer", current.DecisionDigest, trust, current)
	if err != nil {
		return empty, rejected("native Decision verification rejected")
	}
	for _, v := range []map[string]any{evidence, decision} {
		if v["verificationPlanDigest"] != d || !reflect.DeepEqual(v["bindings"], bindings) {
			return empty, rejected("cross-context evidence")
		}
	}
	var receipt any
	resultsDigest, err := exactjson.Digest(evidence["results"])
	if err != nil || resultsDigest != current.CollectedResultsDigest {
		return empty, rejected("incomplete or changed collected run history")
	}
	if current.IntegrationReceiptDigest != nil {
		receipt = *current.IntegrationReceiptDigest
	}
	if decision["actor"] != current.Actor || decision["action"] != current.Action || decision["verificationEvidenceDigest"] != current.EvidenceDigest || decision["targetGeneration"] != current.TargetGeneration || decision["targetCandidateDigest"] != current.TargetCandidateDigest || decision["integrationReceiptDigest"] != receipt || decision["allow"] != true {
		return empty, rejected("action Decision mismatch")
	}
	slots := map[string]map[string]any{}
	hasRequired := false
	for _, raw := range plan["slots"].([]any) {
		s := raw.(map[string]any)
		id := s["slotId"].(string)
		if slots[id] != nil || s["minIndependentRuns"].(int64) > s["maxAttempts"].(int64) {
			return empty, rejected("invalid plan denominator")
		}
		slots[id] = s
		hasRequired = hasRequired || member(s["requiredForActions"], current.Action)
		for _, a := range s["requiredForActions"].([]any) {
			if !member(plan["actions"], a.(string)) || member(s["observationSafeForActions"], a.(string)) {
				return empty, rejected("contradictory slot scope")
			}
		}
		for _, a := range s["observationSafeForActions"].([]any) {
			if !member(plan["actions"], a.(string)) {
				return empty, rejected("unknown observation action")
			}
		}
	}
	if !hasRequired {
		return empty, rejected("empty required action denominator")
	}
	totalBytes := 0
	originals := map[OriginalRef]Original{}
	read := func(hash, run string, attempt int64) (Original, error) {
		ref := OriginalRef{hash, run, attempt}
		if v, ok := originals[ref]; ok {
			return v, nil
		}
		v, e := current.ReadOriginal(ref)
		if e != nil {
			return Original{}, e
		}
		if len(v.Bytes) > exactjson.MaxBytes || digestBytes(v.Bytes) != hash || v.BindingDigest != digestBytes(bindingBytes) || v.PlanDigest != d {
			return Original{}, rejected("invalid or unbound original")
		}
		totalBytes += len(v.Bytes)
		if len(originals) >= 512 || totalBytes > 16*1024*1024 {
			return Original{}, rejected("original-byte budget exceeded")
		}
		originals[ref] = v
		return v, nil
	}
	seen := map[string]bool{}
	runs := map[string]map[string]bool{}
	counts := map[string]int64{}
	failed := map[string]bool{}
	exception := map[string]bool{}
	for _, raw := range evidence["results"].([]any) {
		r := raw.(map[string]any)
		id := r["slotId"].(string)
		slot := slots[id]
		if slot == nil {
			return empty, rejected("unapproved result slot")
		}
		index := r["reportGateIndex"].(int64)
		identity := fmt.Sprintf("%s/%d/%d", r["runId"], r["attempt"], index)
		// A retransmitted source result cannot manufacture independent samples.
		if seen[identity] {
			return empty, rejected("duplicate source result")
		}
		seen[identity] = true
		if runs[id] == nil {
			runs[id] = map[string]bool{}
		}
		runs[id][r["runId"].(string)] = true
		counts[id]++
		original, e := read(r["reportDigest"].(string), r["runId"].(string), r["attempt"].(int64))
		if e != nil {
			return empty, e
		}
		assertions := []string{}
		for _, value := range slot["assertionIds"].([]any) {
			assertions = append(assertions, value.(string))
		}
		if original.Producer != "protected_driver" || original.Principal == "" || original.Principal == current.Actor || !original.CollectionIntact || !original.DomainStopped || original.RunID != r["runId"] || original.Attempt != r["attempt"] || original.ConfigDigest != slot["configDigest"] || original.Shard != slot["shard"] || !reflect.DeepEqual(original.AssertionIDs, assertions) {
			return empty, rejected("untrusted or incomplete collection")
		}
		report, e := Validate(original.Bytes, "report")
		if e != nil {
			return empty, rejected("invalid original report")
		}
		gates := report["gates"].([]any)
		if index >= int64(len(gates)) {
			return empty, rejected("missing original result")
		}
		gate := gates[index].(map[string]any)
		if gate["gateId"] != slot["gateId"] {
			return empty, rejected("wrong original gate")
		}
		pass := gate["executed"] == true && gate["outcome"] == "pass"
		if gate["failureOnNoResults"] == true && gate["artifactCount"] == int64(0) {
			pass = false
		}
		if member(plan["requireOverallSuccessForActions"], current.Action) && report["overallOutcome"] != "pass" {
			return empty, rejected("required overall verify did not pass")
		}
		artifacts := r["artifactDigests"].(map[string]any)
		for name, hash := range artifacts {
			if !member(slot["artifactIds"], name) {
				return empty, rejected("unapproved artifact")
			}
			v, e := read(hash.(string), r["runId"].(string), r["attempt"].(int64))
			if errors.Is(e, ErrOriginalMissing) {
				pass = false
				continue
			}
			if e != nil {
				return empty, e
			}
			if (v.Producer != "candidate_raw" && v.Producer != "protected_driver" && v.Producer != "supervisor") || v.Principal == "" || v.RunID != r["runId"] || v.Attempt != r["attempt"] || !v.CollectionIntact || !v.DomainStopped {
				return empty, rejected("artifact source mismatch")
			}
		}
		for _, name := range slot["artifactIds"].([]any) {
			if _, ok := artifacts[name.(string)]; !ok {
				pass = false
			}
		}
		if !pass {
			failed[id] = true
		}
	}
	for id, slot := range slots {
		if counts[id] == 0 || counts[id] > slot["maxAttempts"].(int64) {
			return empty, rejected("omitted slot or exceeded attempts")
		}
		if int64(len(runs[id])) < slot["minIndependentRuns"].(int64) {
			failed[id] = true
		}
		if failed[id] {
			if member(slot["requiredForActions"], current.Action) || !member(slot["observationSafeForActions"], current.Action) {
				return empty, rejected("unsatisfied required result")
			}
			exception[id] = true
		}
	}
	exceptions := []string{}
	for id := range exception {
		exceptions = append(exceptions, id)
	}
	sort.Strings(exceptions)
	claimed := []string{}
	for _, v := range decision["observationExceptions"].([]any) {
		claimed = append(claimed, v.(string))
	}
	if !reflect.DeepEqual(claimed, exceptions) {
		return empty, rejected("Decision hides or invents observation exceptions")
	}
	return Checked{d, current.EvidenceDigest, current.DecisionDigest, exceptions}, nil
}
