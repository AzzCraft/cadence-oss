package qualification

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AzzCraft/cadence-oss/cadence-core/internal/dsse"
	"github.com/AzzCraft/cadence-oss/cadence-core/internal/exactjson"
)

func jsonBytes(t *testing.T, v any) []byte {
	t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func object(t *testing.T, name string) map[string]any {
	t.Helper()
	b, e := os.ReadFile(filepath.Join("..", "..", "..", "cadence-protocol", "fixtures", "das_v1_5", "valid", name+".json"))
	if e != nil {
		t.Fatal(e)
	}
	v, e := Validate(b, "das-"+strings.ReplaceAll(name, "_", "-")+"/v1")
	if e != nil {
		t.Fatal(e)
	}
	return v
}
func hash(t *testing.T, v any) string {
	t.Helper()
	d, e := exactjson.Digest(v)
	if e != nil {
		t.Fatal(e)
	}
	return d
}

// Public, deterministic TEST identity only. No production signer is introduced.
func sign(t *testing.T, v any, typ string) []byte {
	t.Helper()
	b := jsonBytes(t, v)
	pae, e := dsse.PAE(typ, b)
	if e != nil {
		t.Fatal(e)
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, 32))
	return jsonBytes(t, map[string]any{"payloadType": typ, "payload": base64.StdEncoding.EncodeToString(b), "signatures": []any{map[string]any{"sig": base64.StdEncoding.EncodeToString(ed25519.Sign(key, pae))}}})
}

type fixture struct {
	plan, evidence, decision map[string]any
	current                  Current
	trust                    Trust
	originals                map[string]Original
}

func setup(t *testing.T) fixture {
	t.Helper()
	plan := object(t, "verification_plan")
	evidence := object(t, "verification_evidence")
	decision := object(t, "action_decision")
	b := plan["bindings"].(map[string]any)
	b["baselineCandidateDigest"] = "sha256:" + strings.Repeat("b", 64)
	b["sourceCandidateDigest"] = "sha256:" + strings.Repeat("c", 64)
	b["integratedCandidateDigest"] = "sha256:" + strings.Repeat("d", 64)
	planDigest := hash(t, plan)
	evidence["verificationPlanDigest"] = planDigest
	evidence["bindings"] = b
	decision["bindings"] = b
	decision["targetCandidateDigest"] = b["baselineCandidateDigest"]
	raw, e := os.ReadFile(filepath.Join("..", "..", "..", "cadence-protocol", "fixtures", "das_v1_5", "qualification_verify_report.json"))
	if e != nil {
		t.Fatal(e)
	}
	report, e := Validate(raw, "report")
	if e != nil {
		t.Fatal(e)
	}
	report["overallOutcome"] = "pass"
	report["gates"] = []any{map[string]any{"gateId": "TEST-driver-check", "cadence": "pr_blocking", "enforcementClass": "blocking", "expected": false, "executed": true, "outcome": "pass", "artifactCount": int64(1), "failureOnNoResults": true}}
	raw = jsonBytes(t, report)
	output := []byte("TEST original output bytes")
	row := evidence["results"].([]any)[0].(map[string]any)
	row["reportDigest"] = digestBytes(raw)
	row["artifactDigests"] = map[string]any{"original-output": digestBytes(output)}
	bindHash := hash(t, b)
	original := Original{Bytes: raw, Producer: "protected_driver", Principal: "TEST-driver", RunID: "TEST-run", PlanDigest: planDigest, BindingDigest: bindHash, ConfigDigest: b["toolDigest"].(string), Shard: "whole", Attempt: 1, AssertionIDs: []string{"TEST-assertion"}, CollectionIntact: true, DomainStopped: true}
	artifact := original
	artifact.Bytes = output
	artifact.Producer = "candidate_raw"
	artifact.Principal = "TEST-actor"
	originals := map[string]Original{digestBytes(raw): original, digestBytes(output): artifact}
	now := time.Date(2026, 10, 6, 0, 5, 0, 0, time.UTC)
	current := Current{Earliest: now, Latest: now.Add(time.Second), ObservedAt: now.Add(-time.Second), MaxStaleness: 5 * time.Second, AuthorityEpoch: 1, Actor: "TEST-actor", Audience: "TEST-consumer", Action: "integrate", PlanDigest: planDigest, Bindings: b, TargetGeneration: 1, TargetCandidateDigest: b["baselineCandidateDigest"].(string)}
	current.CollectedResultsDigest = hash(t, evidence["results"])
	current.ReadOriginal = func(ref OriginalRef) (Original, error) {
		v, ok := originals[ref.Digest]
		if !ok {
			return Original{}, ErrOriginalMissing
		}
		return v, nil
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, 32))
	trust := Trust{"TEST-issuer", []dsse.Key{{Public: key.Public().(ed25519.PublicKey), Principal: "TEST-independent-signer", Issuer: "TEST-issuer", Roles: []string{"evidence_issuer", "decision_issuer"}}}, 1}
	return fixture{plan, evidence, decision, current, trust, originals}
}
func (f *fixture) check(t *testing.T) (Checked, error) {
	t.Helper()
	f.current.EvidenceDigest = hash(t, f.evidence)
	f.decision["verificationPlanDigest"] = f.current.PlanDigest
	f.decision["verificationEvidenceDigest"] = f.current.EvidenceDigest
	f.current.DecisionDigest = hash(t, f.decision)
	return Check(jsonBytes(t, f.plan), sign(t, f.evidence, EvidenceType), sign(t, f.decision, DecisionType), f.trust, f.current)
}
func TestNativeSignedEvidenceToExactActionDecision(t *testing.T) {
	f := setup(t)
	checked, e := f.check(t)
	if e != nil || checked.VerificationPlanDigest != f.current.PlanDigest || len(checked.ObservationExceptions) != 0 {
		t.Fatal(e, checked)
	}
	// The retained original report deliberately has expected=false. It does not
	// redefine the approved required denominator or prevent genuine execution.
	row := f.evidence["results"].([]any)[0].(map[string]any)
	if !bytes.Contains(f.originals[row["reportDigest"].(string)].Bytes, []byte(`"expected":false`)) {
		t.Fatal("raw report changed")
	}
	for _, name := range []string{"verification_plan", "verification_evidence", "action_decision"} {
		data, e := os.ReadFile(filepath.Join("..", "..", "..", "cadence-protocol", "fixtures", "das_v1_5", "invalid", name+".json"))
		if e != nil {
			t.Fatal(e)
		}
		if _, e = Validate(data, "das-"+strings.ReplaceAll(name, "_", "-")+"/v1"); e == nil {
			t.Fatal("invalid fixture accepted", name)
		}
	}
}

// Signature validity is independent of current candidate/closure authority.
// This TEST mechanism does not approve a published package or a release channel.
func TestDistinctSignedCandidateClosuresNeverMixOrReplay(t *testing.T) {
	evidenceDir := t.TempDir()
	if root := os.Getenv("DAS_V15_DRIVER_EVIDENCE_DIR"); root != "" {
		evidenceDir = filepath.Join(root, "a31-signed-closures")
		if err := os.Mkdir(evidenceDir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	save := func(name string, data []byte) {
		file, err := os.OpenFile(filepath.Join(evidenceDir, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			t.Fatal(err)
		}
		_, writeErr := file.Write(data)
		closeErr := file.Close()
		if writeErr != nil || closeErr != nil {
			t.Fatal(writeErr, closeErr)
		}
	}
	prepare := func(label string, generation int64) fixture {
		f := setup(t)
		candidate := []byte("TEST actual candidate " + label + "\n")
		path := filepath.Join(evidenceDir, "candidate-"+label+".txt")
		save("candidate-"+label+".txt", candidate)
		actual, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		binding := f.plan["bindings"].(map[string]any)
		binding["sourceCandidateDigest"] = digestBytes(actual)
		binding["integratedCandidateDigest"] = digestBytes(append([]byte("TEST integrated "), actual...))
		binding["targetGeneration"] = generation
		f.current.TargetGeneration = generation
		f.decision["targetGeneration"] = generation
		f.current.PlanDigest = hash(t, f.plan)
		f.evidence["verificationPlanDigest"] = f.current.PlanDigest
		for id, original := range f.originals {
			original.PlanDigest = f.current.PlanDigest
			original.BindingDigest = hash(t, binding)
			f.originals[id] = original
		}
		if _, err := f.check(t); err != nil {
			t.Fatal("complete legitimate TEST closure rejected", label, err)
		}
		return f
	}
	a, b := prepare("A", 1), prepare("B", 2)
	fixtures := []fixture{a, b}
	plans, evidences, decisions := make([][]byte, 2), make([][]byte, 2), make([][]byte, 2)
	for i, f := range fixtures {
		plans[i], evidences[i], decisions[i] = jsonBytes(t, f.plan), sign(t, f.evidence, EvidenceType), sign(t, f.decision, DecisionType)
		save(fmt.Sprintf("plan-%d.json", i), plans[i])
		save(fmt.Sprintf("evidence-%d.json", i), evidences[i])
		save(fmt.Sprintf("decision-%d.json", i), decisions[i])
		save(fmt.Sprintf("originals-%d.json", i), jsonBytes(t, f.originals))
		for _, signed := range []struct {
			envelope          []byte
			payloadType, role string
		}{{evidences[i], EvidenceType, "evidence_issuer"}, {decisions[i], DecisionType, "decision_issuer"}} {
			if _, err := dsse.Verify(signed.envelope, signed.payloadType, f.trust.Issuer, signed.role, f.trust.Keys, f.trust.Threshold); err != nil {
				t.Fatal("negative control contains an invalid signature", err)
			}
		}
	}
	for _, current := range []int{0, 1} {
		for p := range fixtures {
			for e := range fixtures {
				for d := range fixtures {
					name := fmt.Sprintf("current-%d/plan-%d/evidence-%d/decision-%d", current, p, e, d)
					t.Run(name, func(t *testing.T) {
						_, err := Check(plans[p], evidences[e], decisions[d], fixtures[current].trust, fixtures[current].current)
						legal := p == current && e == current && d == current
						if (err == nil) != legal {
							t.Fatal("mixed/replayed valid signatures changed current closure authority", legal, err)
						}
					})
				}
			}
		}
	}
}

func TestCompletedWorkAuditHasIndependentPurposeAndExactSubject(t *testing.T) {
	for _, analysis := range []bool{false, true} {
		kind := "integration"
		if analysis {
			kind = "analysis"
		}
		for _, fault := range []string{"none", "business-purpose", "mixed-actions", "wrong-completion", "missing-scope", "target-moved", "fake-receipt", "missing-original", "self-signer"} {
			t.Run(kind+"/"+fault, func(t *testing.T) {
				f := setup(t)
				b := f.plan["bindings"].(map[string]any)
				b["completionDigest"] = "sha256:" + strings.Repeat("4", 64)
				b["verificationScopeDigest"] = "sha256:" + strings.Repeat("5", 64)
				b["integratedCandidateDigest"] = b["baselineCandidateDigest"]
				evidenceType, decisionType := EvidenceType, DecisionType
				if analysis {
					delete(b, "integratedCandidateDigest")
					b["completionMode"], b["taskBindingDigest"] = "analysis", "sha256:"+strings.Repeat("6", 64)
					f.plan["contractIdentity"] = "das-analysis-verification-plan/v1"
					f.evidence["contractIdentity"] = "das-analysis-verification-evidence/v1"
					f.decision["contractIdentity"] = "das-analysis-action-decision/v1"
					evidenceType, decisionType = "application/vnd.das.analysis-verification-evidence.v1+json", "application/vnd.das.analysis-action-decision.v1+json"
				}
				f.plan["actions"], f.plan["requireOverallSuccessForActions"] = []any{"audit"}, []any{"audit"}
				for _, raw := range f.plan["slots"].([]any) {
					slot := raw.(map[string]any)
					slot["requiredForActions"], slot["observationSafeForActions"] = []any{"audit"}, []any{}
				}
				f.current.Action, f.decision["action"] = "audit", "audit"
				switch fault {
				case "business-purpose":
					f.current.Action, f.decision["action"] = "complete", "complete"
				case "mixed-actions":
					f.plan["actions"] = []any{"audit", "complete"}
				case "missing-scope":
					delete(b, "verificationScopeDigest")
				case "target-moved":
					f.current.TargetGeneration++
				case "fake-receipt":
					ref := hash(t, f.plan)
					f.current.IntegrationReceiptDigest = &ref
				case "missing-original":
					f.current.ReadOriginal = func(OriginalRef) (Original, error) { return Original{}, ErrOriginalMissing }
				case "self-signer":
					f.trust.Keys[0].Principal = f.current.Actor
				}
				f.current.PlanDigest = hash(t, f.plan)
				f.evidence["verificationPlanDigest"] = f.current.PlanDigest
				if fault == "wrong-completion" {
					other := map[string]any{}
					for key, value := range b {
						other[key] = value
					}
					other["completionDigest"] = "sha256:" + strings.Repeat("7", 64)
					f.evidence["bindings"] = other
				}
				for key, original := range f.originals {
					original.PlanDigest, original.BindingDigest = f.current.PlanDigest, hash(t, b)
					f.originals[key] = original
				}
				f.current.EvidenceDigest = hash(t, f.evidence)
				f.decision["verificationPlanDigest"], f.decision["verificationEvidenceDigest"] = f.current.PlanDigest, f.current.EvidenceDigest
				f.current.DecisionDigest = hash(t, f.decision)
				_, err := Check(jsonBytes(t, f.plan), sign(t, f.evidence, evidenceType), sign(t, f.decision, decisionType), f.trust, f.current)
				if (err == nil) != (fault == "none") {
					t.Fatal(fault, err)
				}
			})
		}
	}
}

func TestAnalysisUsesSameConsumerWithoutIntegrationSurrogate(t *testing.T) {
	for _, fault := range []string{"none", "wrong-purpose", "fake-receipt", "postimage", "old-envelope", "missing-original", "self-approval"} {
		t.Run(fault, func(t *testing.T) {
			f := setup(t)
			bindings := f.plan["bindings"].(map[string]any)
			delete(bindings, "integratedCandidateDigest")
			bindings["completionMode"] = "analysis"
			bindings["taskBindingDigest"] = "sha256:" + strings.Repeat("1", 64)
			f.plan["contractIdentity"] = "das-analysis-verification-plan/v1"
			f.plan["actions"] = []any{"complete"}
			f.plan["requireOverallSuccessForActions"] = []any{"complete"}
			for _, raw := range f.plan["slots"].([]any) {
				slot := raw.(map[string]any)
				slot["requiredForActions"], slot["observationSafeForActions"] = []any{"complete"}, []any{}
			}
			f.evidence["contractIdentity"] = "das-analysis-verification-evidence/v1"
			f.decision["contractIdentity"], f.decision["action"] = "das-analysis-action-decision/v1", "complete"
			f.current.Action, f.current.PlanDigest = "complete", hash(t, f.plan)
			f.evidence["verificationPlanDigest"] = f.current.PlanDigest
			f.current.EvidenceDigest = hash(t, f.evidence)
			f.decision["verificationPlanDigest"], f.decision["verificationEvidenceDigest"] = f.current.PlanDigest, f.current.EvidenceDigest
			f.current.DecisionDigest = hash(t, f.decision)
			for key, original := range f.originals {
				original.PlanDigest, original.BindingDigest = f.current.PlanDigest, hash(t, bindings)
				f.originals[key] = original
			}
			evidenceType := "application/vnd.das.analysis-verification-evidence.v1+json"
			decisionType := "application/vnd.das.analysis-action-decision.v1+json"
			switch fault {
			case "wrong-purpose":
				f.current.Action = "integrate"
			case "fake-receipt":
				receipt := hash(t, f.plan)
				f.current.IntegrationReceiptDigest = &receipt
			case "postimage":
				f.current.TargetGeneration++
			case "old-envelope":
				evidenceType = EvidenceType
			case "missing-original":
				f.current.ReadOriginal = func(OriginalRef) (Original, error) { return Original{}, ErrOriginalMissing }
			case "self-approval":
				f.trust.Keys[0].Principal = f.current.Actor
			}
			_, err := Check(jsonBytes(t, f.plan), sign(t, f.evidence, evidenceType), sign(t, f.decision, decisionType), f.trust, f.current)
			if (err == nil) != (fault == "none") {
				t.Fatal(fault, err)
			}
		})
	}
}

func TestAnObservationOnlyPlanCannotAuthorizeAnEmptyRequiredDenominator(t *testing.T) {
	f := setup(t)
	slot := f.plan["slots"].([]any)[0].(map[string]any)
	slot["requiredForActions"] = []any{}
	slot["observationSafeForActions"] = []any{"integrate", "complete"}
	f.current.PlanDigest = hash(t, f.plan)
	f.evidence["verificationPlanDigest"] = f.current.PlanDigest
	for id, v := range f.originals {
		v.PlanDigest = f.current.PlanDigest
		f.originals[id] = v
	}
	if _, e := f.check(t); e == nil {
		t.Fatal("an observation-only plan manufactured action qualification")
	}
}
func TestCurrentQualificationAndSourcesFailClosed(t *testing.T) {
	for _, kind := range []string{"actor", "audience", "action", "epoch", "policy-revoked", "evidence-revoked", "decision-revoked", "stale", "backwards", "expiry-boundary", "unavailable-reader", "plan-digest", "bindings", "target", "target-generation", "submit-decision", "allow-false", "missing-artifact", "missing-report", "bad-report-bytes", "candidate-pass", "same-actor-driver", "writer-active", "collection-failed", "wrong-config", "wrong-shard", "wrong-assertions", "wrong-run", "wrong-attempt", "omitted-slot", "duplicate-result", "fraction", "wrong-protocol"} {
		t.Run(kind, func(t *testing.T) {
			f := setup(t)
			row := f.evidence["results"].([]any)[0].(map[string]any)
			reportHash := row["reportDigest"].(string)
			original := f.originals[reportHash]
			switch kind {
			case "actor":
				f.current.Actor = "other"
			case "audience":
				f.current.Audience = "other"
			case "action":
				f.current.Action = "complete"
			case "epoch":
				f.current.AuthorityEpoch++
			case "policy-revoked":
				f.current.PolicyRevoked = true
			case "evidence-revoked":
				f.current.EvidenceRevoked = true
			case "decision-revoked":
				f.current.DecisionRevoked = true
			case "stale":
				f.current.ObservedAt = f.current.Earliest.Add(-time.Minute)
			case "backwards":
				f.current.Latest = f.current.Earliest.Add(-time.Second)
			case "expiry-boundary":
				f.current.Latest = f.current.Latest.Add(5 * time.Minute)
			case "unavailable-reader":
				f.current.ReadOriginal = nil
			case "plan-digest":
				f.current.PlanDigest = "sha256:" + strings.Repeat("e", 64)
			case "bindings":
				f.current.Bindings = map[string]any{}
			case "target":
				f.current.TargetCandidateDigest = "sha256:" + strings.Repeat("a", 64)
			case "target-generation":
				f.current.TargetGeneration++
			case "submit-decision":
				f.decision["action"] = "submit"
			case "allow-false":
				f.decision["allow"] = false
			case "missing-artifact":
				row["artifactDigests"] = map[string]any{}
			case "missing-report":
				delete(f.originals, reportHash)
			case "bad-report-bytes":
				original.Bytes = []byte("{}")
				f.originals[reportHash] = original
			case "candidate-pass":
				original.Producer = "candidate_raw"
				f.originals[reportHash] = original
			case "same-actor-driver":
				original.Principal = f.current.Actor
				f.originals[reportHash] = original
			case "writer-active":
				original.DomainStopped = false
				f.originals[reportHash] = original
			case "collection-failed":
				original.CollectionIntact = false
				f.originals[reportHash] = original
			case "wrong-config":
				original.ConfigDigest = "sha256:" + strings.Repeat("a", 64)
				f.originals[reportHash] = original
			case "wrong-shard":
				original.Shard = "other"
				f.originals[reportHash] = original
			case "wrong-assertions":
				original.AssertionIDs = []string{"other"}
				f.originals[reportHash] = original
			case "wrong-run":
				original.RunID = "other"
				f.originals[reportHash] = original
			case "wrong-attempt":
				original.Attempt++
				f.originals[reportHash] = original
			case "omitted-slot":
				f.evidence["results"] = []any{}
			case "duplicate-result":
				f.evidence["results"] = []any{row, row}
			case "fraction":
				row["attempt"] = json.Number("1.000000000000000001")
			case "wrong-protocol":
				f.check(t)
				_, e := Check(jsonBytes(t, f.plan), sign(t, f.evidence, DecisionType), sign(t, f.decision, DecisionType), f.trust, f.current)
				if e == nil {
					t.Fatal("cross-purpose signature accepted")
				}
				return
			}
			if _, e := f.check(t); e == nil {
				t.Fatal("invalid current qualification accepted", kind)
			}
		})
	}
}
func observation(t *testing.T, f *fixture) {
	t.Helper()
	slot := f.plan["slots"].([]any)[0].(map[string]any)
	observed := map[string]any{}
	for k, v := range slot {
		observed[k] = v
	}
	observed["slotId"] = "observation"
	observed["gateId"] = "TEST-observation"
	observed["requiredForActions"] = []any{}
	observed["observationSafeForActions"] = []any{"integrate", "complete"}
	f.plan["slots"] = []any{slot, observed}
	f.current.PlanDigest = hash(t, f.plan)
	f.evidence["verificationPlanDigest"] = f.current.PlanDigest
	for id, v := range f.originals {
		v.PlanDigest = f.current.PlanDigest
		f.originals[id] = v
	}
	row := map[string]any{}
	for k, v := range f.evidence["results"].([]any)[0].(map[string]any) {
		row[k] = v
	}
	row["slotId"] = "observation"
	row["runId"] = "TEST-observed-run"
	row["artifactDigests"] = map[string]any{}
	old := f.originals[f.evidence["results"].([]any)[0].(map[string]any)["reportDigest"].(string)]
	report, e := Validate(old.Bytes, "report")
	if e != nil {
		t.Fatal(e)
	}
	gate := report["gates"].([]any)[0].(map[string]any)
	gate["gateId"] = "TEST-observation"
	gate["expected"] = true
	gate["executed"] = false
	gate["outcome"] = "not_run"
	gate["artifactCount"] = int64(0)
	report["overallOutcome"] = "fail"
	old.Bytes = jsonBytes(t, report)
	old.RunID = "TEST-observed-run"
	row["reportDigest"] = digestBytes(old.Bytes)
	f.originals[row["reportDigest"].(string)] = old
	f.evidence["results"] = append(f.evidence["results"].([]any), row)
	f.current.CollectedResultsDigest = hash(t, f.evidence["results"])
	f.decision["observationExceptions"] = []any{"observation"}
}
func TestApprovedObservationFailuresRemainVisibleWithoutFalsifyingReports(t *testing.T) {
	f := setup(t)
	observation(t, &f)
	checked, e := f.check(t)
	if e != nil || len(checked.ObservationExceptions) != 1 {
		t.Fatal(e, checked)
	}
	for _, kind := range []string{"hidden", "required", "omitted", "collection-fault", "reader-fault", "overall-required"} {
		t.Run(kind, func(t *testing.T) {
			f := setup(t)
			observation(t, &f)
			switch kind {
			case "hidden":
				f.decision["observationExceptions"] = []any{}
			case "required":
				f.plan["slots"].([]any)[1].(map[string]any)["requiredForActions"] = []any{"integrate"}
			case "omitted":
				f.evidence["results"] = f.evidence["results"].([]any)[:1]
			case "collection-fault":
				row := f.evidence["results"].([]any)[1].(map[string]any)
				h := row["reportDigest"].(string)
				v := f.originals[h]
				v.CollectionIntact = false
				f.originals[h] = v
			case "reader-fault":
				f.current.ReadOriginal = func(OriginalRef) (Original, error) { return Original{}, errors.New("protected collector failed") }
			case "overall-required":
				f.plan["requireOverallSuccessForActions"] = []any{"integrate"}
			}
			// Reapprove only the changed TEST plan, retaining its original metadata.
			f.current.PlanDigest = hash(t, f.plan)
			f.evidence["verificationPlanDigest"] = f.current.PlanDigest
			for id, v := range f.originals {
				v.PlanDigest = f.current.PlanDigest
				f.originals[id] = v
			}
			if _, e := f.check(t); e == nil {
				t.Fatal("observation escaped its approved scope")
			}
		})
	}
}
func TestCompletionHasDistinctCurrentDecisionAndNativeReceipt(t *testing.T) {
	f := setup(t)
	receipt := "sha256:" + strings.Repeat("f", 64)
	f.current.Action = "complete"
	f.current.TargetGeneration = 2
	f.current.TargetCandidateDigest = f.current.Bindings["integratedCandidateDigest"].(string)
	f.current.IntegrationReceiptDigest = &receipt
	if _, e := f.check(t); e == nil {
		t.Fatal("integration Decision became Completion permission")
	}
	f.decision["action"] = "complete"
	f.decision["targetGeneration"] = int64(2)
	f.decision["targetCandidateDigest"] = f.current.TargetCandidateDigest
	f.decision["integrationReceiptDigest"] = receipt
	if _, e := f.check(t); e != nil {
		t.Fatal(e)
	}
	old := f.current.TargetGeneration
	f.current.TargetGeneration = old + 2
	if _, e := f.check(t); e == nil {
		t.Fatal("ABA target reused old evidence")
	}
}

func TestRetryCannotHideTheOriginalFailureOrCountOneRunAsTwo(t *testing.T) {
	f := setup(t)
	slot := f.plan["slots"].([]any)[0].(map[string]any)
	slot["maxAttempts"] = int64(2)
	f.current.PlanDigest = hash(t, f.plan)
	f.evidence["verificationPlanDigest"] = f.current.PlanDigest
	first := f.evidence["results"].([]any)[0].(map[string]any)
	second := map[string]any{}
	for k, v := range first {
		second[k] = v
	}
	second["runId"] = "TEST-second-run"
	second["attempt"] = int64(2)
	firstOriginal := f.originals[first["reportDigest"].(string)]
	report, e := Validate(firstOriginal.Bytes, "report")
	if e != nil {
		t.Fatal(e)
	}
	report["gates"].([]any)[0].(map[string]any)["outcome"] = "fail"
	report["overallOutcome"] = "fail"
	firstOriginal.Bytes = jsonBytes(t, report)
	first["reportDigest"] = digestBytes(firstOriginal.Bytes)
	f.originals[first["reportDigest"].(string)] = firstOriginal
	secondOriginal := firstOriginal
	secondOriginal.RunID = "TEST-second-run"
	secondOriginal.Attempt = 2
	report["gates"].([]any)[0].(map[string]any)["outcome"] = "pass"
	report["overallOutcome"] = "pass"
	secondOriginal.Bytes = jsonBytes(t, report)
	second["reportDigest"] = digestBytes(secondOriginal.Bytes)
	f.originals[second["reportDigest"].(string)] = secondOriginal
	second["artifactDigests"] = map[string]any{}
	// Both reports are actual collected outcomes; omitting optional test output
	// here would itself be a required failure. Remove the TEST artifact obligation
	// independently BEFORE approving this separate TEST retry plan.
	slot["artifactIds"] = []any{}
	first["artifactDigests"] = map[string]any{}
	f.current.PlanDigest = hash(t, f.plan)
	f.evidence["verificationPlanDigest"] = f.current.PlanDigest
	for id, v := range f.originals {
		v.PlanDigest = f.current.PlanDigest
		f.originals[id] = v
	}
	f.evidence["results"] = []any{first, second}
	f.current.CollectedResultsDigest = hash(t, f.evidence["results"])
	if _, e := f.check(t); e == nil {
		t.Fatal("failed original attempt was ignored")
	}
	f.evidence["results"] = []any{second}
	if _, e := f.check(t); e == nil {
		t.Fatal("new signature hid actual failed run history")
	}
}

func TestIdenticalOriginalBytesFromTwoRealRunsKeepDistinctProvenance(t *testing.T) {
	f := setup(t)
	slot := f.plan["slots"].([]any)[0].(map[string]any)
	slot["minIndependentRuns"] = int64(2)
	slot["maxAttempts"] = int64(2)
	f.current.PlanDigest = hash(t, f.plan)
	f.evidence["verificationPlanDigest"] = f.current.PlanDigest
	first := f.evidence["results"].([]any)[0].(map[string]any)
	second := map[string]any{}
	for k, v := range first {
		second[k] = v
	}
	second["runId"] = "TEST-another-real-run"
	// Actual independently stored metadata, same immutable content bytes. A
	// different signer/envelope or a repeated run ID would not add a sample.
	indexed := map[OriginalRef]Original{}
	for _, run := range []string{"TEST-run", "TEST-another-real-run"} {
		for id, v := range f.originals {
			v.RunID = run
			v.PlanDigest = f.current.PlanDigest
			indexed[OriginalRef{id, run, 1}] = v
		}
	}
	f.current.ReadOriginal = func(ref OriginalRef) (Original, error) {
		v, ok := indexed[ref]
		if !ok {
			return Original{}, ErrOriginalMissing
		}
		return v, nil
	}
	f.evidence["results"] = []any{first, second}
	f.current.CollectedResultsDigest = hash(t, f.evidence["results"])
	if _, e := f.check(t); e != nil {
		t.Fatal("legitimate identical output runs were conflated", e)
	}
	second["runId"] = "TEST-run"
	second["attempt"] = int64(2)
	for ref, v := range indexed {
		if ref.RunID == "TEST-run" {
			v.Attempt = 2
			indexed[OriginalRef{ref.Digest, ref.RunID, 2}] = v
		}
	}
	f.current.CollectedResultsDigest = hash(t, f.evidence["results"])
	if _, e := f.check(t); e == nil {
		t.Fatal("one run with two attempts became two independent runs")
	}
}

func TestApprovedSameGateMatrixRequiresEveryExactSourceSlot(t *testing.T) {
	for _, kind := range []string{"valid", "omitted", "duplicate-source", "wrong-config", "wrong-shard", "missing-assertion"} {
		t.Run(kind, func(t *testing.T) {
			f := setup(t)
			baseSlot := f.plan["slots"].([]any)[0].(map[string]any)
			baseRow := f.evidence["results"].([]any)[0].(map[string]any)
			slots, rows := []any{}, []any{}
			indexed := map[OriginalRef]Original{}
			for n, shard := range []string{"linux-part-1", "linux-part-2"} {
				slot, row := map[string]any{}, map[string]any{}
				for k, v := range baseSlot {
					slot[k] = v
				}
				for k, v := range baseRow {
					row[k] = v
				}
				slot["slotId"] = "TEST-" + shard
				slot["configDigest"] = "sha256:" + strings.Repeat([]string{"2", "3"}[n], 64)
				slot["shard"] = shard
				// One approved result may satisfy these two named assertions. It is not
				// counted as two independent runs and cannot fill the other matrix slot.
				slot["assertionIds"] = []any{"TEST-assertion", "TEST-second-assertion"}
				row["slotId"] = slot["slotId"]
				row["runId"] = "TEST-run-" + shard
				for id, original := range f.originals {
					original.RunID = row["runId"].(string)
					original.ConfigDigest = slot["configDigest"].(string)
					original.Shard = shard
					original.AssertionIDs = []string{"TEST-assertion", "TEST-second-assertion"}
					indexed[OriginalRef{id, original.RunID, 1}] = original
				}
				slots = append(slots, slot)
				rows = append(rows, row)
			}
			f.plan["slots"] = slots
			f.current.PlanDigest = hash(t, f.plan)
			f.evidence["verificationPlanDigest"] = f.current.PlanDigest
			for ref, original := range indexed {
				original.PlanDigest = f.current.PlanDigest
				indexed[ref] = original
			}
			second := rows[1].(map[string]any)
			ref := OriginalRef{second["reportDigest"].(string), second["runId"].(string), 1}
			original := indexed[ref]
			switch kind {
			case "omitted":
				rows = rows[:1]
			case "duplicate-source":
				second["runId"] = rows[0].(map[string]any)["runId"]
			case "wrong-config":
				original.ConfigDigest = baseSlot["configDigest"].(string)
			case "wrong-shard":
				original.Shard = "whole"
			case "missing-assertion":
				original.AssertionIDs = []string{"TEST-assertion"}
			}
			indexed[ref] = original
			f.evidence["results"] = rows
			f.current.CollectedResultsDigest = hash(t, rows)
			f.current.ReadOriginal = func(ref OriginalRef) (Original, error) {
				v, ok := indexed[ref]
				if !ok {
					return Original{}, ErrOriginalMissing
				}
				return v, nil
			}
			_, err := f.check(t)
			if kind == "valid" && err != nil {
				t.Fatal("approved exact matrix rejected", err)
			}
			if kind != "valid" && err == nil {
				t.Fatal("matrix gap or substituted original was admitted")
			}
		})
	}
}

func TestReportFlagsCannotDowngradeApprovedRequiredSlot(t *testing.T) {
	for _, kind := range []string{"expected-false", "report-only", "empty-success", "skipped", "error", "not_run", "fail"} {
		t.Run(kind, func(t *testing.T) {
			f := setup(t)
			row := f.evidence["results"].([]any)[0].(map[string]any)
			original := f.originals[row["reportDigest"].(string)]
			report, err := Validate(original.Bytes, "report")
			if err != nil {
				t.Fatal(err)
			}
			gate := report["gates"].([]any)[0].(map[string]any)
			gate["executed"] = false
			gate["outcome"] = "not_run"
			switch kind {
			case "expected-false":
				gate["expected"] = false
			case "report-only":
				gate["enforcementClass"] = "report_only"
			case "empty-success":
				gate["executed"] = true
				gate["outcome"] = "pass"
				gate["artifactCount"] = int64(0)
			default:
				gate["outcome"] = kind
			}
			// Keep the source's overall PASS. The approved required slot still governs
			// action qualification; no raw outcome/exit value is rewritten to pass.
			original.Bytes = jsonBytes(t, report)
			row["reportDigest"] = digestBytes(original.Bytes)
			f.originals[row["reportDigest"].(string)] = original
			f.current.CollectedResultsDigest = hash(t, f.evidence["results"])
			if _, err := f.check(t); err == nil {
				t.Fatal("report flag/empty result weakened required slot")
			}
		})
	}
}
