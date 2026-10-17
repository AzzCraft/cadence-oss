package resolver

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/AzzCraft/cadence-oss/cadence-core/internal/dsse"
	"github.com/AzzCraft/cadence-oss/cadence-core/internal/exactjson"
)

func factsFixture(t *testing.T) (map[string]any, map[string]any) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "cadence-protocol", "fixtures", "das_v1_5", "approved_facts_vector.json"))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := exactjson.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	vector := parsed.(map[string]any)
	input := leafRequest(t)
	return map[string]any{"contractIdentity": "das-approved-facts-preview-input/v1", "factsEnvelope": vector["envelope"],
		"controlContext": vector["controlContext"], "catalog": input["catalog"], "requirementsCatalog": input["requirementsCatalog"]}, vector["payload"].(map[string]any)
}

func signFacts(t *testing.T, input map[string]any, payload map[string]any, seeds ...byte) {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	pae, err := dsse.PAE(ApprovedFactsPayloadType, raw)
	if err != nil {
		t.Fatal(err)
	}
	signatures := []any{}
	for _, seed := range seeds {
		private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
		signatures = append(signatures, map[string]any{"sig": base64.StdEncoding.EncodeToString(ed25519.Sign(private, pae))})
	}
	input["factsEnvelope"] = map[string]any{"payloadType": ApprovedFactsPayloadType, "payload": base64.StdEncoding.EncodeToString(raw), "signatures": signatures}
}

func TestFactsOfflineSchemasCompile(t *testing.T) {
	if err := schemas(); err != nil {
		t.Fatal(err)
	}
}

func TestCheckedFactsBindOriginalSignedBytesIndependentPrincipalsAndCurrentContext(t *testing.T) {
	input, _ := factsFixture(t)
	checked, err := CheckApprovedFacts(input)
	if err != nil {
		t.Fatal(err)
	}
	refs := checked["checkedRefs"].(map[string]any)
	raw, err := dsse.Decode(input["factsEnvelope"].(map[string]any)["payload"].(string), dsse.MaxPayload)
	if err != nil {
		t.Fatal(err)
	}
	envelopeDigest, _ := exactjson.Digest(input["factsEnvelope"])
	contextDigest, _ := exactjson.Digest(input["controlContext"])
	if checked["contractIdentity"] != "das-approved-facts-check/v2" || checked["authority"] != false || checked["qualification"] != false ||
		refs["envelopeDigest"] != envelopeDigest || refs["controlContextDigest"] != contextDigest ||
		refs["payloadBytesDigest"] != fmt.Sprintf("sha256:%x", sha256.Sum256(raw)) {
		t.Fatal("checked references lost the exact verified inputs or claimed public authority")
	}
	if !reflect.DeepEqual(refs["principals"], []string{"fixture-independent-approver"}) {
		t.Fatalf("incorrect independent native signer identities: %v", refs["principals"])
	}
	preview, err := ApprovedFactsPreview(input)
	if err != nil || !reflect.DeepEqual(preview, checked["preview"]) {
		t.Fatal("legacy signed-facts preview changed")
	}
}

func TestCheckedFactsRawPayloadIdentityDoesNotCollapseSignedWhitespace(t *testing.T) {
	input, payload := factsFixture(t)
	one, err := CheckApprovedFacts(input)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, '\n')
	pae, _ := dsse.PAE(ApprovedFactsPayloadType, raw)
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize))
	input["factsEnvelope"] = map[string]any{"payloadType": ApprovedFactsPayloadType, "payload": base64.StdEncoding.EncodeToString(raw),
		"signatures": []any{map[string]any{"sig": base64.StdEncoding.EncodeToString(ed25519.Sign(private, pae))}}}
	two, err := CheckApprovedFacts(input)
	if err != nil || !reflect.DeepEqual(one["preview"], two["preview"]) ||
		one["checkedRefs"].(map[string]any)["payloadBytesDigest"] == two["checkedRefs"].(map[string]any)["payloadBytesDigest"] ||
		one["checkedRefs"].(map[string]any)["payloadDigest"] != two["checkedRefs"].(map[string]any)["payloadDigest"] ||
		one["checkedRefs"].(map[string]any)["approvedFactsDigest"] != two["checkedRefs"].(map[string]any)["approvedFactsDigest"] {
		t.Fatal("equal semantic facts must retain distinct signed byte identities")
	}
}

func TestCheckedFactsCanonicalApprovalIgnoresOnlyFactOrdering(t *testing.T) {
	input, payload := factsFixture(t)
	one, err := CheckApprovedFacts(input)
	if err != nil {
		t.Fatal(err)
	}
	facts := payload["facts"].([]any)
	for left, right := 0, len(facts)-1; left < right; left, right = left+1, right-1 {
		facts[left], facts[right] = facts[right], facts[left]
	}
	signFacts(t, input, payload, 1)
	two, err := CheckApprovedFacts(input)
	if err != nil {
		t.Fatal(err)
	}
	before, after := one["checkedRefs"].(map[string]any), two["checkedRefs"].(map[string]any)
	if before["approvedFactsDigest"] != after["approvedFactsDigest"] || before["payloadDigest"] == after["payloadDigest"] ||
		before["payloadBytesDigest"] == after["payloadBytesDigest"] || !reflect.DeepEqual(one["preview"], two["preview"]) {
		t.Fatal("semantic fact ordering changed applicability or collapsed original signed identities")
	}
	payload["factsGeneration"] = json.Number("2")
	input["controlContext"].(map[string]any)["factsGeneration"] = json.Number("2")
	signFacts(t, input, payload, 1)
	three, err := CheckApprovedFacts(input)
	if err != nil || after["approvedFactsDigest"] == three["checkedRefs"].(map[string]any)["approvedFactsDigest"] {
		t.Fatal("approval normalization lost the actual facts generation", err)
	}
}

func TestPythonOpenSSLFactsAreConsumedBySameGoResolver(t *testing.T) {
	input, payload := factsFixture(t)
	result, err := ApprovedFactsPreview(input)
	if err != nil {
		t.Fatal(err)
	}
	ordinary := map[string]any{"contractIdentity": "das-bundle-preview-input/v3", "scope": payload["scope"],
		"policyDigest": payload["policyRef"].(map[string]any)["policyDigest"], "catalog": input["catalog"],
		"requirementsCatalog": input["requirementsCatalog"], "facts": payload["facts"]}
	expected, err := Preview(ordinary)
	if err != nil || !reflect.DeepEqual(result, expected) {
		t.Fatal("signed facts did not use the same evaluator", err)
	}
	if result["authorityVerified"] != false || result["qualificationEligible"] != false || result["leafMigrationComplete"] != true {
		t.Fatal("supplied trust was mistaken for installed authority")
	}
	falseIDs := map[string]bool{}
	falseIDs["das.security-agent.s20.no-integration-preapproved-branch"] = true
	for _, suffix := range []string{"delegation-protected-parent-child-provenance", "delegation-current-actor-represented-subject-all-ancestors",
		"delegation-resource-purpose-parameters-expiry-quota-attenuation", "delegation-invalid-parent-no-renewal-or-revocation-bypass",
		"delegation-depth-size-cost-bounded", "delegation-shared-ancestor-business-budget-atomic", "client-role-or-audit-actor-chain-not-authority"} {
		falseIDs["das.security-agent.s10."+suffix] = true
	}
	for _, id := range []string{"das.security-agent.ai-task.breaking-compatibility-plan", "das.security-agent.z04.delegation-ceiling", "das.security-agent.z06.verification-external-binding", "das.security-agent.z06.integration-external-binding", "das.security-agent.z09.competition-reverification", "das.security-agent.z09.merge-result-reverification"} {
		falseIDs[id] = true
	}
	for _, suffix := range []string{"ui-spec", "hfvi-section", "hfvi-appendix", "hfvi-contract-surfaces"} {
		falseIDs["das.core.profile."+suffix] = true
	}
	for _, suffix := range []string{"machine-manifest", "masterdoc-reference", "namespaced-id",
		"name", "namespace", "kind", "extension-point", "owner", "scope", "compatibility-note",
		"review-trigger", "doc-type-mapping", "schema-validation"} {
		falseIDs["das.core.manifest.extension-"+suffix] = true
	}
	falseIDs["das.architecture-modularity.sdmm.breaking-migration-window"] = true
	falseIDs["das.architecture-modularity.topology.harness-external-replay"] = true
	// The independently authored data scenario uses a governed snapshot because
	// hashing is infeasible. It cannot simultaneously select feasible-hash advice.
	falseIDs["das.ai-runtime-evaluation.data.gating-hash-preferred"] = true
	for _, suffix := range []string{"browser-smoke-or-api-rationale", "stable-ui-selectors", "ui-screen-id-alignment",
		"ui-failure-artifacts", "ui-failure-correlation", "deterministic-ui-smoke", "ui-workflow-screen-mapping"} {
		falseIDs["das.governance.verification-release.integration."+suffix] = true
	}
	for _, suffix := range []string{"breaking-expand-contract", "breaking-window", "breaking-major-version", "breaking-compatibility-runners",
		"deprecation-note", "deprecation-date", "citation-offset-unit", "citation-offset-contract", "citation-web-utf16",
		"tokens-incubator-namespace", "tokens-incubator-owner", "tokens-incubator-expiry",
		"stable-exhaustion-code", "stream-generic-working"} {
		falseIDs["das.contracts-compatibility.contract."+suffix] = true
	}
	for _, suffix := range []string{"replay-config", "replay-dependency-pins", "replay-harness",
		"replay-golden-fixtures", "replay-ci", "hard-termination-code", "dry-run-read-only-or-fakes",
		"material-change-evaluations", "evaluation-dataset-pin", "evaluation-report", "evaluation-artifacts",
		"large-refactor-safe-migration"} {
		falseIDs["das.ai-runtime-evaluation.algorithm."+suffix] = true
	}
	for _, suffix := range []string{"drift-external-compatibility", "drift-old-new-fixtures",
		"drift-reproducing-gate", "drift-waiver-owner", "drift-waiver-scope", "drift-waiver-expiry",
		"l2-automated-drift-check", "l2-drift-ci", "out-of-band-reconcile-or-noncanonical", "dispute-decision-record"} {
		falseIDs["das.governance.documentation.doc."+suffix] = true
	}
	for _, suffix := range []string{"ui-spec-appendix", "ui-spec-screen-route-ids", "ui-spec-standard-states", "ui-spec-ai-states",
		"ui-spec-traceability", "ui-spec-selectors", "ui-spec-interaction-mode", "ui-spec-ai-contract-references",
		"ui-spec-shared-design-references", "automatable-design-review-gate", "context-pack-l2-current",
		"material-change-doc-or-waiver", "sub-doc-na-reason", "sub-doc-na-truth", "manual-traceability-focus",
		"manual-traceability-owner", "manual-traceability-review"} {
		falseIDs["das.governance.documentation.doc."+suffix] = true
	}
	for _, suffix := range []string{"pre-release-parity", "pre-release-closure", "pre-release-lock-closure-check",
		"closure-policy-pack-version", "closure-template-version", "report-no-results-fails",
		"registry-publication", "registry-schema-validation"} {
		falseIDs["das.governance.verification-release.verify."+suffix] = true
	}
	for _, suffix := range []string{"acl-deterministic", "acl-fixtures", "external-legacy-acl",
		"nondeterministic-scenario-tagged", "nondeterministic-scenario-isolated", "nondeterministic-scenario-explicit-runner",
		"inheritance-stable-is-a", "tier-deterministic-verification", "tier-bdd-offline-default",
		"unjustified-boundary-merge-or-formalize"} {
		falseIDs["das.architecture-modularity.domain."+suffix] = true
	}
	for _, suffix := range []string{"helper-generated", "helper-no-network-persistence", "helper-no-duplicate-cyclic-dependencies",
		"helper-no-runtime-exceptions", "helper-data-constructors", "strict-internet-version-negotiation", "contract-pr-codegen",
		"behavior-change-documentation", "behavior-change-fixtures-tests", "breaking-strategy-cutoff",
		"breaking-strategy-old-new-fixtures", "breaking-strategy-stored-data-migration"} {
		falseIDs["das.contracts-compatibility.multirepo."+suffix] = true
	}
	for _, suffix := range []string{"golden-expectations", "replay-ci-stability", "tier0-offline", "tier1-pinned-replay", "cutover-replay"} {
		falseIDs["das.architecture-modularity.migration."+suffix] = true
	}
	for _, suffix := range []string{"shallow-inheritance", "no-inheritance-reuse-hack"} {
		falseIDs["das.architecture-modularity.ddd."+suffix] = true
	}
	for _, suffix := range []string{"offline-replay-fixtures", "untrusted-model-input", "model-schema-validation", "scenario-budget-enforcement", "scenario-budget-termination", "ui-stable-selectors"} {
		falseIDs["das.architecture-modularity.bdd."+suffix] = true
	}
	// The independently signed scenario is L0, not L1/L2. Preserve these minima.
	for _, suffix := range []string{
		"environment-matrix-environment",
		"environment-matrix-purpose",
		"environment-matrix-data-class",
		"environment-matrix-secrets",
		"environment-matrix-dependencies",
		"environment-matrix-deploy-method",
		"environment-matrix-rollback",
		"environment-matrix-owner",
		"resource-inventory-compute",
		"resource-inventory-data-stores",
		"resource-inventory-messages-streams",
		"resource-inventory-observability",
		"resource-inventory-secrets",
		"resource-inventory-network",
		"dependency-registry-dependency",
		"dependency-registry-type",
		"dependency-registry-purpose",
		"dependency-registry-contract",
		"dependency-registry-auth",
		"dependency-registry-rate-limits",
		"dependency-registry-cost",
		"dependency-registry-data",
		"dependency-registry-service-level",
		"dependency-registry-fallback",
		"dependency-registry-owner",
		"l2-large-program-service-catalog",
		"l2-large-program-api-governance",
		"l2-large-program-identity",
		"l2-large-program-audit",
		"l2-large-program-change-management",
		"l2-large-program-data",
		"l2-large-program-vendor",
		"l2-staging-allowed-differences-rationale",
		"l2-feature-flag-lifecycle",
		"l1-l2-production-cloud-iac",
		"l2-production-sbom",
		"l2-ci-direct-transitive-sca",
		"l2-deployment-signature-check",
		"deployment-provenance-metadata",
		"l2-vendor-change-notification-review",
		"runbook-deploy",
		"runbook-rollback",
		"runbook-incidents",
		"l2-oncall-incident-process",
		"large-program-disaster-recovery",
		"large-program-central-observability",
		"large-program-golden-paths",
	} {
		falseIDs["das.governance.verification-release.deployment."+suffix] = true
	}
	for _, suffix := range []string{"issue-rfc-adr", "pr-approvals", "release-milestone"} {
		falseIDs["das.governance.verification-release.collaboration.l2-boundary-rule-trace-"+suffix] = true
	}
	// The original TEST fixture has no actual documentation dispute.
	for _, suffix := range []string{"dispute-decision-owner-final-call", "dispute-record-change", "dispute-record-rationale", "dispute-record-compatibility-migration", "dispute-record-approver", "disputed-decision-owner-escalation"} {
		falseIDs["das.governance.verification-release.collaboration."+suffix] = true
	}
	for _, suffix := range []string{
		"multi-repo-task-breaking-rollout-compat-plan",
		"recommended-role-gate-frontend-visible-ui-smoke",
		"recommended-repository-doc-ui-spec",
		"ai-task-tier-replay-fixtures",
		"recommended-role-gate-algorithm-tier0-replay",
	} {
		falseIDs["das.architecture-modularity.repo."+suffix] = true
	}
	for _, id := range []string{
		"das.governance.documentation.manifest-rule.l2-master-doc-requires-context-pack",
		"das.governance.documentation.manifest-rule.worker-service-module-docs-require-interaction-profile",
		"das.governance.documentation.manifest-rule.module-doc-requires-module-doc-role",
		"das.governance.documentation.manifest-rule.normative-addendum-requires-subordinate-role",
		"das.interaction.headless.manifest-rule.ui-spec-requires-non-headless-interaction-profile",
		"das.interaction.headless.manifest-rule.headless-surface-note-requires-headless-interaction-profile",
	} {
		falseIDs[id] = true
	}
	if len(result["requirementTrace"].([]any)) != 2723 {
		t.Fatal("signed facts lost their current partial denominator")
	}
	uiCount, hfviCount, templateCount := 0, 0, 0
	for _, raw := range result["requirementTrace"].([]any) {
		row := raw.(map[string]any)
		want := "true"
		id := row["requirementId"].(string)
		if strings.HasPrefix(id, "das.interaction.standard-ui.") {
			uiCount++
			want = "false" // This signed TEST scenario has no actual frontend/UI activities.
		}
		if strings.HasPrefix(id, "das.interaction.hfvi.") {
			hfviCount++
			want = "false" // Neither a declared HFVI profile nor an actual HFVI surface.
		}
		if strings.HasPrefix(id, "das.governance.documentation.template.") {
			templateCount++
			want = "false" // This original headless fixture did not adopt Appendix C.
		}
		if falseIDs[id] {
			want = "false"
		}
		if row["state"] != want {
			t.Fatal("lost independently expected applicability", row)
		}
	}
	if uiCount != 183 || hfviCount != 61 || templateCount != 117 {
		t.Fatal("signed headless scenario lost its independent interaction denominator")
	}
}

func TestFactsSignedBindingAndCurrentStateFailuresHaveNoOutput(t *testing.T) {
	for _, fault := range []string{"issuer", "audience", "scope", "facts-id", "proposer", "facts-generation", "policy-id", "policy-digest", "policy-generation", "epoch", "candidate", "deployment", "facts-revoked", "policy-revoked", "unavailable", "backward-time", "future-observation", "stale", "not-before", "expiry-boundary", "reversed-window", "unsupported-standard", "module-rewrite", "module-source-erasure", "requirement-rewrite", "unbound-digest", "duplicate-fact-source", "invalid-fact-type", "unknown-payload-field", "fractional-generation", "unsafe-generation"} {
		t.Run(fault, func(t *testing.T) {
			input, payload := factsFixture(t)
			current := input["controlContext"].(map[string]any)
			policy := current["policyRef"].(map[string]any)
			target := current["target"].(map[string]any)
			switch fault {
			case "issuer", "audience", "scope":
				current[fault] = "another-context"
			case "facts-id":
				current["factsId"] = "another-id"
			case "proposer":
				current["callerPrincipal"] = "another-caller"
			case "facts-generation":
				generation, err := exactjson.SafeInteger(current["factsGeneration"])
				if err != nil {
					t.Fatal(err)
				}
				current["factsGeneration"] = json.Number(fmt.Sprint(generation + 1))
			case "policy-id":
				policy["policyId"] = "another-policy"
			case "policy-digest":
				policy["policyDigest"] = "sha256:" + strings.Repeat("f", 64)
			case "policy-generation":
				policy["policyGeneration"] = json.Number("3")
			case "epoch":
				policy["authorityEpoch"] = json.Number("4")
			case "candidate":
				target["candidateDigest"] = "sha256:" + strings.Repeat("f", 64)
			case "deployment":
				target["deploymentBaselineDigest"] = "sha256:" + strings.Repeat("f", 64)
			case "facts-revoked":
				current["factsRevoked"] = true
			case "policy-revoked":
				current["policyRevoked"] = true
			case "unavailable":
				delete(current, "observedAt")
			case "backward-time":
				current["latest"] = "2026-10-06T00:04:59Z"
			case "future-observation":
				current["observedAt"] = "2026-10-06T00:05:01Z"
			case "stale":
				current["observedAt"] = "2026-10-06T00:04:00Z"
			case "not-before":
				payload["notBefore"] = "2026-10-06T00:05:01Z"
			case "expiry-boundary":
				payload["expiresAt"] = current["latest"]
			case "reversed-window":
				payload["expiresAt"] = payload["notBefore"]
			case "unsupported-standard":
				payload["standardVersion"] = "1.4.0"
			case "module-rewrite":
				catalog := input["catalog"].(map[string]any)
				catalog["modules"].([]any)[1].(map[string]any)["activation"] = map[string]any{"op": "const", "value": false}
				payload["catalogDigest"], _ = exactjson.Digest(catalog)
			case "module-source-erasure":
				catalog := input["catalog"].(map[string]any)
				core := catalog["modules"].([]any)[0].(map[string]any)
				sources := []any{}
				for _, source := range core["normativeSources"].([]any) {
					if source != "CHANGELOG.md" {
						sources = append(sources, source)
					}
				}
				core["normativeSources"] = sources
				payload["catalogDigest"], _ = exactjson.Digest(catalog)
			case "requirement-rewrite":
				catalog := input["requirementsCatalog"].(map[string]any)
				catalog["editionRequirements"] = catalog["editionRequirements"].([]any)[1:]
				payload["requirementsCatalogDigest"], _ = exactjson.DigestCatalog(catalog)
			case "unbound-digest":
				payload["catalogDigest"] = "sha256:" + strings.Repeat("f", 64)
			case "duplicate-fact-source":
				payload["facts"] = append(payload["facts"].([]any), payload["facts"].([]any)[0])
			case "invalid-fact-type":
				payload["facts"].([]any)[0].(map[string]any)["value"] = "false"
			case "unknown-payload-field":
				payload["authorityVerified"] = true
			case "fractional-generation":
				payload["factsGeneration"] = json.Number("4.000000000000000001")
			case "unsafe-generation":
				payload["factsGeneration"] = json.Number("9007199254740992")
			}
			signFacts(t, input, payload, 1)
			if output, err := ApprovedFactsPreview(input); err == nil || output != nil {
				t.Fatal("invalid context yielded a result", output, err)
			}
		})
	}
}

func TestFactsNativeSignaturePurposeAndIndependentPrincipals(t *testing.T) {
	for _, fault := range []string{"wrong-type", "wrong-role", "wrong-key", "tampered-native-bytes", "duplicate-signature", "same-principal", "duplicate-trusted-key", "self-approval", "independent-plus-caller", "independent-threshold"} {
		t.Run(fault, func(t *testing.T) {
			input, payload := factsFixture(t)
			current := input["controlContext"].(map[string]any)
			keys := current["keys"].([]any)
			key := keys[0].(map[string]any)
			second := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, 32)).Public().(ed25519.PublicKey)
			newKey := map[string]any{"publicKeyBase64": base64.StdEncoding.EncodeToString(second), "principal": "second-independent", "issuer": current["issuer"], "roles": []any{"facts_approver"}}
			current["keys"] = append(keys, newKey)
			if fault == "same-principal" || fault == "duplicate-signature" || fault == "independent-threshold" {
				current["threshold"] = json.Number("2")
			}
			signFacts(t, input, payload, 1, 2)
			envelope := input["factsEnvelope"].(map[string]any)
			switch fault {
			case "wrong-type":
				envelope["payloadType"] = "application/vnd.das.action-authorization.v1+json"
			case "wrong-role":
				key["roles"] = []any{"action_authorizer"}
				newKey["roles"] = []any{"action_authorizer"}
			case "wrong-key":
				signFacts(t, input, payload, 3)
			case "tampered-native-bytes":
				raw, _ := base64.StdEncoding.DecodeString(envelope["payload"].(string))
				envelope["payload"] = base64.StdEncoding.EncodeToString(append(raw, '\n'))
			case "duplicate-signature":
				envelope["signatures"] = []any{envelope["signatures"].([]any)[0], envelope["signatures"].([]any)[0]}
			case "same-principal":
				newKey["principal"] = key["principal"]
			case "duplicate-trusted-key":
				newKey["publicKeyBase64"] = key["publicKeyBase64"]
			case "self-approval":
				key["principal"] = current["callerPrincipal"]
				newKey["principal"] = current["callerPrincipal"]
			case "independent-plus-caller":
				newKey["principal"] = current["callerPrincipal"]
			}
			output, err := ApprovedFactsPreview(input)
			if fault == "independent-plus-caller" || fault == "independent-threshold" {
				if err != nil || output["authorityVerified"] != false {
					t.Fatal("independent approval with extra proposer signature failed", err)
				}
				return
			}
			if err == nil || output != nil {
				t.Fatal("signature or independence failure was accepted", output, err)
			}
		})
	}
}

func TestFactsUnknownConflictAndOriginalPayloadOnly(t *testing.T) {
	input, payload := factsFixture(t)
	payload["facts"] = []any{map[string]any{"key": "activity.protected_action", "value": true, "sourceRef": "fixture:one"}, map[string]any{"key": "activity.protected_action", "value": false, "sourceRef": "fixture:two"}}
	signFacts(t, input, payload, 1)
	first, err := ApprovedFactsPreview(input)
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range first["requirementTrace"].([]any) {
		row := raw.(map[string]any)
		if row["requirementId"] == "das.security-agent.z04.subject-recheck" && row["state"] != "conflict" {
			t.Fatal("conflict folded")
		}
		if row["requirementId"] == "das.security-agent.z06.verification-external-binding" && row["state"] != "unknown" {
			t.Fatal("missing fact exempted")
		}
	}
	values := payload["facts"].([]any)
	values[0], values[1] = values[1], values[0]
	signFacts(t, input, payload, 1)
	second, err := ApprovedFactsPreview(input)
	if err != nil || !reflect.DeepEqual(first, second) {
		t.Fatal("fact order changed proposal", err)
	}
	input["facts"] = []any{}
	if output, err := ApprovedFactsPreview(input); err == nil || output != nil {
		t.Fatal("unsigned alternate facts accepted")
	}
}
