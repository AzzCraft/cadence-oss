package resolver

import (
	"reflect"
	"strings"
	"testing"

	"github.com/AzzCraft/cadence-oss/cadence-core/internal/exactjson"
)

func leafRequest(t *testing.T) map[string]any {
	t.Helper()
	input := request(t)
	leaves, err := exactjson.ParseCatalog(requirementCatalog)
	if err != nil {
		t.Fatal(err)
	}
	input["contractIdentity"] = "das-bundle-preview-input/v3"
	input["requirementsCatalog"] = leaves
	return input
}

func TestEditionPathsApplyBeforeVerificationAndPreserveOptionalTransports(t *testing.T) {
	input := leafRequest(t)
	values := map[string]any{
		"activity.verification": false, "activity.candidate_build": true,
		"activity.dynamic_candidate_preparation": false,
		"activity.evidence_consumption":          false, "activity.evidence_issuance": true,
		"activity.signed_object_exchange": false,
		"activity.text_delta_transport":   true, "transport.sse": false,
		"format.jwt_adapter": false,
		"surface.ui":         false, "surface.hfvi": true,
	}
	setFacts(input, values)
	states := leafStates(t, input)
	for _, id := range []string{
		"das.security-agent.s11.candidate-domain-distinct-protected-test-observer",
		"das.security-agent.s11.build-output-separate-input-builder-config-output-byte-proof",
		"das.security-agent.s12.independent-signature-complete-plan-original-run-and-aggregation",
		"das.contracts-compatibility.s8.task-candidate-verification-integration-completion-dag",
		"das.interaction.standard-ui.s16.complete-authorized-reading",
		"das.core.s2.independent-fact-approval-before-evaluation",
	} {
		if states[id] != "true" {
			t.Fatal("a real pre-verification, issuer or HFVI path lost its duty: " + id)
		}
	}
	for _, id := range []string{
		"das.security-agent.s11.dynamic-metadata-no-reimport-candidate-in-control",
		"das.contracts-compatibility.s5.sse-native-framing-no-eof-event",
		"das.contracts-compatibility.s8.jwt-protected-algorithm-issuer-key-and-claims",
	} {
		if states[id] != "false" {
			t.Fatal("an unused mechanism acquired an obligation: " + id)
		}
	}
	values["activity.candidate_build"], values["activity.dynamic_candidate_preparation"] = false, true
	values["surface.hfvi"] = false
	delete(values, "transport.sse")
	delete(values, "format.jwt_adapter")
	setFacts(input, values)
	states = leafStates(t, input)
	if states["das.security-agent.s11.candidate-domain-distinct-protected-test-observer"] != "true" ||
		states["das.security-agent.s11.dynamic-metadata-no-reimport-candidate-in-control"] != "true" ||
		states["das.security-agent.s11.build-output-separate-input-builder-config-output-byte-proof"] != "false" ||
		states["das.interaction.standard-ui.s16.complete-authorized-reading"] != "false" {
		t.Fatal("preparation-only or headless paths changed applicability")
	}
	for _, id := range []string{
		"das.contracts-compatibility.s5.sse-native-framing-no-eof-event",
		"das.contracts-compatibility.s8.jwt-protected-algorithm-issuer-key-and-claims",
	} {
		if states[id] != "unknown" {
			t.Fatal("an unobserved transport became an exemption: " + id)
		}
	}
	values["transport.sse"], values["format.jwt_adapter"] = true, true
	setFacts(input, values)
	input["facts"] = append(input["facts"].([]any), map[string]any{
		"key": "transport.sse", "value": false,
		"sourceRef": "independent:contradictory-native-stream"})
	states = leafStates(t, input)
	if states["das.contracts-compatibility.s5.sse-native-framing-no-eof-event"] != "conflict" ||
		states["das.contracts-compatibility.s8.jwt-protected-algorithm-issuer-key-and-claims"] != "true" {
		t.Fatal("optional native protocol lost conflict or positive applicability")
	}
}

func TestAuditConfiguredPathIncludesFailureHandlingAndIndependentStopBeforeAnyClaimedFault(t *testing.T) {
	input := leafRequest(t)
	values := map[string]any{
		"activity.authoritative_write": true, "failure.audit_unavailable": false,
		"permission.business_write_allowed": false, "storage.sqlite_reference": false,
		"activity.protected_local_stop": true, "permission.audit_record_available": false,
		"activity.artifact_registration": true, "activity.artifact_recovery": false,
	}
	setFacts(input, values)
	states := leafStates(t, input)
	for _, id := range []string{
		"das.security-agent.s13.audit-durable-intent-before-effect-and-result",
		"das.security-agent.s13.audit-service-failure-stops-normal-write",
		"das.security-agent.s13.audit-actual-loaded-engine-driver-config-source-fix-proof",
		"das.security-agent.s13.audit-independent-preapproved-local-stop",
		"das.security-agent.s13.audit-stop-bounded-scope-not-business-recovery",
		"das.security-agent.s13.audit-unknown-storage-not-file-visibility-as-success-or-absence",
	} {
		if states[id] != "true" {
			t.Fatal("a denied capability or unclaimed fault hid a configured path obligation: " + id)
		}
	}
	if states["das.security-agent.s13.audit-sqlite-actual-nonnull-foreign-key-conflicts"] != "false" {
		t.Fatal("a non-SQLite implementation acquired a SQLite-specific obligation")
	}
	values["activity.artifact_registration"], values["activity.artifact_recovery"] = false, true
	setFacts(input, values)
	if leafStates(t, input)["das.security-agent.s13.audit-unknown-storage-not-file-visibility-as-success-or-absence"] != "true" {
		t.Fatal("standalone artifact recovery lost its unknown-commit boundary")
	}
	delete(values, "storage.sqlite_reference")
	setFacts(input, values)
	if leafStates(t, input)["das.security-agent.s13.audit-sqlite-actual-nonnull-foreign-key-conflicts"] != "unknown" {
		t.Fatal("an unobserved storage engine became a SQLite exemption")
	}
	values["storage.sqlite_reference"] = true
	setFacts(input, values)
	input["facts"] = append(input["facts"].([]any), map[string]any{
		"key": "storage.sqlite_reference", "value": false,
		"sourceRef": "independent:contradictory-loaded-storage"})
	if leafStates(t, input)["das.security-agent.s13.audit-sqlite-actual-nonnull-foreign-key-conflicts"] != "conflict" {
		t.Fatal("a contradictory loaded storage engine lost its conflict")
	}
}

func TestProtectedCompletionUsesActualEventsAndPreservesNoIntegrationAndRevalidation(t *testing.T) {
	input := leafRequest(t)
	values := map[string]any{
		"activity.protected_task_governance": true, "activity.completion": true,
		"task.integration_applicable": false, "task.integration_not_applicable": true,
		"activity.protected_completion_chain": true, "permission.completion_allowed": false,
		"activity.task_evidence_revalidation": true, "result.revalidation_failed_or_insufficient": false,
		"activity.protected_action": true, "permission.current_action_allowed": false,
		"activity.change_closure_rescind": false,
	}
	setFacts(input, values)
	states := leafStates(t, input)
	for _, id := range []string{
		"das.governance.documentation.s14.completion-unique-task-cycle",
		"das.governance.documentation.s14.completion-no-identity-change-bypass",
		"das.governance.documentation.s14.revalidation-no-worker-business-authority",
		"das.governance.documentation.s14.revalidation-no-mutation-side-effects-or-integration",
		"das.security-agent.s20.no-integration-preapproved-branch",
		"das.security-agent.s20.resource-current-decision-context-evidence-recheck",
	} {
		if states[id] != "true" {
			t.Fatal("denial or a legitimate path hid a required completion boundary: " + id)
		}
	}
	for _, id := range []string{
		"das.governance.documentation.s14.completion-applicable-integration-evidence",
		"das.governance.documentation.s14.revalidation-failure-history-retained-current-denied",
		"das.governance.documentation.s14.rescind-narrow-proof",
	} {
		if states[id] != "false" {
			t.Fatal("an absent event or successful revalidation acquired an inapplicable duty: " + id)
		}
	}
	delete(values, "task.integration_applicable")
	setFacts(input, values)
	if leafStates(t, input)["das.governance.documentation.s14.completion-applicable-integration-evidence"] != "unknown" {
		t.Fatal("unobserved integration applicability became an exemption")
	}
	values["task.integration_applicable"], values["task.integration_not_applicable"] = true, false
	values["result.revalidation_failed_or_insufficient"] = true
	setFacts(input, values)
	states = leafStates(t, input)
	if states["das.governance.documentation.s14.completion-applicable-integration-evidence"] != "true" ||
		states["das.governance.documentation.s14.revalidation-failure-history-retained-current-denied"] != "true" ||
		states["das.security-agent.s20.no-integration-preapproved-branch"] != "false" {
		t.Fatal("real integration/failure events ignored current obligations")
	}
	input["facts"] = append(input["facts"].([]any), map[string]any{
		"key": "task.integration_applicable", "value": false,
		"sourceRef": "independent:contradictory-task-integration"})
	if leafStates(t, input)["das.governance.documentation.s14.completion-applicable-integration-evidence"] != "conflict" {
		t.Fatal("conflicting integration applicability became an exemption")
	}
}

func TestToolingUsesActualArtifactsAndDoesNotHideMandatoryRulesBehindPermission(t *testing.T) {
	input := leafRequest(t)
	values := map[string]any{
		"activity.ci_verification": true, "permission.verify_allowed": false,
		"activity.repository_verification":            true,
		"tooling.generator_or_policy_affects_outputs": false,
		"activity.tooling_pre_release_or_adoption":    true, "tooling.verify_report_emitted": false,
		"activity.release_or_adoption_closure": true, "permission.refs_approved": false,
		"activity.governed_verify_report": true, "gate.failure_on_no_results": true,
		"gate.blocking_or_source_of_truth": true, "permission.results_available": false,
	}
	setFacts(input, values)
	states := leafStates(t, input)
	for _, id := range []string{
		"das.governance.verification-release.verify.reproducible-tooling-lock",
		"das.governance.verification-release.verify.closure-structured-pins",
		"das.governance.verification-release.verify.report-no-results-fails",
		"das.governance.verification-release.tooling.report-expected",
	} {
		if states[id] != "true" {
			t.Fatal("a permission denial hid an independently applicable tooling rule: " + id)
		}
	}
	for _, id := range []string{
		"das.governance.verification-release.tooling.lock-generator-policy-versions",
		"das.governance.verification-release.tooling.check-verify-report",
	} {
		if states[id] != "false" {
			t.Fatal("an unused mechanism acquired a tooling rule: " + id)
		}
	}
	delete(values, "tooling.verify_report_emitted")
	setFacts(input, values)
	if leafStates(t, input)["das.governance.verification-release.tooling.check-verify-report"] != "unknown" {
		t.Fatal("an unobserved report became an exemption")
	}
	values["tooling.verify_report_emitted"] = true
	setFacts(input, values)
	if leafStates(t, input)["das.governance.verification-release.tooling.check-verify-report"] != "true" {
		t.Fatal("an actually emitted report lost its schema check")
	}
	input["facts"] = append(input["facts"].([]any), map[string]any{
		"key": "tooling.verify_report_emitted", "value": false,
		"sourceRef": "independent:contradictory-tooling-artifact"})
	if leafStates(t, input)["das.governance.verification-release.tooling.check-verify-report"] != "conflict" {
		t.Fatal("a contradictory report observation became an exemption")
	}
}

func TestOriginalPlaybookEventsRetainAlternativesAndDenialIndependentDuties(t *testing.T) {
	input := leafRequest(t)
	values := map[string]any{
		"surface.ui": true, "surface.hfvi": false,
		"activity.ui_judgement_review": true, "permission.ui_review_approved": false,
		"ui.p1_finding": true, "ui.p1_deferred": false,
		"activity.bdd_scenario": true, "scenario.tier_2": true, "scenario.live_services_used": false,
		"activity.critical_workflow": true, "scenario.automation_short_term_infeasible": true,
		"activity.migration_production_cutover": true, "pipeline.tier_0_or_1": false,
		"change.breaking_persisted_or_cross_repo_contract": false,
		"change.coupled_multi_module_refactor":             false,
		"change.major_algorithm_quality_or_cost":           false,
		"change.production_adapter_or_prompt_migration":    true,
	}
	setFacts(input, values)
	states := leafStates(t, input)
	for _, id := range []string{"das.interaction.standard-ui.review.judgement-human",
		"das.architecture-modularity.bdd.tier2-isolated", "das.architecture-modularity.bdd.tier2-cost-controls",
		"das.architecture-modularity.bdd.short-term-gap-owner", "das.architecture-modularity.migration.required-playbook"} {
		if states[id] != "true" {
			t.Fatal("denial or a lawful choice hid a playbook duty: " + id)
		}
	}
	for _, id := range []string{"das.interaction.standard-ui.review.p1-deferred-owner",
		"das.architecture-modularity.migration.cutover-replay"} {
		if states[id] != "false" {
			t.Fatal("an absent event acquired a duty: " + id)
		}
	}
	values["surface.ui"], values["surface.hfvi"] = false, true
	values["ui.p1_deferred"] = true
	setFacts(input, values)
	if leafStates(t, input)["das.interaction.standard-ui.review.p1-deferred-owner"] != "true" {
		t.Fatal("HFVI omitted its applicable Standard UI review")
	}
	values["surface.hfvi"] = false
	setFacts(input, values)
	if leafStates(t, input)["das.interaction.standard-ui.review.judgement-human"] != "false" {
		t.Fatal("headless was forced into human UI review")
	}
	delete(values, "scenario.tier_2")
	setFacts(input, values)
	if leafStates(t, input)["das.architecture-modularity.bdd.tier2-isolated"] != "unknown" {
		t.Fatal("missing scenario tier became an exemption")
	}
	input["facts"] = append(input["facts"].([]any), map[string]any{
		"key": "change.production_adapter_or_prompt_migration", "value": false,
		"sourceRef": "independent:contradictory-migration-event"})
	if leafStates(t, input)["das.architecture-modularity.migration.required-playbook"] != "conflict" {
		t.Fatal("a contradictory required migration became an exemption")
	}
}

func leafStates(t *testing.T, input map[string]any) map[string]string {
	t.Helper()
	result, err := Preview(input)
	if err != nil {
		t.Fatal(err)
	}
	if result["contractIdentity"] != "das-bundle-preview/v3" || result["leafMigrationComplete"] != true || result["authorityVerified"] != false || result["qualificationEligible"] != false {
		t.Fatal("complete mapping lost its versioned output or claimed authority")
	}
	digest, err := exactjson.DigestCatalog(input["requirementsCatalog"])
	if err != nil || result["requirementsCatalogDigest"] != digest {
		t.Fatal("requirement catalog lost its input binding")
	}
	states := map[string]string{}
	previous := ""
	for _, raw := range result["requirementTrace"].([]any) {
		row := raw.(map[string]any)
		id := row["requirementId"].(string)
		owner := "das.security-agent"
		if strings.HasPrefix(id, "das.core.") {
			owner = "das.core"
		}
		if strings.HasPrefix(id, "das.interaction.headless.") {
			owner = "das.interaction.headless"
		}
		if strings.HasPrefix(id, "das.architecture-modularity.") {
			owner = "das.architecture-modularity"
		}
		if strings.HasPrefix(id, "das.contracts-compatibility.") {
			owner = "das.contracts-compatibility"
		}
		if strings.HasPrefix(id, "das.ai-runtime-evaluation.") {
			owner = "das.ai-runtime-evaluation"
		}
		if strings.HasPrefix(id, "das.governance.documentation.") {
			owner = "das.governance.documentation"
		}
		if strings.HasPrefix(id, "das.interaction.standard-ui.") {
			owner = "das.interaction.standard-ui"
		}
		if strings.HasPrefix(id, "das.interaction.hfvi.") {
			owner = "das.interaction.hfvi"
		}
		if strings.HasPrefix(id, "das.governance.verification-release.") {
			owner = "das.governance.verification-release"
		}
		if id <= previous || row["ownerModule"] != owner {
			t.Fatal("missing stable ownership or sorted unique leaf IDs")
		}
		states[id] = row["state"].(string)
		previous = id
	}
	if len(states) != 2723 {
		t.Fatal("lost partial catalog denominator")
	}
	return states
}

func TestCompleteMappingRejectsOldOutputAndUnsupportedCatalogCombinations(t *testing.T) {
	input := leafRequest(t)
	for _, identity := range []string{"das-bundle-preview-input/v2", "das-bundle-preview-input/v4"} {
		input["contractIdentity"] = identity
		if _, err := Preview(input); err == nil {
			t.Fatalf("complete mapping accepted unsupported output %s", identity)
		}
	}
	input["contractIdentity"] = "das-bundle-preview-input/v3"
	requirements := input["requirementsCatalog"].(map[string]any)
	requirements["migrationStage"] = "partial-leaf-mapping"
	if _, err := Preview(input); err == nil {
		t.Fatal("partial mapping acquired a complete output identity")
	}
}

func TestDataOnlyRepositoryIncludesItsNormativeOwnerWithoutInventingAI(t *testing.T) {
	input := leafRequest(t)
	setFacts(input, map[string]any{
		"surface.headless": true, "surface.ui": false, "surface.hfvi": false,
		"capability.ai": false, "capability.algorithm": false,
		"activity.dataset_in_use": true, "activity.eval_suite": false,
	})
	if leafStates(t, input)["das.ai-runtime-evaluation.data.dataset-manifest-required"] != "true" {
		t.Fatal("actual data use lost its manifest duty")
	}
	result, err := Preview(input)
	if err != nil || !contains(result["resolvedModules"], "das.ai-runtime-evaluation") {
		t.Fatal("applicable data duty lost its normative module owner", err)
	}
}

func TestOperationalScopesRetainLegalAlternativesAndDoNotInventProduction(t *testing.T) {
	input := leafRequest(t)
	values := map[string]any{
		"activity.integration_harness": true, "surface.ui": true,
		"harness.smoke_not_every_pr": false, "harness.local_ci_divergence": false,
		"activity.harness_ui_smoke": false, "harness.api_smoke_rationale_documented": true,
		"activity.production_system": false, "activity.stable_contract_publish_or_advertise": true,
		"permission.stable_publish_approved": false, "activity.principles_must_exception": false,
		"activity.principles_should_deviation": true, "activity.llm_tool_retrieval_or_agent": true,
		"activity.ai_tool_use": true, "permission.tools_allowed": false,
	}
	setFacts(input, values)
	states := leafStates(t, input)
	for _, id := range []string{"das.governance.verification-release.integration.browser-smoke-or-api-rationale",
		"das.governance.verification-release.platform.stable-contract-actual-producer",
		"das.core.principles.should-deviation-justification-controls",
		"das.security-agent.operational.tool-allowlists-io-schemas"} {
		if states[id] != "true" {
			t.Fatal("a valid alternative or denied permission hid an independent duty: " + id)
		}
	}
	for _, id := range []string{"das.governance.verification-release.integration.merge-smoke-if-not-every-pr",
		"das.governance.verification-release.integration.parity-divergence-tested",
		"das.governance.verification-release.integration.stable-ui-selectors",
		"das.governance.verification-release.platform.production-oncall-escalation",
		"das.core.principles.must-exception-owner-approval"} {
		if states[id] != "false" {
			t.Fatal("invented runtime, production or exception event: " + id)
		}
	}
	delete(values, "activity.production_system")
	setFacts(input, values)
	if leafStates(t, input)["das.governance.verification-release.platform.production-oncall-escalation"] != "unknown" {
		t.Fatal("missing production observation became an exemption")
	}
	values["harness.smoke_not_every_pr"] = true
	setFacts(input, values)
	input["facts"] = append(input["facts"].([]any), map[string]any{
		"key": "harness.smoke_not_every_pr", "value": false, "sourceRef": "independent:contradictory-ci-cadence"})
	if leafStates(t, input)["das.governance.verification-release.integration.merge-smoke-if-not-every-pr"] != "conflict" {
		t.Fatal("conflicting CI cadence became an exemption")
	}
}

func TestOriginalDataChoicesDoNotHidePrivacyOrInventOptionalPointers(t *testing.T) {
	input := leafRequest(t)
	values := map[string]any{
		"activity.dataset_manifest": true, "dataset.storage_uri_present": false,
		"activity.gating_dataset": true, "dataset.content_hash_infeasible": true,
		"dataset.content_hash_feasible": false, "activity.sensitive_debug_capture": true,
		"activity.eval_run": true, "eval.random_seeds_used": false,
		"eval.scoring_artifact_used": false, "activity.dataset_labeling": false,
		"permission.debug_capture_allowed": false, "verification.passed": false,
	}
	setFacts(input, values)
	states := leafStates(t, input)
	prefix := "das.ai-runtime-evaluation.data."
	for _, suffix := range []string{"gating-snapshot-when-hash-infeasible", "sensitive-debug-access-approval",
		"sensitive-debug-retention", "sensitive-debug-redaction-or-encryption", "sensitive-debug-deletion-path",
		"eval-run-dataset-immutable-identity", "eval-run-tier"} {
		if states[prefix+suffix] != "true" {
			t.Fatal("a failed permission or verification hid a data duty: " + suffix)
		}
	}
	for _, suffix := range []string{"optional-uri-immutable-same-bytes", "gating-hash-preferred", "eval-run-seeds-when-used",
		"eval-run-scoring-version", "label-guidelines-examples-edge-cases"} {
		if states[prefix+suffix] != "false" {
			t.Fatal("an absent optional data capability acquired a duty: " + suffix)
		}
	}
	delete(values, "dataset.storage_uri_present")
	setFacts(input, values)
	if leafStates(t, input)[prefix+"optional-uri-immutable-same-bytes"] != "unknown" {
		t.Fatal("missing optional pointer observation became an exemption")
	}
	values["dataset.content_hash_infeasible"] = true
	setFacts(input, values)
	input["facts"] = append(input["facts"].([]any), map[string]any{
		"key": "dataset.content_hash_infeasible", "value": false, "sourceRef": "independent:contradictory-hash-feasibility"})
	if leafStates(t, input)[prefix+"gating-snapshot-when-hash-infeasible"] != "conflict" {
		t.Fatal("conflicting hash feasibility became an exemption")
	}
}

func TestOriginalBackendActivitiesDoNotBecomePermissionOrSuccessExemptions(t *testing.T) {
	input := leafRequest(t)
	values := map[string]any{
		"activity.backend_system_of_record_operation": true,
		"activity.retryable_backend_write":            true, "operation.no_safe_implicit_idempotency": false,
		"activity.backend_long_running_job": true, "job.hard_budget_exhausted": false,
		"job.soft_budget_used": true, "activity.backend_algorithm_job": true,
		"job.derived_result_field_present": false,
		"permission.operation_allowed":     false, "verification.passed": false,
	}
	setFacts(input, values)
	states := leafStates(t, input)
	prefix := "das.architecture-modularity.backend."
	for _, suffix := range []string{"sor-authorization", "retryable-write-idempotency", "job-type-budgets",
		"soft-budget-documented-lifecycle", "full-pipeline-result-every-attempt", "retry-cancel-terminal-state"} {
		if states[prefix+suffix] != "true" {
			t.Fatal("permission or failed verification hid an actual backend duty: " + suffix)
		}
	}
	for _, suffix := range []string{"explicit-key-when-no-safe-implicit-idempotency", "hard-budget-no-effects", "identical-derived-job-result"} {
		if states[prefix+suffix] != "false" {
			t.Fatal("an inactive original condition acquired a duty: " + suffix)
		}
	}
	delete(values, "operation.no_safe_implicit_idempotency")
	delete(values, "job.hard_budget_exhausted")
	delete(values, "job.derived_result_field_present")
	setFacts(input, values)
	states = leafStates(t, input)
	for _, suffix := range []string{"explicit-key-when-no-safe-implicit-idempotency", "hard-budget-no-effects", "identical-derived-job-result"} {
		if states[prefix+suffix] != "unknown" {
			t.Fatal("missing backend condition became an exemption: " + suffix)
		}
	}
	values["job.hard_budget_exhausted"] = true
	setFacts(input, values)
	input["facts"] = append(input["facts"].([]any), map[string]any{
		"key": "job.hard_budget_exhausted", "value": false, "sourceRef": "independent:contradictory-budget"})
	if leafStates(t, input)[prefix+"hard-budget-no-effects"] != "conflict" {
		t.Fatal("conflicting exhausted-budget evidence became an exemption")
	}
}

func TestOriginalMinimumGatesKeepRepositoryAndJobScopes(t *testing.T) {
	input := leafRequest(t)
	values := map[string]any{
		"activity.backend_repository": true, "activity.backend_job_flows": false,
		"activity.contract_repository": true, "activity.integration_harness": true,
		"activity.contract_change":  true,
		"activity.governed_doc_set": true, "permission.job_tests_waived": true,
		"verification.passed": false,
	}
	setFacts(input, values)
	states := leafStates(t, input)
	prefix := "das.governance.verification-release.minimum."
	for _, suffix := range []string{"contracts-schema", "contracts-fixtures", "contracts-changed-compatibility",
		"backend-unit", "backend-integration", "backend-contract", "integration-smoke", "integration-compatibility",
		"integration-system-verify", "docs-status", "docs-governing-standard", "docs-required-sections", "docs-placeholders"} {
		if states[prefix+suffix] != "true" {
			t.Fatal("a permission or failed gate hid an original repository minimum: " + suffix)
		}
	}
	for _, suffix := range []string{"backend-job-idempotency", "backend-job-retry"} {
		if states[prefix+suffix] != "false" {
			t.Fatal("an absent job flow acquired a job-specific duty: " + suffix)
		}
	}
	delete(values, "activity.backend_job_flows")
	setFacts(input, values)
	if leafStates(t, input)[prefix+"backend-job-idempotency"] != "unknown" {
		t.Fatal("missing job-flow observation became an exemption")
	}
	values["activity.backend_job_flows"] = true
	setFacts(input, values)
	input["facts"] = append(input["facts"].([]any), map[string]any{
		"key": "activity.backend_job_flows", "value": false, "sourceRef": "independent:contradictory-job"})
	if leafStates(t, input)[prefix+"backend-job-retry"] != "conflict" {
		t.Fatal("conflicting job-flow observation became an exemption")
	}
	values["activity.backend_repository"] = false
	values["activity.governed_doc_set"] = false
	values["activity.contract_change"] = false
	setFacts(input, values)
	states = leafStates(t, input)
	if states[prefix+"backend-job-retry"] != "false" || states[prefix+"docs-status"] != "false" ||
		states[prefix+"contracts-changed-compatibility"] != "false" {
		t.Fatal("an absent repository/doc set acquired unrelated minima")
	}
}

func TestActualInteractionScopesDoNotInventScreensOrWaiveIdempotency(t *testing.T) {
	input := leafRequest(t)
	values := map[string]any{
		"activity.ui_stream_screen": false, "activity.low_risk_reversible_ui_action": true,
		"ui.optimistic_update_used": false, "profile.hfvi": true, "profile.l0": true,
		"activity.prototype_motion_values": false, "activity.hfvi_task": true,
	}
	setFacts(input, values)
	states := leafStates(t, input)
	for _, id := range []string{"das.interaction.standard-ui.ui.stream-contract", "das.interaction.standard-ui.ui.stream-cancel",
		"das.interaction.standard-ui.ui.optimistic-rollback", "das.interaction.hfvi.hfvi.prototype-motion-owner"} {
		if states[id] != "false" {
			t.Fatal("invented screen, optional optimistic behavior or prototype: " + id)
		}
	}
	for _, id := range []string{"das.interaction.standard-ui.ui.reversible-backend-idempotency",
		"das.interaction.hfvi.hfvi.no-hardcoded-motion", "das.interaction.hfvi.hfvi.schema-before-code"} {
		if states[id] != "true" {
			t.Fatal("an optional prototype or optimistic UI hid an independent duty: " + id)
		}
	}
	delete(values, "ui.optimistic_update_used")
	delete(values, "activity.prototype_motion_values")
	setFacts(input, values)
	states = leafStates(t, input)
	if states["das.interaction.standard-ui.ui.optimistic-rollback"] != "unknown" ||
		states["das.interaction.hfvi.hfvi.prototype-motion-owner"] != "unknown" {
		t.Fatal("missing activity observations became exemptions")
	}
	values["ui.optimistic_update_used"] = true
	values["activity.prototype_motion_values"] = true
	setFacts(input, values)
	input["facts"] = append(input["facts"].([]any), map[string]any{
		"key": "ui.optimistic_update_used", "value": false, "sourceRef": "independent:contradictory-ui"})
	if leafStates(t, input)["das.interaction.standard-ui.ui.optimistic-rollback"] != "conflict" {
		t.Fatal("conflicting activity became an exemption")
	}
}

func TestSupplementContractRolesKeepExistingParentAndConditionalDuties(t *testing.T) {
	input := leafRequest(t)
	values := map[string]any{
		"activity.contract_consumer": true, "activity.contract_producer": true,
		"activity.internet_facing_contract": true, "contract.strict_decoding_selected": false,
		"activity.generated_contract_helper": true, "helper.constructors_provided": false,
		"activity.contract_change_pr": true, "change.contract_codegen_applicable": false,
		"permission.helper_exceptions_allowed": true,
	}
	setFacts(input, values)
	states := leafStates(t, input)
	prefix := "das.contracts-compatibility.multirepo."
	for _, suffix := range []string{"producer-implementation", "producer-compliance-tests", "consumer-compatible-changes",
		"consumer-no-undocumented-interpretation", "helper-no-runtime-exceptions", "contract-pr-owner-approval"} {
		if states[prefix+suffix] != "true" {
			t.Fatal("a supplied permission or optional constructor hid a real contract duty: " + suffix)
		}
	}
	for _, suffix := range []string{"strict-internet-version-negotiation", "helper-data-constructors", "contract-pr-codegen"} {
		if states[prefix+suffix] != "false" {
			t.Fatal("an optional actual mechanism acquired an unconditional duty: " + suffix)
		}
	}
	delete(values, "contract.strict_decoding_selected")
	setFacts(input, values)
	if leafStates(t, input)[prefix+"strict-internet-version-negotiation"] != "unknown" {
		t.Fatal("missing strict-decoding observation became an exemption")
	}
	values["contract.strict_decoding_selected"] = true
	setFacts(input, values)
	input["facts"] = append(input["facts"].([]any), map[string]any{
		"key": "contract.strict_decoding_selected", "value": false, "sourceRef": "independent:contradictory-decoding"})
	if leafStates(t, input)[prefix+"strict-internet-version-negotiation"] != "conflict" {
		t.Fatal("conflicting decoding selection became an exemption")
	}
}

func TestDeclaredProfileAndActualModuleUseKeepLawfulOrAlternatives(t *testing.T) {
	input := leafRequest(t)
	values := map[string]any{
		"activity.module_work": true, "module.published_outside_boundary": false,
		"module.shared_across_repos_or_teams": false, "module.codegen_or_verify_consumed": true,
		"module.persisted_contract_policy_or_runtime_critical": false,
		"activity.frontend_repository":                         true, "profile.l1": false, "profile.l2": false,
		"ui.kit_exists": true, "activity.pure_package_library_tooling_doc": true,
	}
	setFacts(input, values)
	states := leafStates(t, input)
	if states["das.governance.documentation.doc.module-master-doc"] != "true" ||
		states["das.governance.documentation.doc.package-no-fake-profile"] != "true" ||
		states["das.interaction.standard-ui.ui.token-enforcement"] != "true" ||
		states["das.interaction.standard-ui.ui.accessibility-gate"] != "false" {
		t.Fatal("actual module use or all-profile UI kit scope was lost")
	}
	values["ui.kit_exists"] = false
	values["module.codegen_or_verify_consumed"] = false
	setFacts(input, values)
	states = leafStates(t, input)
	if states["das.governance.documentation.doc.module-master-doc"] != "false" ||
		states["das.interaction.standard-ui.ui.token-enforcement"] != "false" {
		t.Fatal("optional internal package or L0 prototype acquired stronger requirements")
	}
	delete(values, "module.codegen_or_verify_consumed")
	delete(values, "ui.kit_exists")
	setFacts(input, values)
	states = leafStates(t, input)
	if states["das.governance.documentation.doc.module-master-doc"] != "unknown" ||
		states["das.interaction.standard-ui.ui.token-enforcement"] != "unknown" {
		t.Fatal("unknown actual use or kit became an exemption")
	}
}

func TestReportAndDomainDutiesDoNotDependOnPassingOrPermissionClaims(t *testing.T) {
	input := leafRequest(t)
	values := map[string]any{
		"activity.governed_verify_report": true, "gate.failure_on_no_results": false,
		"gate.blocking_or_source_of_truth": true, "activity.governed_gate_entry": true,
		"gate.governed_output_expected": false, "activity.ai_assisted_domain_draft": true,
		"scenario.release_gate": true, "activity.bdd_scenario": true,
		"scenario.nondeterministic_external_dependencies": false,
		"verification.passed":                             false, "permission.domain_approved": false,
	}
	setFacts(input, values)
	states := leafStates(t, input)
	for _, id := range []string{"das.governance.verification-release.verify.report-explicit-not-run",
		"das.governance.verification-release.verify.report-no-empty-pass",
		"das.architecture-modularity.domain.owner-accept-release-scenario"} {
		if states[id] != "true" {
			t.Fatal("a PASS or permission claim hid a duty: " + id)
		}
	}
	for _, id := range []string{"das.governance.verification-release.verify.report-no-results-fails",
		"das.governance.verification-release.verify.registry-expected-artifacts",
		"das.architecture-modularity.domain.nondeterministic-scenario-isolated"} {
		if states[id] != "false" {
			t.Fatal("an absent policy/activity condition became mandatory: " + id)
		}
	}
	delete(values, "gate.failure_on_no_results")
	setFacts(input, values)
	if leafStates(t, input)["das.governance.verification-release.verify.report-no-results-fails"] != "unknown" {
		t.Fatal("missing declared no-result policy became PASS")
	}
}

func TestIdentifierScopeDoesNotInventUnrelatedIdentifiersOrWaiveObjectMinima(t *testing.T) {
	input := leafRequest(t)
	setFacts(input, map[string]any{
		"activity.canonical_identifier_surface": true, "identifier.gating_dataset_id_surface": true,
		"identifier.job_id_surface": false, "activity.job_envelope": true,
	})
	states := leafStates(t, input)
	if states["das.contracts-compatibility.contract.stable-gating-dataset-id"] != "true" ||
		states["das.contracts-compatibility.contract.stable-job-id"] != "false" ||
		states["das.contracts-compatibility.contract.stable-error-code"] != "unknown" {
		t.Fatal("stability requirements ignored their actual declared identifier surface")
	}
	if states["das.contracts-compatibility.contract.job-profile"] != "true" ||
		states["das.contracts-compatibility.contract.job-config-identity"] != "true" {
		t.Fatal("identifier-scope facts hid independent required envelope fields")
	}
	setFacts(input, map[string]any{"activity.canonical_identifier_surface": true, "identifier.job_id_surface": true})
	input["facts"] = append(input["facts"].([]any), map[string]any{
		"key": "identifier.job_id_surface", "value": false, "sourceRef": "independent:conflicting-identifier"})
	if leafStates(t, input)["das.contracts-compatibility.contract.stable-job-id"] != "conflict" {
		t.Fatal("conflicting identifier declarations became exemptions")
	}
}

func TestDocumentationDriftDoesNotTurnWaiversIntoPermissionOrDropL2(t *testing.T) {
	input := leafRequest(t)
	values := map[string]any{
		"activity.doc_drift_observed": true, "change.drift_external_or_persisted": false,
		"drift.not_fixed_in_current_pr": true, "activity.doc_drift_waiver": false,
		"permission.waiver_approved": true, "profile.l2": false,
		"activity.out_of_band_doc_edit": true,
	}
	setFacts(input, values)
	states := leafStates(t, input)
	for _, suffix := range []string{"drift-record-immediately", "drift-one-outcome", "drift-decision-record", "out-of-band-reconcile-or-noncanonical"} {
		if states["das.governance.documentation.doc."+suffix] != "true" {
			t.Fatal("a waiver or optional legal alternative hid a present drift duty: " + suffix)
		}
	}
	for _, suffix := range []string{"drift-external-compatibility", "drift-old-new-fixtures", "drift-reproducing-gate",
		"drift-waiver-owner", "drift-waiver-scope", "drift-waiver-expiry", "l2-automated-drift-check", "l2-drift-ci"} {
		if states["das.governance.documentation.doc."+suffix] != "false" {
			t.Fatal("an optional waiver, external impact or L2 condition was erased: " + suffix)
		}
	}
	delete(values, "change.drift_external_or_persisted")
	delete(values, "profile.l2")
	setFacts(input, values)
	states = leafStates(t, input)
	if states["das.governance.documentation.doc.drift-external-compatibility"] != "unknown" ||
		states["das.governance.documentation.doc.l2-drift-ci"] != "unknown" {
		t.Fatal("missing impact/profile facts became exemptions")
	}
	values["activity.doc_drift_waiver"] = true
	values["profile.l2"] = true
	setFacts(input, values)
	states = leafStates(t, input)
	if states["das.governance.documentation.doc.drift-waiver-owner"] != "true" ||
		states["das.governance.documentation.doc.l2-drift-ci"] != "true" {
		t.Fatal("an adopted waiver lost metadata or L2 lost its independent CI requirement")
	}
	input["facts"] = append(input["facts"].([]any), map[string]any{
		"key": "profile.l2", "value": false, "sourceRef": "independent:contradictory-profile"})
	if leafStates(t, input)["das.governance.documentation.doc.l2-drift-ci"] != "conflict" {
		t.Fatal("a contradictory profile became a waiver")
	}
}

func TestBudgetAndStreamScopePreservesEventsAndActualSurfaces(t *testing.T) {
	input := leafRequest(t)
	setFacts(input, map[string]any{
		"activity.algorithm_execution": true, "budget.exhaustion_occurred": false,
		"activity.legacy_ui_stream": true, "stream.text_surface": false,
		"pipeline.compute_bound": true, "stream.progress_unavailable": false,
	})
	states := leafStates(t, input)
	for _, suffix := range []string{"stable-exhaustion-code", "stream-append", "stream-generic-working"} {
		if states["das.contracts-compatibility.contract."+suffix] != "false" {
			t.Fatal("original condition was erased: " + suffix)
		}
	}
	for _, suffix := range []string{"stable-resource-names", "stream-terminal", "stream-timeout", "stream-recovery"} {
		if states["das.contracts-compatibility.contract."+suffix] != "true" {
			t.Fatal("conditional response rules hid an independent obligation: " + suffix)
		}
	}
	setFacts(input, map[string]any{"activity.algorithm_execution": true, "activity.legacy_ui_stream": true, "pipeline.compute_bound": true})
	states = leafStates(t, input)
	for _, suffix := range []string{"stable-exhaustion-code", "stream-append", "stream-generic-working"} {
		if states["das.contracts-compatibility.contract."+suffix] != "unknown" {
			t.Fatal("missing original trigger became an exemption: " + suffix)
		}
	}
	setFacts(input, map[string]any{
		"activity.algorithm_execution": true, "budget.exhaustion_occurred": true,
		"activity.legacy_ui_stream": true, "stream.text_surface": true,
		"pipeline.compute_bound": true, "stream.progress_unavailable": true,
		"permission.write_allowed": false, "verification.passed": false,
	})
	states = leafStates(t, input)
	for _, suffix := range []string{"stable-exhaustion-code", "stream-append", "stream-generic-working"} {
		if states["das.contracts-compatibility.contract."+suffix] != "true" {
			t.Fatal("permission or PASS claims hid a real response duty: " + suffix)
		}
	}
	input["facts"] = append(input["facts"].([]any), map[string]any{
		"key": "budget.exhaustion_occurred", "value": false, "sourceRef": "independent:contradictory-budget-event"})
	if leafStates(t, input)["das.contracts-compatibility.contract.stable-exhaustion-code"] != "conflict" {
		t.Fatal("conflicting actual events became a waiver")
	}
}

func TestAlgorithmTrackSeparatesTierReplayHardTerminationAndDryRun(t *testing.T) {
	input := leafRequest(t)
	values := map[string]any{
		"activity.algorithm_pipeline": true, "pipeline.tier_0_or_1": false,
		"activity.algorithm_execution": true, "budget.limit_affects_execution": true, "budget.hard_termination": false,
		"activity.external_write_adapter": true, "activity.algorithm_adapter": true, "side_effects.dry_run": false,
		"activity.algorithm_run": true, "change.algorithm_material": false, "change.large_algorithm_refactor": false,
	}
	setFacts(input, values)
	states := leafStates(t, input)
	for _, suffix := range []string{"tier-master-doc", "tier-run-manifest", "pipeline-budget-policy",
		"runtime-budget-enforcement", "limit-diagnostic-code", "adapter-check-before-write",
		"run-manifest", "pipeline-result", "exact-manifest-pointer", "lossless-job-wrapping"} {
		if states["das.ai-runtime-evaluation.algorithm."+suffix] != "true" {
			t.Fatal("an absent field or successful check hid the algorithm duty: " + suffix)
		}
	}
	for _, suffix := range []string{"replay-config", "replay-dependency-pins", "replay-harness", "replay-golden-fixtures",
		"replay-ci", "hard-termination-code", "dry-run-read-only-or-fakes", "material-change-evaluations", "large-refactor-safe-migration"} {
		if states["das.ai-runtime-evaluation.algorithm."+suffix] != "false" {
			t.Fatal("a tier or mode condition became unconditional: " + suffix)
		}
	}
	delete(values, "pipeline.tier_0_or_1")
	setFacts(input, values)
	if leafStates(t, input)["das.ai-runtime-evaluation.algorithm.replay-ci"] != "unknown" {
		t.Fatal("missing tier became a replay waiver")
	}
	values["pipeline.tier_0_or_1"] = true
	values["budget.hard_termination"] = true
	values["side_effects.dry_run"] = true
	setFacts(input, values)
	states = leafStates(t, input)
	for _, suffix := range []string{"replay-ci", "hard-termination-code", "dry-run-read-only-or-fakes"} {
		if states["das.ai-runtime-evaluation.algorithm."+suffix] != "true" {
			t.Fatal("an actual tier, hard termination or dry run lost its duty: " + suffix)
		}
	}
	input["facts"] = append(input["facts"].([]any), map[string]any{
		"key": "pipeline.tier_0_or_1", "value": false, "sourceRef": "independent:contradictory-tier"})
	if leafStates(t, input)["das.ai-runtime-evaluation.algorithm.replay-ci"] != "conflict" {
		t.Fatal("a tier conflict became an exemption")
	}
}

func TestTopologyAlternativesRemainObligationsAndDoNotBecomePermissionPredicates(t *testing.T) {
	input := leafRequest(t)
	setFacts(input, map[string]any{
		"activity.cross_repo_boundary": true, "component.data_evals": true, "component.contracts_hub": true,
		"activity.multi_repo_system": true, "material.external_dependencies": false,
		"permission.compliance_approved": true, "verification.atomic_cutover_passed": true,
	})
	states := leafStates(t, input)
	for _, suffix := range []string{"cross-repo-compatible-or-atomic", "eval-data-scrubbed-or-approved",
		"hub-no-business-logic", "hub-no-orchestration", "contract-schema", "contract-semantics",
		"contract-positive-fixtures", "contract-negative-fixtures", "contract-ci-checks", "contract-compatibility-runners"} {
		if states["das.architecture-modularity.topology."+suffix] != "true" {
			t.Fatal("an approval or already-passing claim hid the obligation to satisfy a lawful branch: " + suffix)
		}
	}
	if states["das.architecture-modularity.topology.harness-external-replay"] != "false" {
		t.Fatal("a system without external dependencies acquired an unconditional replay requirement")
	}
	setFacts(input, map[string]any{"activity.multi_repo_system": true})
	if leafStates(t, input)["das.architecture-modularity.topology.harness-external-replay"] != "unknown" {
		t.Fatal("missing dependency facts became an exemption")
	}
}

func TestContractMinimaDoNotDependOnTheirOwnPresenceAndPreserveOldCompatibility(t *testing.T) {
	input := leafRequest(t)
	setFacts(input, map[string]any{
		"activity.run_manifest": true, "activity.job_envelope": true,
		"activity.legacy_job_envelope": true, "activity.compatibility_surface": true,
		"activity.legacy_compatibility_surface": true, "change.contract_breaking": false,
		"activity.dataset_manifest": true, "dataset.content_hash_present": false,
		"activity.shared_ui_component": true, "ui.kit_exists": false,
		"ui.component_state_referenced": "unknown", "activity.legacy_ui_stream": true,
		"pipeline.compute_bound": true, "stream.progress_feasible": false,
		"stream.progress_unavailable": true,
	})
	states := leafStates(t, input)
	for _, suffix := range []string{"run-config-identity", "run-input-identity", "run-side-effects-mode",
		"run-budget-remaining", "job-config-identity", "legacy-tolerant-reader", "job-legacy-tolerant-reader",
		"dataset-content-identity", "stream-terminal", "stream-timeout", "stream-recovery", "stream-generic-working"} {
		if states["das.contracts-compatibility.contract."+suffix] != "true" {
			t.Fatal("an absent required field or unavailable progress hid the obligation: " + suffix)
		}
	}
	for _, suffix := range []string{"breaking-major-version", "breaking-window", "dataset-hash-method", "component-story", "stream-progress"} {
		if states["das.contracts-compatibility.contract."+suffix] != "false" {
			t.Fatal("a conditional requirement became unconditional: " + suffix)
		}
	}
	if states["das.contracts-compatibility.contract.job-identical-pointers"] != "unknown" {
		t.Fatal("a missing pointer-presence fact became an exemption")
	}
	setFacts(input, map[string]any{"activity.shared_ui_component": true, "ui.kit_exists": true})
	if leafStates(t, input)["das.contracts-compatibility.contract.component-story"] != "unknown" {
		t.Fatal("a missing UI state inventory became a waiver")
	}
	input["facts"] = append(input["facts"].([]any), map[string]any{
		"key": "ui.kit_exists", "value": false, "sourceRef": "independent:conflicting-kit"})
	if leafStates(t, input)["das.contracts-compatibility.contract.component-story"] != "conflict" {
		t.Fatal("a contradictory kit declaration hid a shared component obligation")
	}
}

func TestMissingLeafFactsRemainUnknown(t *testing.T) {
	states := leafStates(t, leafRequest(t))
	always := []string{"policy-approval", "facts-approval", "acceptance-scope-approval", "unknown-risk-block"}
	for _, suffix := range always {
		id := "das.security-agent.z02." + suffix
		if states[id] != "true" {
			t.Fatal("independent approval duty became optional")
		}
		delete(states, id)
	}
	for _, suffix := range []string{"tool-provenance", "plugin-provenance", "rule-provenance", "cache-provenance", "adapter-provenance", "missing-capability-stop", "revocation-stop", "incident-stop", "downgrade-stop"} {
		id := "das.security-agent.z12." + suffix
		if states[id] != "true" {
			t.Fatal("provenance or safe-stop duty depends on a claimed current failure")
		}
		delete(states, id)
	}
	for _, suffix := range []string{"conformance-one", "interaction-one", "conformance-evolution"} {
		id := "das.core.profile." + suffix
		if states[id] != "true" {
			t.Fatal("unconditional profile duty became optional")
		}
		delete(states, id)
	}
	for _, suffix := range []string{"status-normative-values", "extension-no-silent-enum-widening"} {
		id := "das.core.manifest." + suffix
		if states[id] != "true" {
			t.Fatal("normative enum discipline became optional")
		}
		delete(states, id)
	}
	for id, state := range states {
		// S1-S3 are unconditional catalog/interpretation duties, apart from
		// the two explicitly chosen optional mechanisms. S18 contains both
		// global compatibility duties and actual activation/migration paths.
		alwaysCore := (strings.HasPrefix(id, "das.core.s1.") || strings.HasPrefix(id, "das.core.s2.") ||
			strings.HasPrefix(id, "das.core.s3.")) && id != "das.core.s2.engine-adapter-explicit-states-errors-output-fixtures" &&
			id != "das.core.s3.enhanced-index-explicit-identity-negotiation"
		for _, suffix := range []string{
			"beta-parsing-script-dispatch-image-lock-index-installer-test", "beta-target-separate-build-metadata-tag-prefix",
			"consumer-input-output-target-qualification-capabilities-separate", "doc-status-enum-separate-change-task-execution",
			"each-new-duty-old-id-cli-schema-window-compatibility-decision", "exact-target-artifact-support-matrix",
			"format-read-compatibility-distinct-current-authority", "gate-cadence-not-release-or-adoption-authority",
			"historic-diagnostic-input-no-weakened-new-control", "historic-version-fixtures-no-global-replacement",
			"invalid-unknown-version-unsupported-explicit-failure", "metadata-dispatch-reader-writer-downgrade-regressions",
			"migration-retains-original-value-digest-source-gap-no-fabricated-evidence", "prerelease-name-no-existing-compatibility-promise-waiver",
			"protected-control-minimum-policy-tool-versions-no-worker-downgrade", "public-version-policy-matches-compatibility-decision",
			"reader-before-writer-optional-not-reader-compatibility-proof", "revoked-vulnerable-old-executable-no-compatibility-authority",
			"standard-tool-protocol-channel-deployment-coordinates-independent", "supported-old-legal-format-original-semantics",
			"version-single-author-manifest-index-report-consistency",
		} {
			alwaysCore = alwaysCore || id == "das.core.s18."+suffix
		}
		if alwaysCore {
			if state != "true" {
				t.Fatalf("unconditional catalog/compatibility duty became optional: %s", id)
			}
			continue
		}
		if state != "unknown" {
			t.Fatalf("missing fact removed %s: %s", id, state)
		}
	}
}

func TestReleaseAndExtensionApplicabilityDoesNotStrengthenOptionalMechanisms(t *testing.T) {
	input := leafRequest(t)
	setFacts(input, map[string]any{
		"activity.standard_release": true, "standard.repo_canonical": true,
		"standard.uses_suite_lock": false, "standard.ships_normative_addendum": false,
		"activity.local_extension": true, "extension.satisfies_core_doc_type": false,
		"extension.has_upstreaming_trigger": true, "extension.has_review_date": false,
	})
	states := leafStates(t, input)
	for _, suffix := range []string{"manifest-enum-conformance", "manifest-version", "artifact-version",
		"published-required-paths", "published-link-closure", "extension-owner", "extension-review-trigger",
		"extension-machine-manifest", "extension-masterdoc-reference"} {
		if states["das.core.manifest."+suffix] != "true" {
			t.Fatal("an actual release/extension lost its existing duty: " + suffix)
		}
	}
	for _, suffix := range []string{"manifest-suite-lock-schema", "addendum-required-entries",
		"manifest-shipped-addenda", "extension-doc-type-mapping"} {
		if states["das.core.manifest."+suffix] != "false" {
			t.Fatal("a conditionally optional mechanism became compulsory: " + suffix)
		}
	}
	if states["das.core.manifest.manifest-verify-report-schema"] != "unknown" {
		t.Fatal("a missing mechanism declaration became a waiver")
	}
	setFacts(input, map[string]any{"activity.standard_release": false, "activity.local_extension": false})
	states = leafStates(t, input)
	for _, suffix := range []string{"artifact-version", "manifest-suite-lock-schema", "extension-owner"} {
		if states["das.core.manifest."+suffix] != "false" {
			t.Fatal("an ordinary product acquired standard-publisher/extension duties")
		}
	}
	if states["das.core.manifest.extension-no-silent-enum-widening"] != "true" {
		t.Fatal("undeclared extensions waived the ban on silent enum widening")
	}
}

func TestSDMMBoundariesAndConditionalBreakingWindowStayIndependent(t *testing.T) {
	input := leafRequest(t)
	setFacts(input, map[string]any{
		"activity.module_boundary": true, "activity.external_or_persisted_surface": true,
		"boundary.internal_nonpersisted": true, "change.contract_breaking": false,
	})
	states := leafStates(t, input)
	for _, suffix := range []string{"no-deep-imports", "explicit-graph", "enforce-graph", "acyclic-graph",
		"safe-import", "fast-import", "no-import-io", "no-import-network", "no-import-global-mutation",
		"no-import-expensive-init", "consumed-contracts", "produced-contracts", "contract-tests",
		"compatible-reader", "refactor-boundaries", "refactor-graph", "canonical-verify"} {
		if states["das.architecture-modularity.sdmm."+suffix] != "true" {
			t.Fatal("a configured boundary lost an existing duty: " + suffix)
		}
	}
	if states["das.architecture-modularity.sdmm.breaking-migration-window"] != "false" {
		t.Fatal("a nonbreaking change acquired an unconditional migration requirement")
	}
	setFacts(input, map[string]any{"activity.external_or_persisted_surface": true, "change.contract_breaking": "unknown"})
	if leafStates(t, input)["das.architecture-modularity.sdmm.breaking-migration-window"] != "unknown" {
		t.Fatal("an unclassified change lost its compatibility uncertainty")
	}
	setFacts(input, map[string]any{"activity.external_or_persisted_surface": true, "change.contract_breaking": true})
	if leafStates(t, input)["das.architecture-modularity.sdmm.breaking-migration-window"] != "true" {
		t.Fatal("a breaking external change lost its migration window")
	}
	setFacts(input, map[string]any{"activity.module_boundary": false, "boundary.internal_nonpersisted": false})
	if leafStates(t, input)["das.architecture-modularity.sdmm.no-import-network"] != "false" {
		t.Fatal("non-module activity acquired an import-time requirement")
	}
}

func TestExistingProfileConditionsDoNotBecomeExemptions(t *testing.T) {
	input := leafRequest(t)
	setFacts(input, map[string]any{
		"profile.l0": true, "profile.headless": true, "profile.standard_ui": false,
		"profile.hfvi": false, "activity.headless_pointer_doc": false,
		"activity.new_or_adopted_document": true, "document.legacy_v1_3_conformant": false,
		"activity.external_or_persisted_surface": true,
	})
	states := leafStates(t, input)
	for _, suffix := range []string{"l0-deferred-scope", "l0-debt-owner", "l0-revisit-trigger",
		"headless-note", "headless-operator-surface", "headless-cli-api-surfaces",
		"headless-job-runtime-surfaces", "headless-packet-export-surfaces", "headless-no-screen-reason",
		"conformance-explicit-new-document", "interaction-explicit-new-document", "external-compatibility", "external-fixtures"} {
		if states["das.core.profile."+suffix] != "true" {
			t.Fatal("a declared profile/activity lost an existing obligation: " + suffix)
		}
	}
	for _, suffix := range []string{"headless-pointer-link", "ui-spec", "hfvi-section", "hfvi-appendix",
		"conformance-legacy-declaration", "interaction-legacy-declaration"} {
		if states["das.core.profile."+suffix] != "false" {
			t.Fatal("an optional or unrelated path acquired an unconditional obligation: " + suffix)
		}
	}
	if states["das.core.profile.interaction-enum-source"] != "unknown" {
		t.Fatal("missing activity facts were treated as an exemption")
	}
	setFacts(input, map[string]any{"profile.standard_ui": "unknown", "profile.hfvi": true})
	states = leafStates(t, input)
	if states["das.core.profile.ui-spec"] != "true" {
		t.Fatal("HFVI did not carry its Standard UI document obligation")
	}
	input["facts"] = append(input["facts"].([]any), map[string]any{
		"key": "profile.hfvi", "value": false, "sourceRef": "fixture:conflicting-declaration"})
	if leafStates(t, input)["das.core.profile.ui-spec"] != "conflict" {
		t.Fatal("conflicting profile declarations silently removed an obligation")
	}
}

func TestLegacyDefaultsDoNotSupplyGovernedFactsOrWaiveNewAdoption(t *testing.T) {
	input := leafRequest(t)
	for _, adopted := range []bool{false, true} {
		setFacts(input, map[string]any{
			"document.legacy_v1_3_conformant":  true,
			"activity.new_or_adopted_document": adopted,
			"document.kind_master_doc":         true,
		})
		states := leafStates(t, input)
		for _, suffix := range []string{"conformance-legacy-declaration", "interaction-legacy-declaration"} {
			if states["das.core.profile."+suffix] != "true" {
				t.Fatal("legacy declaration guidance lost its actual historical scope: " + suffix)
			}
		}
		want := "false"
		if adopted {
			want = "true"
		}
		for _, suffix := range []string{"conformance-explicit-new-document", "interaction-explicit-new-document"} {
			if states["das.core.profile."+suffix] != want {
				t.Fatal("legacy compatibility waived explicit new adoption: " + suffix)
			}
		}
		for _, id := range []string{
			"das.core.profile.ui-spec", "das.core.profile.headless-note", "das.core.profile.l0-deferred-scope",
			"das.governance.documentation.manifest-rule.l2-master-doc-requires-context-pack",
			"das.interaction.headless.manifest-rule.headless-master-doc-requires-headless-surface-note",
		} {
			if states[id] != "unknown" {
				t.Fatal("legacy warning/default became a governed positive or exemption: " + id)
			}
		}
		if len(input["facts"].([]any)) != 3 {
			t.Fatal("the resolver filled historical defaults into approved facts")
		}
	}
}

func TestLegacyConditionsAndPerActionDuties(t *testing.T) {
	input := leafRequest(t)
	setFacts(input, map[string]any{
		"activity.ai_task_or_pr": true, "change.contract_needed": true, "change.contract_breaking": false,
		"activity.protected_action": true, "activity.delegation": false, "activity.evidence_consumption": false,
	})
	states := leafStates(t, input)
	for _, suffix := range []string{"repo-scope", "module-scope", "contract-surface-scope", "contract-impact", "determinism-tier", "replay-expectation", "budgets", "verification-commands", "verification-outcomes"} {
		if states["das.security-agent.ai-task."+suffix] != "true" {
			t.Fatal("AI task lost a mandatory field")
		}
	}
	if states["das.security-agent.ai-task.breaking-compatibility-plan"] != "false" {
		t.Fatal("nonbreaking change acquired an unconditional compatibility plan")
	}
	for _, suffix := range []string{"document-sequencing", "enforce-sequencing"} {
		if states["das.security-agent.cross-repo."+suffix] != "true" {
			t.Fatal("contract change lost a sequencing duty")
		}
	}
	for _, suffix := range []string{"subject-recheck", "resource-recheck", "action-recheck", "expiry-recheck", "budget-recheck", "generation-recheck"} {
		if states["das.security-agent.z04."+suffix] != "true" {
			t.Fatal("protected action lost a per-action recheck")
		}
	}
	if states["das.security-agent.z04.delegation-ceiling"] != "false" || states["das.security-agent.z08.report-trust"] != "false" {
		t.Fatal("unrelated duties ignored their actual applicability condition")
	}
}

func TestBreakingPlanUsesStrongKleeneCondition(t *testing.T) {
	for _, row := range []struct {
		task, breaking any
		want           string
	}{{true, true, "true"}, {true, false, "false"}, {true, "unknown", "unknown"}, {false, "unknown", "false"}, {"unknown", true, "unknown"}} {
		input := leafRequest(t)
		setFacts(input, map[string]any{"activity.ai_task_or_pr": row.task, "change.contract_breaking": row.breaking})
		if leafStates(t, input)["das.security-agent.ai-task.breaking-compatibility-plan"] != row.want {
			t.Fatal("breaking-plan condition collapsed unknown or ignored its task scope")
		}
	}
}

func TestLeafSourceConflictsSurviveFactOrderAndRiskAddition(t *testing.T) {
	input := leafRequest(t)
	a := map[string]any{"key": "activity.protected_action", "value": true, "sourceRef": "scan:A"}
	b := map[string]any{"key": "activity.protected_action", "value": false, "sourceRef": "scan:B"}
	input["facts"] = []any{a, b}
	first, err := Preview(input)
	if err != nil {
		t.Fatal(err)
	}
	input["facts"] = []any{b, a}
	second, err := Preview(input)
	if err != nil || !reflect.DeepEqual(first, second) {
		t.Fatal("fact input order changed leaf resolution")
	}
	if leafStates(t, input)["das.security-agent.z04.generation-recheck"] != "conflict" {
		t.Fatal("conflict sources turned into an exemption")
	}
	keys := []string{"activity.ai_task_or_pr", "change.contract_needed", "change.contract_breaking", "activity.protected_action", "activity.delegation", "activity.evidence_consumption"}
	for mask := 0; mask < 64; mask++ {
		values := map[string]any{}
		for i, key := range keys {
			values[key] = mask&(1<<i) != 0
		}
		setFacts(input, values)
		before := leafStates(t, input)
		for i, key := range keys {
			if mask&(1<<i) != 0 {
				continue
			}
			values[key] = true
			setFacts(input, values)
			after := leafStates(t, input)
			for id, state := range before {
				if state == "true" && after[id] != "true" {
					t.Fatal("adding a risk removed a leaf duty")
				}
			}
			values[key] = false
		}
	}
}

func TestChangedRequirementCatalogAndDowngradeReject(t *testing.T) {
	for _, fault := range []string{"remove", "duplicate", "weaken", "condition", "body", "owner", "baseline", "version", "module-parent", "module-owner", "v1-smuggle", "self-approve"} {
		t.Run(fault, func(t *testing.T) {
			input := leafRequest(t)
			requirements := input["requirementsCatalog"].(map[string]any)
			leaves := requirements["editionRequirements"].([]any)
			first := leaves[0].(map[string]any)
			catalog := input["catalog"].(map[string]any)
			switch fault {
			case "remove":
				requirements["editionRequirements"] = leaves[:len(leaves)-1]
			case "duplicate":
				leaves[len(leaves)-1] = first
			case "weaken":
				first["strength"] = "SHOULD"
			case "condition":
				first["activation"] = map[string]any{"op": "const", "value": false}
			case "body":
				first["bodyRefs"].([]any)[0].(map[string]any)["textSha256"] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			case "owner":
				first["ownerModule"] = "das.core"
			case "baseline":
				catalog["baselineSha256"] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			case "version":
				catalog["standardVersion"] = "1.4.0"
			case "module-parent", "module-owner":
				for _, raw := range catalog["modules"].([]any) {
					module := raw.(map[string]any)
					if module["id"] == "das.security-agent" {
						if fault == "module-parent" {
							module["clauseIds"] = []any{}
						} else {
							module["legacyUnitIds"] = []any{}
						}
					}
				}
			case "v1-smuggle":
				input["contractIdentity"] = "das-bundle-preview-input/v1"
			case "self-approve":
				input["approved"] = true
			}
			if _, err := Preview(input); err == nil {
				t.Fatal("changed mandatory catalog or authority claim accepted")
			}
		})
	}
}

func TestZTableActivityScopesAndNecessaryExternalMaterial(t *testing.T) {
	input := leafRequest(t)
	setFacts(input, map[string]any{
		"activity.verification": true, "activity.integration": false,
		"material.external_required": false, "risk.agent_authored_tests": false,
	})
	states := leafStates(t, input)
	for _, part := range []string{"candidate", "code", "document", "config", "dependency"} {
		if states["das.security-agent.z06.verification-"+part+"-binding"] != "true" || states["das.security-agent.z06.integration-"+part+"-binding"] != "false" {
			t.Fatal("verification and integration scopes were collapsed")
		}
	}
	if states["das.security-agent.z06.verification-external-binding"] != "false" || states["das.security-agent.z07.agent-tests-not-sole-acceptance"] != "false" || states["das.security-agent.z07.independent-verification"] != "true" {
		t.Fatal("external necessity or Agent-test condition changed")
	}
	setFacts(input, map[string]any{"activity.verification": true, "activity.integration": false})
	states = leafStates(t, input)
	if states["das.security-agent.z06.verification-external-binding"] != "unknown" || states["das.security-agent.z06.integration-external-binding"] != "false" || states["das.security-agent.z07.agent-tests-not-sole-acceptance"] != "unknown" {
		t.Fatal("missing material/test facts became exemptions or ignored known scope")
	}
	setFacts(input, map[string]any{"activity.integration": true, "change.integration_competition": false, "change.integration_rebase": true})
	states = leafStates(t, input)
	if states["das.security-agent.z09.target-baseline-check"] != "true" || states["das.security-agent.z09.competition-reverification"] != "false" || states["das.security-agent.z09.rebase-reverification"] != "true" || states["das.security-agent.z09.merge-result-reverification"] != "unknown" {
		t.Fatal("integration triggers were conflated or defaulted")
	}
}

func TestEveryMinimumControlAndNewRiskHasAnIndependentObservedDuty(t *testing.T) {
	input := leafRequest(t)
	// These independent observation targets are not inferred from the catalog.
	targets := map[string]string{
		"activity.agent_execution":         "das.security-agent.z01.no-self-approval",
		"activity.worker_execution":        "das.security-agent.z03.policy-write-denial",
		"activity.untrusted_execution":     "das.security-agent.z05.control-socket-denial",
		"activity.verification":            "das.security-agent.z07.independent-verification",
		"activity.integration":             "das.security-agent.z09.target-baseline-check",
		"material.external_required":       "das.security-agent.z06.verification-external-binding",
		"risk.agent_authored_tests":        "das.security-agent.z07.agent-tests-not-sole-acceptance",
		"change.integration_competition":   "das.security-agent.z09.competition-reverification",
		"change.integration_rebase":        "das.security-agent.z09.rebase-reverification",
		"change.integration_merge_result":  "das.security-agent.z09.merge-result-reverification",
		"activity.completion":              "das.security-agent.z10.force-no-conformance",
		"activity.log_emission":            "das.security-agent.z11.log-secret-exclusion",
		"activity.artifact_output":         "das.security-agent.z11.artifact-secret-exclusion",
		"activity.authoritative_write":     "das.security-agent.s13.storage.transaction-before-read",
		"activity.state_backup":            "das.security-agent.s13.storage.backup-consistent-boundary",
		"activity.artifact_registration":   "das.security-agent.s13.storage.artifact-complete-bytes",
		"storage.system_crash_covered":     "das.security-agent.s13.storage.artifact-protected-reference",
		"storage.linux_filesystem":         "das.security-agent.s13.storage.artifact-directory-sync",
		"activity.artifact_recovery":       "das.security-agent.s13.storage.recovery-no-different-bytes",
		"activity.qualification_issuance":  "das.security-agent.s13.storage.qualification-durable-evidence",
		"activity.audit_recording":         "das.security-agent.s13.control.audit-checkpoint",
		"activity.protected_read":          "das.security-agent.s13.control.read-caller-binding",
		"activity.capability_url_handling": "das.security-agent.s13.control.capability-revocation",
		"activity.continuous_disclosure":   "das.security-agent.s13.control.disclosure-bounded-unit",
	}
	all := map[string]any{
		"activity.ai_task_or_pr": true, "change.contract_needed": true, "change.contract_breaking": true,
		"activity.protected_action": true, "activity.delegation": true, "activity.evidence_consumption": true,
	}
	for key := range targets {
		all[key] = true
	}
	setFacts(input, all)
	for id, state := range leafStates(t, input) {
		// Retain the original AI-task/Z/S13 denominator. Newly mapped operational
		// activities have their own independent observations and scope tests.
		minimum := strings.HasPrefix(id, "das.security-agent.ai-task.") ||
			strings.HasPrefix(id, "das.security-agent.cross-repo.") ||
			strings.HasPrefix(id, "das.security-agent.z") ||
			strings.HasPrefix(id, "das.security-agent.s13.storage.") ||
			strings.HasPrefix(id, "das.security-agent.s13.control.")
		if minimum && state != "true" {
			t.Fatalf("all risks known true lost %s", id)
		}
	}
	for key, id := range targets {
		// Reuse these exact observations for the monotonicity comparison below.
		// Catalog and other facts are unchanged within this one risk's cases.
		booleanStates := map[bool]map[string]string{}
		for _, known := range []any{false, "unknown", true} {
			all[key] = known
			setFacts(input, all)
			want := "unknown"
			if value, ok := known.(bool); ok {
				want = "false"
				if value {
					want = "true"
				}
			}
			states := leafStates(t, input)
			if value, ok := known.(bool); ok {
				booleanStates[value] = states
			}
			if states[id] != want {
				t.Fatalf("risk %s ignored actual applicability %v", key, known)
			}
		}
		all[key] = true
		setFacts(input, all)
		input["facts"] = append(input["facts"].([]any), map[string]any{"key": key, "value": false, "sourceRef": "independent:conflict"})
		if leafStates(t, input)[id] != "conflict" {
			t.Fatalf("risk %s lost conflicting source", key)
		}
		before := booleanStates[false]
		for other, after := range booleanStates[true] {
			if before[other] == "true" && after != "true" {
				t.Fatal("new risk removed an existing duty")
			}
		}
	}
	// Gate duties apply regardless of whether an Agent claimed a bypass flag.
	setFacts(input, map[string]any{"activity.completion": true, "activity.protected_action": true, "activity.worker_execution": true})
	states := leafStates(t, input)
	for _, id := range []string{"das.security-agent.z01.unidentified-denial", "das.security-agent.z01.unauthorized-denial", "das.security-agent.z01.expired-denial", "das.security-agent.z03.validator-write-denial", "das.security-agent.z03.key-write-denial", "das.security-agent.z10.done-no-conformance", "das.security-agent.z10.force-no-conformance", "das.security-agent.z10.waiver-no-conformance", "das.security-agent.z11.audit-rollback-denial"} {
		if states[id] != "true" {
			t.Fatal("missing authorization/bypass claims disabled a minimum control")
		}
	}
}

func TestStorageConfiguredPathIncludesFailureHandlingBeforeAnyClaimedFailure(t *testing.T) {
	input := leafRequest(t)
	setFacts(input, map[string]any{
		"activity.authoritative_write": true, "failure.transaction_statement": false,
		"request.identity_conflict": false, "permission.write_allowed": false,
		"activity.artifact_registration": true, "storage.system_crash_covered": false,
		"activity.artifact_recovery": true,
	})
	states := leafStates(t, input)
	for _, criterion := range []string{"conflict-fingerprint", "conflict-original-or-deny", "failed-transaction-state", "failed-transaction-rollback", "connection-constraint-proof"} {
		if states["das.security-agent.s13.storage."+criterion] != "true" {
			t.Fatal("no claimed fault or permission waived write-path integrity", criterion)
		}
	}
	for _, criterion := range []string{"artifact-complete-bytes", "artifact-storage-durability", "artifact-protected-reference", "artifact-directory-sync", "artifact-sync-results"} {
		if states["das.security-agent.s13.storage."+criterion] != "false" {
			t.Fatal("specific system-crash obligation lost its fault-model condition", criterion)
		}
	}
	// A narrower fault model cannot waive the other registration/recovery duties.
	if states["das.security-agent.s13.storage.recovery-no-different-bytes"] != "true" {
		t.Fatal("narrow durability model waived truthful recovery")
	}
}

func TestControlConfiguredPathsCannotBeWaivedByPermissionOrFailureClaims(t *testing.T) {
	input := leafRequest(t)
	setFacts(input, map[string]any{
		"activity.authoritative_write": true, "activity.protected_action": true,
		"activity.protected_read": true, "activity.capability_url_handling": true,
		"activity.audit_recording": true, "activity.log_emission": true,
		"permission.read_allowed": false, "failure.result_write": false,
		"failure.audit_channel": false, "failure.revoked": false,
	})
	states := leafStates(t, input)
	for _, criterion := range []string{"audit-checkpoint", "no-backfilled-success", "no-automatic-replay",
		"no-absence-as-nonexecution", "bounded-stop-without-record-channel", "read-caller-binding",
		"read-audience-binding", "capability-revocation", "capability-no-log-artifact",
		"revocation-no-confirmation-with-old-path", "redaction-no-enumerable-hash-claim"} {
		if states["das.security-agent.s13.control."+criterion] != "true" {
			t.Fatal("a permission/fault claim waived a configured path duty", criterion)
		}
	}
}

func TestContinuousDisclosureKeepsProtectedReadScopeAndUnknown(t *testing.T) {
	for _, row := range []struct {
		read, continuous any
		want             string
	}{{true, true, "true"}, {true, false, "false"}, {false, true, "false"},
		{true, "unknown", "unknown"}, {"unknown", true, "unknown"}, {"unknown", false, "false"}} {
		input := leafRequest(t)
		setFacts(input, map[string]any{"activity.protected_read": row.read, "activity.continuous_disclosure": row.continuous})
		states := leafStates(t, input)
		for _, criterion := range []string{"disclosure-bounded-unit", "disclosure-byte-record-limit",
			"disclosure-unit-time-limit", "disclosure-continuation-checkpoint", "disclosure-revocation-effect",
			"disclosure-revocation-confirmation", "disclosure-inflight-volume-limit", "disclosure-inflight-time-limit"} {
			if states["das.security-agent.s13.control."+criterion] != row.want {
				t.Fatal("disclosure ignored protected scope or collapsed unknown", criterion)
			}
		}
		if row.read == true && states["das.security-agent.s13.control.read-caller-binding"] != "true" {
			t.Fatal("a noncontinuous read lost ordinary read authority requirements")
		}
	}
}

func TestDeploymentProfilesAndLawfulRebuildRemainThreeValued(t *testing.T) {
	prefix := "das.governance.verification-release.deployment."
	for _, row := range []struct {
		adopt, l1, l2, rebuild any
		matrix, rebuilt        string
	}{
		{true, false, false, false, "false", "false"},
		{true, true, false, false, "true", "false"},
		{true, false, true, true, "true", "true"},
		{true, false, false, true, "false", "true"},
		{false, true, true, true, "false", "false"},
		{"unknown", true, false, true, "unknown", "unknown"},
	} {
		input := leafRequest(t)
		setFacts(input, map[string]any{"activity.deployment_governance": row.adopt,
			"profile.l1": row.l1, "profile.l2": row.l2, "build.rebuild_per_environment": row.rebuild})
		states := leafStates(t, input)
		if states[prefix+"environment-matrix-owner"] != row.matrix ||
			states[prefix+"chosen-per-env-rebuild-provenance"] != row.rebuilt {
			t.Fatal("deployment lost profile, actual adoption, alternative or unknown", row)
		}
	}
	input := leafRequest(t)
	setFacts(input, map[string]any{"activity.deployment_governance": true, "profile.l1": true, "profile.l2": false})
	input["facts"] = append(input["facts"].([]any), map[string]any{
		"key": "activity.deployment_governance", "value": false, "sourceRef": "independent:conflict"})
	if leafStates(t, input)[prefix+"environment-matrix-owner"] != "conflict" {
		t.Fatal("conflicting adoption became a deployment waiver")
	}
}

func TestManifestRulesUseGovernedDocumentFactsAndKeepUnknowns(t *testing.T) {
	input := leafRequest(t)
	values := map[string]any{
		"document.kind_master_doc": true, "document.conformance_l2": true,
		"document.interaction_headless": true, "document.interaction_standard_ui": false,
		"document.interaction_hfvi": false, "document.kind_module_doc": true,
		"document.module_worker": false, "document.module_service": true,
		"document.kind_ui_spec": true, "document.kind_headless_surface_note": true,
		"document.kind_normative_addendum": true,
		// A project's primary profile cannot replace a document's declaration.
		"profile.l2": false, "profile.headless": false, "profile.standard_ui": true,
		"permission.adoption_allowed": false,
	}
	wants := map[string]string{
		"das.governance.documentation.manifest-rule.l2-master-doc-requires-context-pack":                     "true",
		"das.interaction.headless.manifest-rule.headless-master-doc-requires-headless-surface-note":          "true",
		"das.interaction.standard-ui.manifest-rule.ui-projects-require-ui-spec":                              "false",
		"das.interaction.hfvi.manifest-rule.hfvi-projects-require-vis-appendix":                              "false",
		"das.governance.documentation.manifest-rule.worker-service-module-docs-require-interaction-profile":  "true",
		"das.governance.documentation.manifest-rule.master-doc-requires-canonical-entrypoint-role":           "true",
		"das.governance.documentation.manifest-rule.module-doc-requires-module-doc-role":                     "true",
		"das.interaction.headless.manifest-rule.ui-spec-requires-non-headless-interaction-profile":           "true",
		"das.interaction.headless.manifest-rule.headless-surface-note-requires-headless-interaction-profile": "true",
		"das.governance.documentation.manifest-rule.normative-addendum-requires-subordinate-role":            "true",
	}
	setFacts(input, values)
	states := leafStates(t, input)
	for id, want := range wants {
		if states[id] != want {
			t.Fatalf("manifest rule lost document scope or inherited permission: %s %s", id, states[id])
		}
	}
	id := "das.governance.documentation.manifest-rule.l2-master-doc-requires-context-pack"
	values["profile.l2"], values["document.conformance_l2"] = true, false
	setFacts(input, values)
	if leafStates(t, input)[id] != "false" {
		t.Fatal("project L2 imposed a different document's requirement")
	}
	delete(values, "document.conformance_l2")
	setFacts(input, values)
	if leafStates(t, input)[id] != "unknown" {
		t.Fatal("missing document declaration became a safe default")
	}
	values["document.kind_master_doc"] = false
	setFacts(input, values)
	if leafStates(t, input)[id] != "false" {
		t.Fatal("unrelated document requires an L2 declaration")
	}
	values["document.kind_master_doc"], values["document.conformance_l2"] = true, true
	setFacts(input, values)
	input["facts"] = append(input["facts"].([]any), map[string]any{
		"key": "document.conformance_l2", "value": false, "sourceRef": "independent:conflicting-document"})
	if leafStates(t, input)[id] != "conflict" {
		t.Fatal("conflicting document declarations were overwritten")
	}
}

func TestDeploymentPolicyDoesNotInheritExplicitL2MechanismScope(t *testing.T) {
	prefix := "das.governance.verification-release.deployment."
	for _, row := range []struct {
		adopt, l2         any
		policy, mechanism string
	}{
		{true, false, "true", "false"},
		{true, true, "true", "true"},
		{true, "unknown", "true", "unknown"},
		{false, true, "false", "false"},
		{"unknown", true, "unknown", "unknown"},
	} {
		input := leafRequest(t)
		setFacts(input, map[string]any{"activity.deployment_governance": row.adopt,
			"profile.l2": row.l2, "activity.ci_verification": true,
			"artifact.production": true, "activity.deployment": true})
		states := leafStates(t, input)
		for _, name := range []string{"time-to-fix-gating", "severity", "blocking-severities", "waiver-expiry"} {
			if states[prefix+"vulnerability-policy-"+name] != row.policy {
				t.Fatal("policy MUST lost actual adoption or acquired an L2 waiver", row, name)
			}
		}
		for _, name := range []string{"l2-production-sbom", "l2-ci-direct-transitive-sca", "l2-deployment-signature-check"} {
			if states[prefix+name] != row.mechanism {
				t.Fatal("explicit L2 mechanism scope changed", row, name)
			}
		}
	}
}

func TestCollaborationActualEmergencyAndOptionalRFCPreserveScope(t *testing.T) {
	prefix := "das.governance.verification-release.collaboration."
	for _, row := range []struct {
		coauthors, emergency, rfc any
		control, outcome          string
	}{
		{true, true, false, "true", "false"},
		{true, false, true, "false", "true"},
		{false, true, true, "false", "false"},
		{"unknown", true, true, "unknown", "unknown"},
	} {
		input := leafRequest(t)
		setFacts(input, map[string]any{"activity.multiparty_document_governance": row.coauthors,
			"activity.break_glass_change": row.emergency, "activity.governed_rfc": row.rfc,
			"profile.l2": false})
		states := leafStates(t, input)
		if states[prefix+"break-glass-limited-to-sev1-sev2"] != row.control ||
			states[prefix+"actual-rfc-explicit-outcome"] != row.outcome ||
			states[prefix+"l2-boundary-rule-trace-pr-approvals"] != "false" {
			t.Fatal("collaboration invented RFCs, exemptions or L2 for a L0 fixture", row)
		}
	}
}

func TestVisualCompanionOptionalReferencesKeepActualProfileAndBoundary(t *testing.T) {
	input := leafRequest(t)
	setFacts(input, map[string]any{"surface.ui": true, "surface.hfvi": false,
		"profile.hfvi": false, "activity.ui_spec_doc": true, "activity.ui_workflow": true,
		"ui.behavior_ambiguous_in_words": false, "workflow.crosses_boundary": false})
	states := leafStates(t, input)
	if states["das.interaction.standard-ui.ui.workflow-screen-map"] != "true" ||
		states["das.interaction.standard-ui.ui.boundary-workflow-contract-map"] != "false" ||
		states["das.interaction.standard-ui.ui.ambiguous-behavior-prototype-link"] != "false" ||
		states["das.interaction.hfvi.hfvi.vis-header-parent-master-doc"] != "false" {
		t.Fatal("normal UI invented HFVI, prototypes or cross-boundary contracts")
	}
}

func TestCapabilityAbsenceDoesNotWaiveReadsAndConflictsStayVisible(t *testing.T) {
	input := leafRequest(t)
	setFacts(input, map[string]any{"activity.protected_read": true, "activity.capability_url_handling": false})
	states := leafStates(t, input)
	if states["das.security-agent.s13.control.read-resource-domain-binding"] != "true" ||
		states["das.security-agent.s13.control.capability-current-identity"] != "false" {
		t.Fatal("capability absence changed ordinary read scope")
	}
	input["facts"] = append(input["facts"].([]any), map[string]any{
		"key": "activity.protected_read", "value": false, "sourceRef": "independent:conflict",
	})
	if leafStates(t, input)["das.security-agent.s13.control.read-caller-binding"] != "conflict" {
		t.Fatal("conflicting read scope became a waiver")
	}
}

func TestMasterTemplateActualAdoptionActivationAndExceptionsStayThreeValued(t *testing.T) {
	input := leafRequest(t)
	values := map[string]any{
		"activity.project_master_doc_template": false,
		"activity.document_activation":         true,
		"profile.l2":                           false,
		"profile.hfvi":                         false,
		"activity.long_running_operations":     true,
		"job.correlation_applicable":           false,
		"permission.activate_allowed":          false,
	}
	setFacts(input, values)
	states := leafStates(t, input)
	p := "das.governance.documentation.template."
	for _, name := range []string{"activation-blockers-resolved-or-adr-deferred", "actual-job-cancellation-semantics", "fenced-literals-not-placeholder-replacement"} {
		if states[p+name] != "false" {
			t.Fatal("a project that did not adopt the template acquired template-specific duties", name, states[p+name])
		}
	}
	values["activity.project_master_doc_template"] = true
	setFacts(input, values)
	states = leafStates(t, input)
	if states[p+"activation-blockers-resolved-or-adr-deferred"] != "true" || states[p+"actual-job-cancellation-semantics"] != "true" {
		t.Fatal("actual activation or job duty was hidden by permission", states)
	}
	for _, name := range []string{"activation-l2-current-context-pack", "activation-actual-hfvi-populated-vis", "actual-job-envelope-minimum-applicable-correlation"} {
		if states[p+name] != "false" {
			t.Fatal("template lost its profile/applicable-field condition", name, states[p+name])
		}
	}
	values["profile.l2"] = "unknown"
	setFacts(input, values)
	if leafStates(t, input)[p+"activation-l2-current-context-pack"] != "unknown" {
		t.Fatal("an unknown profile became a template exemption")
	}
}

func TestImplicitRequiredInformationPreservesReadinessProfilesAndActualSurfaces(t *testing.T) {
	input := leafRequest(t)
	values := map[string]any{
		"activity.project_master_doc_template": true, "activity.document_activation": false,
		"activity.active_master_doc_update": false, "activity.project_deployment": true,
		"profile.l1": false, "profile.l2": true, "domain.non_trivial": true,
		"surface.ui": false, "surface.hfvi": false, "activity.ui_spec_doc": true,
		"activity.ui_screen": true, "ui.multi_device": true,
		"profile.hfvi": false, "activity.hfvi_critical_interaction": true,
		"permission.activate_allowed": false, "checks.replay_passed": false,
	}
	setFacts(input, values)
	p := "das.governance.documentation.template."
	states := leafStates(t, input)
	for _, name := range []string{"required-traceability-contracts", "l1-l2-environment-matrix", "minimum-security-declaration-logging-policy"} {
		if states[p+name] != "false" {
			t.Fatal("a draft acquired active-document information duties", name, states[p+name])
		}
	}
	values["activity.active_master_doc_update"] = true
	values["surface.ui"] = true
	setFacts(input, values)
	states = leafStates(t, input)
	for _, id := range []string{p + "l1-l2-environment-matrix", p + "l1-l2-deployment-record-promotion-rule", p + "nontrivial-domain-glossary-definition", "das.interaction.standard-ui.ui.required-accessibility-record-focus", "das.interaction.standard-ui.ui.multidevice-record-breakpoints"} {
		if states[id] != "true" {
			t.Fatal("active information duty hidden by permission or missing result", id, states[id])
		}
	}
	if states["das.interaction.hfvi.hfvi.critical-interaction-verification-replay-command"] != "false" {
		t.Fatal("a non-HFVI surface acquired visual replay information duties")
	}
	values["profile.l2"] = false
	values["profile.l1"] = "unknown"
	values["domain.non_trivial"] = false
	values["profile.hfvi"] = true
	setFacts(input, values)
	states = leafStates(t, input)
	if states[p+"l1-l2-environment-matrix"] != "unknown" || states[p+"nontrivial-domain-glossary-definition"] != "false" || states["das.interaction.hfvi.hfvi.critical-interaction-verification-replay-command"] != "true" {
		t.Fatal("unknown profiles, actual domain or critical-interaction trigger were lost")
	}
}

func TestEveryCrossRepoChangeAndIndependentDeploymentKeepsOriginalTrigger(t *testing.T) {
	input := leafRequest(t)
	values := map[string]any{
		"activity.cross_repo_contract_change":                true,
		"activity.independent_deployments":                   true,
		"contract.supported_window_exists":                   false,
		"checks.already_passed":                              false,
		"activity.consumer_merge_before_producer_deployment": true,
		"activity.model_output_display":                      true,
		"output.not_explicitly_draft_or_unverified":          false,
		"component.frontend":                                 true,
		"activity.user_facing_ui":                            false,
	}
	setFacts(input, values)
	states := leafStates(t, input)
	p := "das.architecture-modularity.repo."
	for _, name := range []string{"cross-repo-change-verifiable-harness-or-fixtures", "independent-deployment-version-matrix-supported-window", "undeployed-producer-merge-tolerant-disabled-consumer", "undeployed-producer-merge-defined-rollout-plan", "recommended-role-gate-frontend-build"} {
		if states[p+name] != "true" {
			t.Fatal("required event or recommended role gate was hidden by readiness/result", name, states[p+name])
		}
	}
	for _, name := range []string{"model-schema-validation-before-visible-nondraft-output", "recommended-role-gate-frontend-visible-ui-smoke"} {
		if states[p+name] != "false" {
			t.Fatal("actual draft/headless legal boundary was lost", name, states[p+name])
		}
	}
	values["output.not_explicitly_draft_or_unverified"] = "unknown"
	setFacts(input, values)
	if leafStates(t, input)[p+"model-schema-validation-before-visible-nondraft-output"] != "unknown" {
		t.Fatal("unknown draft status became a validation exemption")
	}
}

func TestProductAdoptionDoesNotDependOnPublishingTheStandard(t *testing.T) {
	input := leafRequest(t)
	ids := []string{"specific-product-adoption-still-separate", "adoption-actor-artifact-deployment-target-facts-policy-scope-time-binding", "adoption-qualified-scope-time-not-permanent-trust", "control-affecting-drift-stops-related-actions-reanalysis-reverification", "every-new-action-current-authority"}
	for _, value := range []bool{true, false} {
		setFacts(input, map[string]any{"activity.standard_release": false, "activity.product_adoption": value, "activity.package_activation": false, "activity.continued_operation": false, "activity.protected_action": value})
		states := leafStates(t, input)
		expected := "false"
		if value {
			expected = "true"
		}
		for _, suffix := range ids {
			if states["das.governance.verification-release.s19."+suffix] != expected {
				t.Fatalf("%s: want %s got %s", suffix, expected, states["das.governance.verification-release.s19."+suffix])
			}
		}
		if states["das.governance.verification-release.s21.project-final-package-real-deployment-limited-adoption-continued-current-controls"] != expected {
			t.Fatal("final adoption scope changed")
		}
		if states["das.governance.verification-release.s19.offline-full-body-modules-schemas-fixtures-migration-coverage-view-package"] != "false" {
			t.Fatal("publisher duty leaked")
		}
	}
	setFacts(input, map[string]any{"activity.standard_release": false})
	if leafStates(t, input)["das.governance.verification-release.s19.adoption-qualified-scope-time-not-permanent-trust"] != "unknown" {
		t.Fatal("missing adoption fact was defaulted")
	}
}

func TestCurrentPreviewBindsBothCatalogs(t *testing.T) {
	input := leafRequest(t)
	input["catalog"].(map[string]any)["modules"].([]any)[0].(map[string]any)["title"] = "Changed display title"
	if _, err := Preview(input); err == nil || !strings.Contains(err.Error(), "module catalog identity") {
		t.Fatalf("unpinned module catalog accepted: %v", err)
	}
}
