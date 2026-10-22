package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"gopkg.in/yaml.v3"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/AzzCraft/cadence-oss/cadence-core/internal/baseline"
	"github.com/AzzCraft/cadence-oss/cadence-core/internal/checks"
	"github.com/AzzCraft/cadence-oss/cadence-core/internal/config"
	"github.com/AzzCraft/cadence-oss/cadence-core/internal/evidence"
	"github.com/AzzCraft/cadence-oss/cadence-core/internal/plugins"
	"github.com/AzzCraft/cadence-oss/cadence-core/internal/registry"
	"github.com/AzzCraft/cadence-oss/cadence-core/internal/replay"
	"github.com/AzzCraft/cadence-oss/cadence-core/internal/report"
	"github.com/AzzCraft/cadence-oss/cadence-core/internal/sandbox"
	"github.com/AzzCraft/cadence-oss/cadence-core/internal/signing"
	"github.com/AzzCraft/cadence-oss/cadence-core/internal/waiver"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	cmd := os.Args[1]
	switch cmd {
	case "version":
		versionCmd(os.Args[2:])
	case "contracts":
		contractsCmd(os.Args[2:])
	case "resolve":
		resolveCmd(os.Args[2:])
	case "verify":
		verifyCmd(os.Args[2:])
	case "scan":
		scanCmd(os.Args[2:])
	case "adopt":
		adoptCmd(os.Args[2:])
	case "report":
		reportCmd(os.Args[2:])
	case "lock":
		lockCmd(os.Args[2:])
	case "doctor":
		doctorCmd(os.Args[2:])
	case "--help", "-h", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", cmd)
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Print(`cadence (core) - offline deterministic CLI

Usage:
  cadence verify [--profile dev|ci|full] [--out .cadence/out] [--alias latest] [--run-id <id>]
  cadence scan [--json [--with-rule-trace]]
  cadence adopt
  cadence report --in <cadence-report.json|summary.json>
  cadence lock [--check]
  cadence doctor
  cadence version [--json]
  cadence contracts canonicalize --identity das-json-jcs/v1 < input.json
  cadence resolve --preview < proposal.json
  cadence contracts validate --identity <integration-contract> < object.json
  cadence contracts check-action --probe < supplied-context.json
  cadence contracts check-authorization --probe < supplied-context.json
  cadence contracts http-inventory --probe < locked-originals.json
  cadence contracts check-http-coverage --probe < supplied-coverage.json

Cadence Core is an offline deterministic runtime for local and CI verification.
The default checks are intentionally conservative and auditable.
`)
}

func physicalRepoRoot() string {
	root, err := os.Getwd()
	if err == nil {
		root, err = filepath.EvalSymlinks(root)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot resolve project root: %v\n", err)
		os.Exit(1)
	}
	return root
}

func verifyCmd(args []string) {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	outDir := fs.String("out", ".cadence/out", "output directory for evidence artifacts")
	runIDFlag := fs.String("run-id", "", "explicit run id (advanced; must be safe filename). If unset, Cadence generates a unique run id")
	alias := fs.String("alias", "latest", "write a stable alias directory under --out (e.g. 'latest') pointing to the most recent run. Set to empty to disable")
	profile := fs.String("profile", "dev", "execution profile (dev|ci|full)")
	breakGlass := fs.Bool("break-glass", false, "allow P0/P1 bypass with an auditable waiver")
	reason := fs.String("reason", "", "break-glass reason")
	ticket := fs.String("ticket", "", "incident/ticket id")
	waiverFile := fs.String("waiver-file", "", "path to a persisted waiver-file used for non-inline approval ingestion")
	approvalChainFile := fs.String("approval-chain-file", "", "path to a governed approval-chain file for non-inline waiver ingestion")
	waiverApprovedBy := fs.String("waiver-approved-by", "", "explicit approver identity for break-glass")
	waiverReferenceTime := fs.String("waiver-reference-time", "", "explicit RFC3339 decision time for break-glass")
	waiverExpiresAt := fs.String("waiver-expires-at", "", "explicit RFC3339 waiver expiry for break-glass")
	waiverSignature := fs.String("waiver-signature", "", "explicit waiver signature for break-glass")
	validateProtocol := fs.Bool("protocol-validate", true, "validate generated evidence against Cadence protocol invariants")
	_ = fs.Parse(args)

	if fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "verify: unexpected positional arguments", fs.Args())
		os.Exit(2)
	}
	*profile = strings.ToLower(strings.TrimSpace(*profile))
	if *profile != "dev" && *profile != "ci" && *profile != "full" {
		fmt.Fprintln(os.Stderr, "verify: profile must be dev, ci, or full")
		os.Exit(2)
	}
	signingMode := currentSigningMode()
	if signingMode != "dev" && signingMode != "governed" {
		fmt.Fprintln(os.Stderr, "verify: CADENCE_SIGNING_MODE must be dev or governed")
		os.Exit(2)
	}

	if *breakGlass && strings.TrimSpace(*waiverFile) != "" {
		fmt.Fprintln(os.Stderr, "verify failed: --break-glass is mutually exclusive with --waiver-file")
		os.Exit(2)
	}
	if strings.TrimSpace(*approvalChainFile) != "" && strings.TrimSpace(*waiverFile) == "" {
		fmt.Fprintln(os.Stderr, "verify failed: --approval-chain-file requires --waiver-file")
		os.Exit(2)
	}
	if strings.TrimSpace(*waiverFile) != "" && strings.TrimSpace(*ticket) == "" {
		fmt.Fprintln(os.Stderr, "verify failed: --waiver-file requires --ticket")
		os.Exit(2)
	}

	repoRoot := physicalRepoRoot()
	cfg, err := config.Load(repoRoot)
	if err != nil {
		fmt.Fprintf(os.Stderr, "verify failed: %v\n", err)
		os.Exit(1)
	}
	if cfg.UIEnabled {
		fmt.Fprintln(os.Stderr, "verify: UI verification unavailable in the core scanner; use the explicit reference UI runner")
		os.Exit(2)
	}
	registryPath := filepath.Join(repoRoot, cfg.RegistryRef)
	registryConfig, err := registry.Load(registryPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "verify failed: registryRef invalid: %v\n", err)
		os.Exit(1)
	}
	if err := registry.Validate(registryConfig); err != nil {
		fmt.Fprintf(os.Stderr, "verify failed: registryRef invalid: %v\n", err)
		os.Exit(1)
	}
	runtimePath := filepath.Join(repoRoot, cfg.RuntimeRef)
	sandboxPath := filepath.Join(repoRoot, cfg.SandboxRef)
	sandboxProfile, err := sandbox.Load(sandboxPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "verify failed: sandboxRef invalid: %v\n", err)
		os.Exit(1)
	}
	if err := sandbox.Validate(sandboxProfile); err != nil {
		fmt.Fprintf(os.Stderr, "verify failed: sandboxRef invalid: %v\n", err)
		os.Exit(1)
	}
	if err := sandbox.ValidateParentEnvironment(os.Environ()); err != nil {
		fmt.Fprintf(os.Stderr, "verify failed: runtime environment invalid: %v\n", err)
		os.Exit(1)
	}

	started := time.Now().UTC()
	dependencyWarnings := []string{}
	registryDependencies := []map[string]string{}
	resolvedDependencies := make([]registry.Resolution, 0, len(cfg.Policies)+2)

	for _, policyID := range cfg.Policies {
		resolution, resolveErr := registry.ResolveEntryAt(registryPath, registryConfig, "policyPack", policyID, started)
		if resolveErr != nil {
			fmt.Fprintf(os.Stderr, "verify failed: policy registry invalid: %v\n", resolveErr)
			os.Exit(1)
		}
		if err := registry.ValidateSelectedMetadata(resolution); err != nil {
			fmt.Fprintf(os.Stderr, "verify failed: policy metadata invalid: %v\n", err)
			os.Exit(1)
		}
		resolvedDependencies = append(resolvedDependencies, resolution)
		dependencyWarnings = append(dependencyWarnings, resolution.Warnings...)
		registryDependencies = append(registryDependencies, describeRegistryDependency(resolution))
	}

	runtimeResolution, err := registry.ResolveByRefAt(registryPath, registryConfig, "runtimeProfile", runtimePath, started)
	if err != nil {
		fmt.Fprintf(os.Stderr, "verify failed: runtimeRef invalid: %v\n", err)
		os.Exit(1)
	}
	if err := registry.ValidateSelectedMetadata(runtimeResolution); err != nil {
		fmt.Fprintf(os.Stderr, "verify failed: runtime metadata invalid: %v\n", err)
		os.Exit(1)
	}
	resolvedDependencies = append(resolvedDependencies, runtimeResolution)
	dependencyWarnings = append(dependencyWarnings, runtimeResolution.Warnings...)
	registryDependencies = append(registryDependencies, describeRegistryDependency(runtimeResolution))

	sandboxResolution, err := registry.ResolveConfiguredEntryAt(repoRoot, registryPath, registryConfig, "sandboxProfile", sandboxProfile.ProfileID, cfg.SandboxRef, started)
	if err != nil {
		fmt.Fprintf(os.Stderr, "verify failed: sandboxRef invalid: %v\n", err)
		os.Exit(1)
	}
	resolvedDependencies = append(resolvedDependencies, sandboxResolution)
	dependencyWarnings = append(dependencyWarnings, sandboxResolution.Warnings...)
	registryDependencies = append(registryDependencies, describeRegistryDependency(sandboxResolution))

	pluginResolutions, pluginManifests, err := resolveVerifyPlugins(registryPath, registryConfig, cfg.Plugins, started)
	if err != nil {
		fmt.Fprintf(os.Stderr, "verify failed: plugin registry invalid: %v\n", err)
		os.Exit(1)
	}
	for _, resolution := range pluginResolutions {
		resolvedDependencies = append(resolvedDependencies, resolution)
		dependencyWarnings = append(dependencyWarnings, resolution.Warnings...)
		registryDependencies = append(registryDependencies, describeRegistryDependency(resolution))
	}

	dependencyHash, err := computeDependencyHash(registryPath, resolvedDependencies)
	if err != nil {
		fmt.Fprintf(os.Stderr, "verify failed: dependency hash invalid: %v\n", err)
		os.Exit(1)
	}

	outputRoot, err := safeOutputRoot(repoRoot, *outDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "verify failed: output root invalid: %v\n", err)
		os.Exit(1)
	}
	governedOutputPrefixes, err := prepareGovernedOutputRoots(repoRoot, outputRoot)
	if err != nil {
		fmt.Fprintf(os.Stderr, "verify failed: governed output root invalid: %v\n", err)
		os.Exit(1)
	}
	identityExcluded := combineExcludedPrefixes(governedInputExcludedPaths(), governedOutputPrefixes)

	// Compute strong references for evidence provenance before deriving the run ID.
	configHash := computeConfigHash(repoRoot)
	baselinePath := cfg.BaselinePath
	bl, baselineDigest, baselineErr := baseline.LoadWithDigest(baselinePath)
	if baselineErr != nil && (!os.IsNotExist(baselineErr) || cfg.BaselineExplicit) {
		fmt.Fprintf(os.Stderr, "verify failed: baseline could not be read: %v\n", baselineErr)
		os.Exit(1)
	}
	configHash = computeGovernedInputHash(configHash, baselinePath, baselineDigest)
	sourceTreeRecords, sourceTreeHash, err := computeSourceTreeIdentity(repoRoot, identityExcluded)
	if err != nil {
		fmt.Fprintf(os.Stderr, "verify failed: source tree identity invalid: %v\n", err)
		os.Exit(1)
	}
	runtimeInputRecords, runtimeInputsHash, err := computeRuntimeInputIdentity(repoRoot, identityExcluded)
	if err != nil {
		fmt.Fprintf(os.Stderr, "verify failed: runtime input identity invalid: %v\n", err)
		os.Exit(1)
	}
	snapshotID := gitHeadOrEmpty(repoRoot)
	runnerBinaryDigest := computeSelfBinaryHashOrEmpty()
	pluginSetHash, pluginSetEvidence, err := computePluginSetHash(pluginResolutions, pluginManifests)
	if err != nil {
		fmt.Fprintf(os.Stderr, "verify failed: plugin set identity invalid: %v\n", err)
		os.Exit(1)
	}
	environmentSpec, environmentSpecHash := computeEnvironmentSpec(cfg, sandboxProfile, pluginManifests, runnerBinaryDigest)
	environmentInputs, environmentInputsHash := computeEnvironmentInputs(pluginManifests)
	replayPlanHash := computeReplayPlanHash(
		configHash,
		sourceTreeHash,
		runtimeInputsHash,
		dependencyHash,
		pluginSetHash,
		environmentSpecHash,
		environmentInputsHash,
		runnerBinaryDigest,
		snapshotID,
	)
	inputHash := computeGovernedInputHash(
		configHash,
		sourceTreeHash,
		runtimeInputsHash,
		dependencyHash,
		pluginSetHash,
		environmentSpecHash,
		environmentInputsHash,
		runnerBinaryDigest,
		replayPlanHash,
		snapshotID,
	)

	runID := strings.TrimSpace(*runIDFlag)
	automaticRunID := runID == ""
	if automaticRunID {
		runID = deriveRunID(cfg.ProjectID, *profile, configHash, inputHash, snapshotID, dependencyHash)
	} else {
		runID = sanitizeID(runID)
	}
	if err := safePathComponent(runID); err != nil {
		fmt.Fprintf(os.Stderr, "verify failed: run id invalid: %v\n", err)
		os.Exit(1)
	}
	aliasName := ""
	if strings.TrimSpace(*alias) != "" {
		aliasName = sanitizeID(strings.TrimSpace(*alias))
		if err := safePathComponent(aliasName); err != nil {
			fmt.Fprintf(os.Stderr, "verify failed: alias invalid: %v\n", err)
			os.Exit(1)
		}
	}
	runID, runOut, err := allocateRunDirectory(outputRoot, runID, aliasName, automaticRunID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "verify failed: create a fresh run directory (choose a new run id): %v\n", err)
		os.Exit(1)
	}

	inputIdentityPath := filepath.Join(runOut, "input-identity.json")
	inputIdentityHash, err := writeInputIdentityEvidence(
		inputIdentityPath,
		buildInputIdentityEvidence(
			runID,
			snapshotID,
			inputHash,
			configHash,
			sourceTreeHash,
			runtimeInputsHash,
			dependencyHash,
			runnerBinaryDigest,
			environmentSpec,
			environmentSpecHash,
			environmentInputs,
			environmentInputsHash,
			replayPlanHash,
			sourceTreeRecords,
			runtimeInputRecords,
			identityExcluded,
			resolvedDependencies,
			pluginSetHash,
			pluginSetEvidence,
		),
	)
	if err != nil {
		deliveryFailure(runOut, fmt.Errorf("write input-identity.json: %w", err))
	}

	escapeClassification := sandbox.EscapeClassification(sandboxProfile)
	if err := writeJSON(filepath.Join(runOut, "escape-classification.json"), escapeClassification); err != nil {
		deliveryFailure(runOut, fmt.Errorf("write escape-classification.json: %w", err))
	}

	rootAnchor, _ := resolveRootAnchor(cfg)
	leafKeyID := runnerBinaryDigest
	keyHierarchyAlgorithm := "hmac-sha256"
	var keyHierarchy signing.KeyHierarchy
	if signingMode == "governed" {
		if rootAnchor == "operator-local" {
			fmt.Fprintln(os.Stderr, "governed signing requires an explicit CADENCE_ROOT_ANCHOR or cadence.yaml rootAnchor; operator-local is not allowed")
			os.Exit(1)
		}
		rootKeyID, intermediateKeyID, resolvedLeafKeyID := resolveGovernedKeyIDs(rootAnchor, leafKeyID)
		leafKeyID = resolvedLeafKeyID
		keyHierarchyAlgorithm = "ed25519"
		keyHierarchy = signing.BuildGovernedKeyHierarchy(rootAnchor, rootKeyID, intermediateKeyID, leafKeyID, keyHierarchyAlgorithm)
	} else {
		keyHierarchy = signing.BuildKeyHierarchy(rootAnchor, leafKeyID)
	}
	if err := signing.ValidateKeyHierarchy(keyHierarchy); err != nil {
		fmt.Fprintf(os.Stderr, "key hierarchy invalid: %v\n", err)
		os.Exit(1)
	}
	if err := writeJSON(filepath.Join(runOut, "key-hierarchy.json"), keyHierarchy); err != nil {
		deliveryFailure(runOut, fmt.Errorf("write key-hierarchy.json: %w", err))
	}

	sandboxRequest := sandbox.CommandRequest{
		Command: []string{os.Args[0], "scan", "--json", "--with-rule-trace"},
		WorkDir: repoRoot,
		Env: map[string]string{
			"PYTHONDONTWRITEBYTECODE": "1",
		},
	}
	sandboxExecution := sandbox.Execute(sandboxProfile, sandboxRequest)
	isolationProbe := sandbox.ExecutionIsolationProbe(sandboxExecution.Result)
	if sandboxExecution.Result.Backend == "host-local" {
		isolationProbe = sandbox.ProbeRuntimeIsolation()
		enrichSandboxResultWithIsolationProbe(&sandboxExecution.Result, isolationProbe)
	}
	if err := writeJSON(filepath.Join(runOut, "isolation-probe.json"), isolationProbe); err != nil {
		deliveryFailure(runOut, fmt.Errorf("write isolation-probe.json: %w", err))
	}
	sandboxResultForEvidence := normalizeSandboxResult(sandboxExecution.Result)
	if err := writeJSON(filepath.Join(runOut, "sandbox-result.json"), sandboxResultForEvidence); err != nil {
		deliveryFailure(runOut, fmt.Errorf("write sandbox-result.json: %w", err))
	}
	if !sandboxExecution.Result.Passed || sandboxExecution.Result.Status != "ok" {
		fmt.Fprintf(
			os.Stderr,
			"verify failed: sandbox execution failed: %s\n",
			strings.Join(sandboxExecution.Result.FailureReasons, "; "),
		)
		os.Exit(1)
	}

	var scanned struct {
		Violations    []checks.Violation `json:"violations"`
		ExecutedRules []string           `json:"executedRules"`
	}
	if err := json.Unmarshal(sandboxExecution.Stdout, &scanned); err != nil || scanned.ExecutedRules == nil {
		fmt.Fprintf(os.Stderr, "verify failed: sandbox output invalid: %v\n", err)
		os.Exit(1)
	}

	violations := scanned.Violations
	pluginResults, pluginViolations, err := executeVerifyPlugins(
		runOut,
		repoRoot,
		runID,
		inputHash,
		sourceTreeRecords,
		pluginManifests,
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "verify failed: plugin execution invalid: %v\n", err)
		os.Exit(1)
	}
	violations = append(violations, pluginViolations...)
	violations = filterGovernedOutputViolations(violations, governedOutputPrefixes)
	for _, result := range pluginResults {
		if len(result.Response.Violations) > 0 {
			dependencyWarnings = append(
				dependencyWarnings,
				fmt.Sprintf("plugin %s reported %d violations", result.PluginID, len(result.Response.Violations)),
			)
		}
	}

	// Write aggregated plugin results summary.
	agg := plugins.CollectPluginResults(pluginResults)
	if err := writeJSON(filepath.Join(runOut, "plugin-aggregation.json"), agg); err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to write plugin-aggregation.json: %v\n", err)
	}

	// Ratchet: suppress baseline fingerprints (if baseline exists).
	if baselineErr == nil {
		// Write baseline snapshot for audit trail.
		snap := baseline.SnapshotBaseline(bl, "current")
		if err := writeJSON(filepath.Join(runOut, "baseline-snapshot.json"), snap); err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to write baseline-snapshot.json: %v\n", err)
		}
		filtered := make([]checks.Violation, 0, len(violations))
		for _, v := range violations {
			if !baseline.Contains(bl, v.Fingerprint) {
				filtered = append(filtered, v)
			}
		}
		violations = filtered
	}

	sort.Slice(violations, func(i, j int) bool {
		if violations[i].Severity != violations[j].Severity {
			return violations[i].Severity < violations[j].Severity
		}
		if violations[i].RuleID != violations[j].RuleID {
			return violations[i].RuleID < violations[j].RuleID
		}
		return violations[i].File < violations[j].File
	})

	// Determine pipeline status (truth) and gate decision (exit code).
	maxSev := checks.SevP2
	for _, v := range violations {
		if v.Severity < maxSev {
			maxSev = v.Severity
		}
	}

	pipelineStatus := "ok"
	if maxSev == checks.SevP1 || len(dependencyWarnings) > 0 {
		pipelineStatus = "degraded"
	}
	if maxSev == checks.SevP0 {
		pipelineStatus = "error"
	}

	exitCode := 0
	switch strings.ToLower(strings.TrimSpace(*profile)) {
	case "ci", "full":
		if maxSev == checks.SevP0 || maxSev == checks.SevP1 {
			exitCode = 1
		}
	default: // dev
		if maxSev == checks.SevP0 {
			exitCode = 1
		}
	}

	waiverApplied := false
	breakGlassApplied := false
	waiverSource := ""
	appliedWaiverReason := ""
	appliedWaiverTicket := ""
	var appliedWaiverRecord *waiver.Record
	var appliedApprovalChain *waiver.ApprovalChain
	var appliedAuditTrail *waiver.AuditTrail
	if exitCode != 0 {
		switch {
		case *breakGlass:
			if strings.TrimSpace(*reason) == "" || strings.TrimSpace(*ticket) == "" {
				fmt.Fprintln(os.Stderr, "break-glass requires --reason and --ticket")
				os.Exit(2)
			}
			if strings.TrimSpace(*waiverApprovedBy) == "" || strings.TrimSpace(*waiverReferenceTime) == "" || strings.TrimSpace(*waiverSignature) == "" {
				fmt.Fprintln(os.Stderr, "break-glass requires --waiver-approved-by, --waiver-reference-time, and --waiver-signature")
				os.Exit(2)
			}
			if _, err := time.Parse(time.RFC3339, strings.TrimSpace(*waiverReferenceTime)); err != nil {
				fmt.Fprintln(os.Stderr, "break-glass requires RFC3339 --waiver-reference-time")
				os.Exit(2)
			}
			if strings.TrimSpace(*waiverExpiresAt) != "" {
				if _, err := time.Parse(time.RFC3339, strings.TrimSpace(*waiverExpiresAt)); err != nil {
					fmt.Fprintln(os.Stderr, "break-glass requires RFC3339 --waiver-expires-at when provided")
					os.Exit(2)
				}
			}
			if strings.TrimSpace(*waiverApprovedBy) == "cadence-verify-break-glass" {
				fmt.Fprintln(os.Stderr, "break-glass approver must be an explicit approval object, not the default local sentinel")
				os.Exit(2)
			}
			record := waiver.Record{
				Reason:        strings.TrimSpace(*reason),
				Ticket:        strings.TrimSpace(*ticket),
				Owner:         sanitizeID(cfg.ProjectID),
				ApprovedBy:    strings.TrimSpace(*waiverApprovedBy),
				CreatedAt:     strings.TrimSpace(*waiverReferenceTime),
				ExpiresAt:     strings.TrimSpace(*waiverExpiresAt),
				ReferenceTime: strings.TrimSpace(*waiverReferenceTime),
				Signature:     strings.TrimSpace(*waiverSignature),
				Scope:         "profile",
			}
			chain := waiver.BuildApprovalChain(record)
			trail := waiver.BuildAuditTrail(record, chain)
			if err := persistWaiverEvidence(runOut, record, chain, trail); err != nil {
				deliveryFailure(runOut, err)
			}
			for _, decision := range trail.Decisions {
				if decision.Status != "pass" {
					fmt.Fprintf(os.Stderr, "waiver %s warning: %s\n", decision.Check, decision.Message)
				}
			}
			if err := waiver.ValidateAuditTrail(trail); err != nil {
				fmt.Fprintf(os.Stderr, "verify failed: waiver audit-trail invalid: %v\n", err)
				os.Exit(1)
			}
			waiverApplied = true
			breakGlassApplied = true
			waiverSource = "break-glass"
			appliedWaiverReason = record.Reason
			appliedWaiverTicket = record.Ticket
			appliedWaiverRecord = &record
			appliedApprovalChain = &chain
			appliedAuditTrail = &trail
			exitCode = 0
		case strings.TrimSpace(*waiverFile) != "":
			record, chain, err := loadPersistedWaiverInputs(repoRoot, strings.TrimSpace(*waiverFile), strings.TrimSpace(*approvalChainFile), strings.TrimSpace(*ticket))
			if err != nil {
				fmt.Fprintf(os.Stderr, "verify failed: persisted waiver invalid: %v\n", err)
				os.Exit(1)
			}
			trail := waiver.BuildAuditTrail(record, chain)
			acceptanceErr := waiver.ValidatePersistedAcceptance(record, chain)
			decision := waiver.AuditDecision{Check: "persisted-policy", Status: "pass"}
			if acceptanceErr != nil {
				trail.Compliant = false
				decision.Status = "fail"
				decision.Message = acceptanceErr.Error()
			}
			trail.Decisions = append(trail.Decisions, decision)
			if err := persistWaiverEvidence(runOut, record, chain, trail); err != nil {
				deliveryFailure(runOut, err)
			}
			for _, decision := range trail.Decisions {
				if decision.Status != "pass" {
					fmt.Fprintf(os.Stderr, "waiver %s warning: %s\n", decision.Check, decision.Message)
				}
			}
			if err := waiver.ValidateAuditTrail(trail); err != nil {
				fmt.Fprintf(os.Stderr, "verify failed: waiver audit-trail invalid: %v\n", err)
				os.Exit(1)
			}
			if strings.TrimSpace(record.Scope) != "profile" {
				fmt.Fprintf(os.Stderr, "verify failed: persisted waiver scope must be profile for verify bypass, got %q\n", record.Scope)
				os.Exit(1)
			}
			if acceptanceErr != nil {
				fmt.Fprintf(os.Stderr, "verify failed: %v\n", acceptanceErr)
				os.Exit(1)
			}
			if signingMode == "governed" {
				fmt.Fprintln(os.Stderr, "verify failed: file-supplied waiver metadata is not authenticated approval; governed override requires a trusted protected approval consumer")
				os.Exit(1)
			}
			fmt.Fprintln(os.Stderr, "persisted waiver: metadata/policy checks only; approval identities are not authenticated")
			waiverApplied = true
			waiverSource = "waiver-file"
			appliedWaiverReason = record.Reason
			appliedWaiverTicket = record.Ticket
			appliedWaiverRecord = &record
			appliedApprovalChain = &chain
			appliedAuditTrail = &trail
			exitCode = 0
		}
	}

	decision := finalGateDecision(exitCode, pipelineStatus, waiverApplied)

	finished := time.Now().UTC()
	elapsedMs := float64(finished.Sub(started).Milliseconds())

	alloc := float64(60000)
	if strings.ToLower(*profile) == "full" {
		alloc = 300000
	}
	consumed := minFloat(elapsedMs, alloc)
	remaining := maxFloat(0, alloc-consumed)

	budget := evidence.Budget{
		Scope: "pipeline",
		Allocated: map[string]float64{
			"timeMs": alloc,
		},
		Consumed: map[string]float64{
			"timeMs": consumed,
		},
		Remaining: map[string]float64{
			"timeMs": remaining,
		},
		Termination: evidence.BudgetTermination{Code: "ok"},
		Children:    []evidence.Budget{},
	}

	stage := evidence.StageSummary{
		StageID: "checks",
		Status:  pipelineStatus,
		TimeMs:  elapsedMs,
		Codes:   topRuleIDs(violations, 8),
	}

	corr := &evidence.Correlation{
		RequestID: os.Getenv("CADENCE_REQUEST_ID"),
		TraceID:   os.Getenv("CADENCE_TRACE_ID"),
	}

	manifest := evidence.RunManifest{
		SchemaVersion: evidence.SchemaVersionV1,
		RunID:         runID,
		CreatedAt:     started.Format(time.RFC3339),
		AuditMeta: &evidence.AuditMeta{
			CreatedAt: started.Format(time.RFC3339),
		},
		Correlation: corr,
		Pipeline:    evidence.Pipeline{ID: "cadence.verify"},
		Algorithm: evidence.Algorithm{
			Version: "cadence-core@" + releaseVersion(),
			Build:   "release",
		},
		Contracts: map[string]string{
			"run_manifest":    "1.0.0",
			"pipeline_result": "1.0.0",
			"job_envelope":    "1.0.0",
		},
		Config: evidence.ConfigRef{
			ProfileID:  *profile,
			ConfigHash: configHash,
		},
		InputRef: evidence.InputRef{
			RawInputID: "repo://" + sanitizeID(cfg.ProjectID),
			InputHash:  inputHash,
			SnapshotID: snapshotID,
		},
		SideEffectsMode: "dryRun",
		Determinism: evidence.Determinism{
			Tier: "tier1",
			Seed: 0,
			Concurrency: map[string]any{
				"workers": 1,
			},
		},
		Budget:         budget,
		StageSummaries: []evidence.StageSummary{stage},
		Diagnostics: &evidence.Diagnostics{
			Codes: []string{"cadence.verify.completed", "cadence.profile." + strings.ToLower(*profile)},
			KV: map[string]any{
				"projectId":            cfg.ProjectID,
				"mode":                 cfg.Mode,
				"baselinePath":         baselinePath,
				"decision":             decision,
				"waived":               waiverApplied,
				"inputIdentityHash":    inputIdentityHash,
				"dependencyHash":       dependencyHash,
				"sourceTreeHash":       sourceTreeHash,
				"runtimeInputsHash":    runtimeInputsHash,
				"pluginSetHash":        pluginSetHash,
				"environmentSpecHash":  environmentSpecHash,
				"replayPlanHash":       replayPlanHash,
				"runnerBinaryDigest":   runnerBinaryDigest,
				"registryDependencies": registryDependencies,
			},
			Counters: map[string]float64{
				"violations.total": float64(len(violations)),
				"violations.p0":    float64(countSeverity(violations, checks.SevP0)),
				"violations.p1":    float64(countSeverity(violations, checks.SevP1)),
				"violations.p2":    float64(countSeverity(violations, checks.SevP2)),
			},
		},
	}
	if len(dependencyWarnings) > 0 {
		manifest.Diagnostics.Codes = append(manifest.Diagnostics.Codes, "cadence.registry.warning")
	}

	manifest.AuditMeta.FinishedAt = finished.Format(time.RFC3339)

	manifestPath := filepath.Join(runOut, "run-manifest.json")
	manifestHash, err := evidence.WriteCanonicalJSON(manifestPath, buildPrimaryRunManifest(manifest))
	if err != nil {
		deliveryFailure(runOut, fmt.Errorf("write run-manifest.json: %w", err))
	}

	vs := make([]map[string]any, 0, len(violations))
	for _, v := range violations {
		vs = append(vs, map[string]any{
			"ruleId":      v.RuleID,
			"severity":    string(v.Severity),
			"message":     v.Message,
			"file":        v.File,
			"line":        v.Line,
			"fingerprint": v.Fingerprint,
		})
	}

	var errEnv *evidence.ErrorEnvelope
	if pipelineStatus == "error" {
		errEnv = &evidence.ErrorEnvelope{
			Code:      "cadence.verify.failed",
			Kind:      "invalidArgument",
			Message:   "verify found P0 violations",
			Retryable: false,
			Details: map[string]any{
				"decision": decision,
			},
			Correlation: corr,
		}
	}

	result := evidence.PipelineResult{
		SchemaVersion: evidence.SchemaVersionV1,
		RunID:         runID,
		Pipeline:      evidence.Pipeline{ID: "cadence.verify"},
		Status:        pipelineStatus,
		Output: map[string]any{
			"decision":             decision,
			"reportRef":            "cadence-report.json",
			"summaryRef":           "summary.md",
			"inputIdentityRef":     "input-identity.json",
			"violations":           vs,
			"breakGlass":           breakGlassApplied,
			"waiverApplied":        waiverApplied,
			"waiverSource":         waiverSource,
			"breakReason":          appliedWaiverReason,
			"breakTicket":          appliedWaiverTicket,
			"baselineUsed":         len(bl.Fingerprints) > 0,
			"dependencyHash":       dependencyHash,
			"sourceTreeHash":       sourceTreeHash,
			"runtimeInputsHash":    runtimeInputsHash,
			"pluginSetHash":        pluginSetHash,
			"environmentSpecHash":  environmentSpecHash,
			"replayPlanHash":       replayPlanHash,
			"runnerBinaryDigest":   runnerBinaryDigest,
			"registryDependencies": registryDependencies,
			"pluginResultsRef":     "plugin-results-summary.json",
		},
		Warnings:       append([]string{}, dependencyWarnings...),
		StageSummaries: []evidence.StageSummary{stage},
		Budget:         budget,
		Diagnostics: &evidence.Diagnostics{
			Codes: []string{"cadence.pipeline.completed"},
			KV: map[string]any{
				"pluginSetHash":       pluginSetHash,
				"environmentSpecHash": environmentSpecHash,
				"replayPlanHash":      replayPlanHash,
			},
		},
		ManifestRef: evidence.ManifestRef{RunID: runID, ManifestHash: manifestHash},
		Error:       errEnv,
	}

	resultPath := filepath.Join(runOut, "pipeline-result.json")
	resultHash, err := evidence.WriteCanonicalJSON(resultPath, buildPrimaryPipelineResult(result))
	if err != nil {
		deliveryFailure(runOut, fmt.Errorf("write pipeline-result.json: %w", err))
	}

	jobStatus := "succeeded"
	if pipelineStatus == "degraded" {
		jobStatus = "degraded"
	}
	if pipelineStatus == "error" && !waiverApplied {
		jobStatus = "failed"
	}

	job := evidence.JobEnvelope{
		SchemaVersion:   evidence.SchemaVersionV1,
		JobID:           "job_" + sanitizeID(cfg.ProjectID),
		JobType:         "cadence.verify",
		Status:          jobStatus,
		CreatedAt:       started.Format(time.RFC3339),
		UpdatedAt:       finished.Format(time.RFC3339),
		StartedAt:       started.Format(time.RFC3339),
		FinishedAt:      finished.Format(time.RFC3339),
		Correlation:     corr,
		ProfileID:       *profile,
		ConfigHash:      configHash,
		SideEffectsMode: "dryRun",
		InputRef:        &manifest.InputRef,
		Runs: []evidence.JobRun{
			{
				Attempt:     1,
				StartedAt:   started.Format(time.RFC3339),
				FinishedAt:  finished.Format(time.RFC3339),
				ManifestRef: evidence.ManifestRef{RunID: runID, ManifestHash: manifestHash},
				Result:      result,
			},
		},
		Diagnostics: &evidence.Diagnostics{
			Codes: []string{"cadence.job.completed"},
			KV: map[string]any{
				"decision":            decision,
				"inputIdentityHash":   inputIdentityHash,
				"dependencyHash":      dependencyHash,
				"pluginSetHash":       pluginSetHash,
				"environmentSpecHash": environmentSpecHash,
				"replayPlanHash":      replayPlanHash,
			},
		},
	}

	jobPath := filepath.Join(runOut, "job-envelope.json")
	jobHash, err := evidence.WriteCanonicalJSON(jobPath, buildPrimaryJobEnvelope(job))
	if err != nil {
		deliveryFailure(runOut, fmt.Errorf("write job-envelope.json: %w", err))
	}

	canonicalProtocolHashes, err := writeCanonicalProtocolArtifacts(runOut, manifest, result, job)
	if err != nil {
		deliveryFailure(runOut, fmt.Errorf("write canonical protocol artifacts: %w", err))
	}

	auditTelemetryPath := filepath.Join(runOut, "audit-telemetry.json")
	auditTelemetryHash, err := evidence.WriteCanonicalJSON(auditTelemetryPath, buildAuditTelemetry(manifest, result, job, elapsedMs))
	if err != nil {
		deliveryFailure(runOut, fmt.Errorf("write audit-telemetry.json: %w", err))
	}

	deterministicPath := filepath.Join(runOut, "deterministic-evidence.json")
	deterministicHash, err := writeDeterministicEvidence(
		deterministicPath,
		manifest,
		result,
		job,
		decision,
		jobStatus,
		dependencyHash,
		sourceTreeHash,
		runtimeInputsHash,
		pluginSetHash,
		environmentSpecHash,
		replayPlanHash,
		runnerBinaryDigest,
		sandboxResultForEvidence,
		isolationProbe,
		pluginResults,
	)
	if err != nil {
		deliveryFailure(runOut, fmt.Errorf("write deterministic-evidence.json: %w", err))
	}

	// Optional offline attestation for strict-offline execution.
	if strings.ToLower(cfg.Mode) == "strict_offline" {
		att := map[string]any{
			"schemaVersion": "1.0.0",
			"runId":         runID,
			"mode":          "strict_offline",
			"egressPolicy":  "deny",
			"createdAt":     finished.Format(time.RFC3339),
			"claims": []string{
				"cadence-core verify does not perform network I/O in strict_offline mode",
			},
			"toolchainHash": computeSelfBinaryHashOrEmpty(),
		}
		if err := writeJSON(filepath.Join(runOut, "offline-attestation.json"), att); err != nil {
			deliveryFailure(runOut, err)
		}
	}

	if waiverApplied && appliedWaiverRecord != nil && appliedApprovalChain != nil && appliedAuditTrail != nil {
		if err := persistWaiverEvidence(runOut, *appliedWaiverRecord, *appliedApprovalChain, *appliedAuditTrail); err != nil {
			deliveryFailure(runOut, err)
		}
	}

	// Human-friendly summary + machine report.
	summary := map[string]any{
		"decision":       decision,
		"status":         pipelineStatus,
		"jobStatus":      jobStatus,
		"runId":          runID,
		"projectId":      cfg.ProjectID,
		"profile":        *profile,
		"violations":     len(violations),
		"break_glass":    breakGlassApplied,
		"waiver_applied": waiverApplied,
		"waiver_source":  waiverSource,
		"baselinePath":   baselinePath,
		"baselineDigest": baselineDigest,
		"inputIdentity":  "input-identity.json",
		"dependencyHash": dependencyHash,
		"warnings":       dependencyWarnings,
	}
	b, _ := json.MarshalIndent(summary, "", "  ")
	if err := os.WriteFile(filepath.Join(runOut, "summary.json"), b, 0o644); err != nil {
		deliveryFailure(runOut, err)
	}
	if err := os.WriteFile(filepath.Join(runOut, "summary.md"), []byte(renderMarkdownSummary(summary, violations)), 0o644); err != nil {
		deliveryFailure(runOut, err)
	}
	if err := writeJSON(filepath.Join(runOut, "cadence-report.json"), map[string]any{"runId": runID, "decision": decision, "status": pipelineStatus, "violations": vs}); err != nil {
		deliveryFailure(runOut, err)
	}

	if *validateProtocol {
		var primaryManifest evidence.RunManifest
		if err := json.Unmarshal(mustReadFile(manifestPath), &primaryManifest); err != nil {
			fmt.Fprintf(os.Stderr, "protocol validate failed (run-manifest decode): %v\n", err)
			os.Exit(2)
		}
		if err := evidence.ValidateRunManifest(primaryManifest); err != nil {
			fmt.Fprintf(os.Stderr, "protocol validate failed (run-manifest): %v\n", err)
			os.Exit(2)
		}
		var primaryResult evidence.PipelineResult
		if err := json.Unmarshal(mustReadFile(resultPath), &primaryResult); err != nil {
			fmt.Fprintf(os.Stderr, "protocol validate failed (pipeline-result decode): %v\n", err)
			os.Exit(2)
		}
		if err := evidence.ValidatePipelineResult(primaryResult); err != nil {
			fmt.Fprintf(os.Stderr, "protocol validate failed (pipeline-result): %v\n", err)
			os.Exit(2)
		}
		var primaryJob evidence.JobEnvelope
		if err := json.Unmarshal(mustReadFile(jobPath), &primaryJob); err != nil {
			fmt.Fprintf(os.Stderr, "protocol validate failed (job-envelope decode): %v\n", err)
			os.Exit(2)
		}
		if err := evidence.ValidateJobEnvelope(primaryJob); err != nil {
			fmt.Fprintf(os.Stderr, "protocol validate failed (job-envelope): %v\n", err)
			os.Exit(2)
		}
	}

	// Build step hash chain linking the evidence artifacts.
	chain := signing.NewChain()
	chain.Append("checks", inputHash, signing.HashPayload([]byte(configHash)))
	chain.Append("dependencies", inputHash, signing.HashPayload([]byte(dependencyHash)))
	chain.Append("manifest", manifestHash, signing.HashPayload(mustReadFile(manifestPath)))
	chain.Append("run-manifest-canonical", manifestHash, canonicalProtocolHashes["run-manifest.canonical.json"])
	chain.Append("pipeline-result", manifestHash, resultHash)
	chain.Append("pipeline-result-canonical", resultHash, canonicalProtocolHashes["pipeline-result.canonical.json"])
	chain.Append("job-envelope", manifestHash, jobHash)
	chain.Append("job-envelope-canonical", jobHash, canonicalProtocolHashes["job-envelope.canonical.json"])
	chain.Append("input-identity", inputIdentityHash, signing.HashPayload(mustReadFile(inputIdentityPath)))
	chain.Append("audit-telemetry", auditTelemetryHash, signing.HashPayload(mustReadFile(auditTelemetryPath)))
	chain.Append("deterministic-evidence", deterministicHash, signing.HashPayload(mustReadFile(deterministicPath)))
	chainJSON, _ := json.MarshalIndent(chain, "", "  ")
	if err := os.WriteFile(filepath.Join(runOut, "step-hash-chain.json"), chainJSON, 0o644); err != nil {
		deliveryFailure(runOut, err)
	}

	// Generate structured report.
	var reportFindings []report.Finding
	for _, v := range violations {
		reportFindings = append(reportFindings, report.Finding{
			RuleID:   v.RuleID,
			Severity: string(v.Severity),
			Message:  v.Message,
			FilePath: v.File,
		})
	}
	verifyReport := report.Generate(runID, cfg.ProjectID, reportFindings)
	verifyReport.Summary = report.NewSummary(decision, len(reportFindings))
	durationMs := time.Since(started).Milliseconds()
	verifyReport = report.WithMetrics(verifyReport, len(sourceTreeRecords), len(scanned.ExecutedRules), int(durationMs))
	if err := report.Save(filepath.Join(runOut, "report-summary.json"), verifyReport); err != nil {
		deliveryFailure(runOut, err)
	}
	if err := evidence.ValidateRunFiles(runOut); err != nil {
		deliveryFailure(runOut, err)
	}
	for name, value := range map[string]string{"RUN_ID": runID + "\n", "RUN_PATH": runOut + "\n"} {
		if err := os.WriteFile(filepath.Join(runOut, name), []byte(value), 0o644); err != nil {
			deliveryFailure(runOut, err)
		}
	}
	sigKey := []byte(os.Getenv("CADENCE_SIGNING_KEY"))
	var signer signing.Signer
	if len(sigKey) > 0 || signingMode == "governed" {
		signer, err = signing.SelectSigner(leafKeyID, "cadence-core", sigKey)
		if err != nil {
			deliveryFailure(runOut, err)
		}
		anchor, present, err := signing.VerifiedSoftwareAnchor(signer, mustReadFile(filepath.Join(runOut, "key-hierarchy.json")))
		if err != nil {
			deliveryFailure(runOut, err)
		}
		if present {
			if err = writeJSON(filepath.Join(runOut, "hsm-anchor.json"), anchor); err != nil {
				deliveryFailure(runOut, err)
			}
		}
	}

	// Build and verify the evidence bundle.
	evidenceBundle, bundleErr := evidence.BuildEvidenceBundle(runOut, "run-manifest.json", "pipeline-result.json")
	if bundleErr != nil {
		deliveryFailure(runOut, bundleErr)
	}
	if bundleErr == nil {
		if err := writeJSON(filepath.Join(runOut, "evidence-bundle.json"), evidenceBundle); err != nil {
			deliveryFailure(runOut, err)
		}
		if err := evidence.VerifyBundleIntegrity(*evidenceBundle, runOut); err != nil {
			deliveryFailure(runOut, err)
		}
	}

	// Build the canonical replay package after the primary report artifacts are
	// finalized so reused run directories do not snapshot stale intermediate
	// files from a previous invocation.
	replayBundle, replayErr := replay.Build(runID, "run-manifest.json", "pipeline-result.json", runOut)
	if replayErr != nil {
		deliveryFailure(runOut, replayErr)
	}
	if err := replay.Save(filepath.Join(runOut, "replay-package.json"), replayBundle); err != nil {
		deliveryFailure(runOut, err)
	}
	if err := replay.Save(filepath.Join(runOut, "replay-bundle.json"), replayBundle); err != nil {
		deliveryFailure(runOut, err)
	}

	// Sign the evidence bundle if a signing key is available, or if governed
	// mode is explicitly requested. Governed mode is fail-closed.
	if signer != nil {
		if err := writeDetachedSignatures(runOut, runID, signer, sigKey); err != nil {
			deliveryFailure(runOut, fmt.Errorf("sign evidence bundle: %w", err))
		}
	}

	if err := evidence.ValidateDeliveryFiles(runOut); err != nil {
		deliveryFailure(runOut, err)
	}

	// Update a stable alias directory (default: .cadence/out/latest) after all
	// evidence artifacts exist so automation can rely on the alias as a complete
	// evidence set.
	if aliasName != "" && exitCode == 0 {
		if err := writeStableAlias(outputRoot, filepath.Join(outputRoot, aliasName), runOut, runID); err != nil {
			deliveryFailure(runOut, fmt.Errorf("update alias %q: %w", aliasName, err))
		}
	}

	fmt.Printf("verify: %s (decision=%s)\nEvidence written to %s\n", pipelineStatus, decision, runOut)
	if strings.TrimSpace(*alias) != "" && exitCode == 0 {
		fmt.Printf("Alias updated: %s\n", filepath.Join(*outDir, strings.TrimSpace(*alias)))
	}
	os.Exit(exitCode)
}

func mustReadFile(path string) []byte {
	data, err := os.ReadFile(path)
	if err != nil {
		deliveryFailure(filepath.Dir(path), fmt.Errorf("read required file %s: %w", filepath.Base(path), err))
	}
	return data
}

func writeStableAlias(outputRoot string, aliasDir string, runOut string, runID string) error {
	if !pathWithin(outputRoot, aliasDir) || !pathWithin(outputRoot, runOut) || filepath.Clean(aliasDir) == filepath.Clean(runOut) {
		return fmt.Errorf("alias and distinct run must remain in output root")
	}
	if err := evidence.ValidateDeliveryFiles(runOut); err != nil {
		return err
	}
	if info, err := os.Lstat(aliasDir); err == nil && info.IsDir() {
		return fmt.Errorf("legacy alias is a directory; with writers stopped, move it to a retained backup before enabling the atomic symlink alias")
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}
	target, err := filepath.Rel(filepath.Dir(aliasDir), runOut)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(aliasDir), ".cadence-alias-")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if err = tmp.Close(); err != nil {
		os.Remove(name)
		return err
	}
	defer os.Remove(name)
	if err = os.Remove(name); err != nil {
		return err
	}
	if err = os.Symlink(target, name); err != nil {
		return err
	}
	return os.Rename(name, aliasDir)
}

// Preserve scan outcome while explicitly recording a failed delivery.
func deliveryFailure(runOut string, failure error) {
	_ = writeJSON(filepath.Join(runOut, "delivery-error.json"), map[string]any{"deliveryComplete": false, "error": failure.Error()})
	for _, name := range []string{"summary.json", "cadence-report.json", "report-summary.json"} {
		path := filepath.Join(runOut, name)
		if data, err := os.ReadFile(path); err == nil {
			var summary map[string]any
			if json.Unmarshal(data, &summary) == nil && summary != nil {
				summary["deliveryComplete"] = false
				summary["deliveryError"] = failure.Error()
				if observed, ok := summary["decision"]; ok {
					summary["scanDecision"] = observed
					summary["decision"] = "fail"
				}
				if nested, ok := summary["summary"].(map[string]any); ok {
					summary["scanDecision"] = nested["status"]
					nested["status"] = "fail"
				}
				_ = writeJSON(path, summary)
			}
		}
	}
	fmt.Fprintf(os.Stderr, "verify failed: evidence delivery incomplete: %v\n", failure)
	os.Exit(1)
}

func copyFile(src string, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer func() { _ = out.Close() }()
	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Sync()
}

func writeDetachedSignatures(runOut string, runID string, signer signing.Signer, legacyHMACKey []byte) error {
	signable := []string{
		"run-manifest.json",
		"pipeline-result.json",
		"job-envelope.json",
		"input-identity.json",
		"isolation-probe.json",
		"key-hierarchy.json",
		"hsm-anchor.json",
		"audit-telemetry.json",
		"deterministic-evidence.json",
		"sandbox-result.json",
		"plugin-results-summary.json",
		"replay-package.json",
		"approval-chain.json",
		"waiver-audit-trail.json",
		"evidence-bundle.json",
	}
	if signer.Algorithm() == "hmac-sha256" {
		return writeLegacyDetachedSignatures(runOut, runID, legacyHMACKey)
	}
	entries := map[string]string{}
	var manifestPayload []byte
	for _, name := range signable {
		path := filepath.Join(runOut, name)
		if _, err := os.Stat(path); err != nil {
			continue
		}
		payload := mustReadFile(path)
		if name == "run-manifest.json" {
			manifestPayload = payload
		}
		detached, err := signing.NewDetachedSignature(runID+"/"+name, signer, name, payload)
		if err != nil {
			return err
		}
		if err := signing.VerifyDetachedSignature(detached, signer, payload); err != nil {
			return err
		}
		entries[name] = detached.PayloadHash
		payloadEnvelope := map[string]any{
			"schemaVersion": detached.SchemaVersion,
			"signatureId":   detached.SignatureID,
			"algorithm":     detached.Algorithm,
			"signer":        detached.Issuer,
			"keyId":         detached.KeyID,
			"issuer":        detached.Issuer,
			"payloadRole":   name,
			"payloadRef":    detached.PayloadRef,
			"payloadHash":   detached.PayloadHash,
			"signature":     detached.Signature,
		}
		if err := writeJSON(filepath.Join(runOut, name+".signature.json"), payloadEnvelope); err != nil {
			return err
		}
		if name == "run-manifest.json" {
			if err := writeJSON(filepath.Join(runOut, "manifest-signature.json"), payloadEnvelope); err != nil {
				return err
			}
		}
	}
	if len(entries) == 0 {
		return nil
	}
	if len(manifestPayload) == 0 {
		return fmt.Errorf("missing run-manifest.json for governed bundle signature")
	}
	dualSignature, err := signing.NewDualLayerSignature(runID+"/bundle", signer, manifestPayload, entries)
	if err != nil {
		return err
	}
	bundlePayload := map[string]any{
		"schemaVersion": dualSignature.SchemaVersion,
		"signatureId":   runID + "/bundle",
		"algorithm":     signer.Algorithm(),
		"signer":        signer.Issuer(),
		"keyId":         signer.KeyID(),
		"issuer":        signer.Issuer(),
		"bundleHash":    dualSignature.BundleLayer.PayloadHash,
		"entries":       entries,
		"signature":     dualSignature.BundleLayer.Signature,
		"manifestLayer": dualSignature.ManifestLayer,
		"bundleLayer":   dualSignature.BundleLayer,
		"dualHash":      dualSignature.DualHash,
		"dualSignature": dualSignature.DualSignature,
	}
	return writeJSON(filepath.Join(runOut, "bundle-signature.json"), bundlePayload)
}

func writeLegacyDetachedSignatures(runOut string, runID string, key []byte) error {
	signable := []string{
		"run-manifest.json",
		"pipeline-result.json",
		"job-envelope.json",
		"input-identity.json",
		"isolation-probe.json",
		"key-hierarchy.json",
		"hsm-anchor.json",
		"audit-telemetry.json",
		"deterministic-evidence.json",
		"sandbox-result.json",
		"plugin-results-summary.json",
		"replay-package.json",
		"approval-chain.json",
		"waiver-audit-trail.json",
		"evidence-bundle.json",
	}
	entries := map[string]string{}
	for _, name := range signable {
		path := filepath.Join(runOut, name)
		if _, err := os.Stat(path); err != nil {
			continue
		}
		payload := mustReadFile(path)
		hash := signing.HashPayload(payload)
		entries[name] = hash
		envelope := signing.NewEnvelopeForHash(runID+"/"+name, "cadence-core", name, hash, key)
		if err := signing.Save(filepath.Join(runOut, name+".signature.json"), envelope); err != nil {
			return err
		}
		if name == "run-manifest.json" {
			if err := signing.Save(filepath.Join(runOut, "manifest-signature.json"), envelope); err != nil {
				return err
			}
		}
	}
	if len(entries) == 0 {
		return nil
	}
	return signing.SaveBundle(filepath.Join(runOut, "bundle-signature.json"), signing.NewBundleSignature(runID+"/bundle", "cadence-core", entries, key))
}

func sanitizeID(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "unknown"
	}
	var out []rune
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
			out = append(out, r)
		case r >= 'A' && r <= 'Z':
			out = append(out, r)
		case r >= '0' && r <= '9':
			out = append(out, r)
		case r == '-' || r == '_':
			out = append(out, r)
		default:
			out = append(out, '_')
		}
	}
	return string(out)
}

func safePathComponent(value string) error {
	if value == "" || value == "." || value == ".." || filepath.Base(value) != value {
		return fmt.Errorf("must be one non-dot path component")
	}
	return nil
}

func pathWithin(root string, target string) bool {
	rel, err := filepath.Rel(filepath.Clean(root), filepath.Clean(target))
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) && !filepath.IsAbs(rel)
}

// safeOutputRoot limits mutable evidence to the checked repository.  This keeps
// --out, --run-id and --alias from turning a verification command into a file
// deletion primitive outside the project tree.
func safeOutputRoot(repoRoot string, outDir string) (string, error) {
	root, err := filepath.EvalSymlinks(repoRoot)
	if err != nil {
		return "", err
	}
	root, err = filepath.Abs(root)
	if err != nil {
		return "", err
	}
	output := outDir
	if !filepath.IsAbs(output) {
		output = filepath.Join(root, output)
	}
	output, err = filepath.Abs(output)
	if err != nil {
		return "", err
	}
	if !pathWithin(root, output) || filepath.Clean(output) == filepath.Clean(root) {
		return "", fmt.Errorf("--out must be a descendant of the repository root")
	}
	rel, err := filepath.Rel(root, output)
	if err != nil {
		return "", err
	}
	cursor := root
	for _, part := range strings.Split(rel, string(os.PathSeparator)) {
		cursor = filepath.Join(cursor, part)
		info, statErr := os.Lstat(cursor)
		if os.IsNotExist(statErr) {
			break
		}
		if statErr != nil {
			return "", statErr
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("--out must not traverse symbolic links")
		}
	}
	return output, nil
}

func computeConfigHash(repoRoot string) string {
	var parts [][]byte
	for _, p := range []string{"cadence.yaml", "cadence.yml", "tooling_lock.json", "cadence.lock"} {
		b, err := os.ReadFile(filepath.Join(repoRoot, p))
		if err == nil && len(b) > 0 {
			parts = append(parts, []byte("== "+p+" ==\n"))
			parts = append(parts, b)
			parts = append(parts, []byte("\n"))
		}
	}
	joined := bytesJoin(parts)
	return evidence.Sha256Prefixed(joined)
}

func bytesJoin(chunks [][]byte) []byte {
	total := 0
	for _, c := range chunks {
		total += len(c)
	}
	out := make([]byte, 0, total)
	for _, c := range chunks {
		out = append(out, c...)
	}
	return out
}

type inputIdentityRecord struct {
	Path string `json:"path"`
	Mode string `json:"mode"`
	Size int    `json:"size"`
	Sum  string `json:"sha256"`
}

type identityDigestRecord struct {
	Kind   string `json:"kind"`
	ID     string `json:"id"`
	Digest string `json:"digest"`
	Ref    string `json:"ref,omitempty"`
}

type executionEnvRecord struct {
	Key       string `json:"key"`
	Present   bool   `json:"present"`
	ValueHash string `json:"valueHash,omitempty"`
}

func computeSourceTreeIdentity(repoRoot string, excludedPrefixes []string) ([]inputIdentityRecord, string, error) {
	var files []inputIdentityRecord
	if err := checks.WalkFilesDetailed(repoRoot, func(record checks.FileRecord) error {
		if shouldExcludeIdentityPath(record.RelPath, excludedPrefixes) {
			return nil
		}
		sum := sha256.Sum256(record.Bytes)
		files = append(files, inputIdentityRecord{
			Path: record.RelPath,
			Mode: fmt.Sprintf("%#o", record.Mode),
			Size: len(record.Bytes),
			Sum:  "sha256:" + hex.EncodeToString(sum[:]),
		})
		return nil
	}); err != nil {
		return nil, "", err
	}
	return hashIdentityRecords(files)
}

func computeRuntimeInputIdentity(repoRoot string, excludedPrefixes []string) ([]inputIdentityRecord, string, error) {
	var files []inputIdentityRecord
	if err := checks.WalkIdentityFilesDetailed(repoRoot, func(record checks.FileRecord) error {
		if shouldExcludeIdentityPath(record.RelPath, excludedPrefixes) {
			return nil
		}
		sum := sha256.Sum256(record.Bytes)
		files = append(files, inputIdentityRecord{
			Path: record.RelPath,
			Mode: fmt.Sprintf("%#o", record.Mode),
			Size: len(record.Bytes),
			Sum:  "sha256:" + hex.EncodeToString(sum[:]),
		})
		return nil
	}); err != nil {
		return nil, "", err
	}
	return hashIdentityRecords(files)
}

func hashIdentityRecords(files []inputIdentityRecord) ([]inputIdentityRecord, string, error) {
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	h := sha256.New()
	for _, f := range files {
		h.Write([]byte(f.Path))
		h.Write([]byte{0})
		h.Write([]byte(f.Mode))
		h.Write([]byte{0})
		h.Write([]byte(fmt.Sprintf("%d", f.Size)))
		h.Write([]byte{0})
		h.Write([]byte(f.Sum))
		h.Write([]byte{'\n'})
	}
	return files, "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

func buildInputIdentityEvidence(
	runID string,
	snapshotID string,
	inputHash string,
	configHash string,
	sourceTreeHash string,
	runtimeInputsHash string,
	dependencyHash string,
	runnerBinaryDigest string,
	environmentSpec map[string]any,
	environmentSpecHash string,
	environmentInputs []executionEnvRecord,
	environmentInputsHash string,
	replayPlanHash string,
	sourceTreeFiles []inputIdentityRecord,
	runtimeInputFiles []inputIdentityRecord,
	runtimeInputExcluded []string,
	resolvedDependencies []registry.Resolution,
	pluginSetHash string,
	pluginSetEvidence []map[string]any,
) map[string]any {
	return map[string]any{
		"schemaVersion":         "1.0.0",
		"runId":                 runID,
		"inputHash":             inputHash,
		"snapshotId":            snapshotID,
		"configHash":            configHash,
		"sourceTreeHash":        sourceTreeHash,
		"runtimeInputsHash":     runtimeInputsHash,
		"dependencyHash":        dependencyHash,
		"runnerBinaryDigest":    runnerBinaryDigest,
		"environmentSpec":       environmentSpec,
		"environmentSpecHash":   environmentSpecHash,
		"environmentInputs":     environmentInputs,
		"environmentInputsHash": environmentInputsHash,
		"replayPlanHash":        replayPlanHash,
		"sourceTreeFiles":       sourceTreeFiles,
		"runtimeInputFiles":     runtimeInputFiles,
		"sourceTreeExcluded":    combineExcludedPrefixes([]string{".git", "node_modules", "dist", "build", ".cadence"}, runtimeInputExcluded),
		"runtimeInputExcluded":  runtimeInputExcluded,
		"dependencyDigests":     describeDependencyDigests(resolvedDependencies),
		"pluginSetHash":         pluginSetHash,
		"pluginSet":             pluginSetEvidence,
	}
}

func writeInputIdentityEvidence(path string, payload map[string]any) (string, error) {
	return evidence.WriteCanonicalJSON(path, payload)
}

func computeDependencyHash(registryPath string, dependencies []registry.Resolution) (string, error) {
	type dependencyRecord struct {
		Kind         string
		ID           string
		ResolvedRef  string
		Digest       string
		Version      string
		Status       string
		CompatWindow string
		DeprecatedAt string
		TrustSigner  string
		Allowlisted  bool
	}

	registryDigest, err := fileSHA256(registryPath)
	if err != nil {
		return "", err
	}

	records := make([]dependencyRecord, 0, len(dependencies))
	for _, dependency := range dependencies {
		digest, hashErr := fileSHA256(dependency.ResolvedRef)
		if hashErr != nil {
			return "", hashErr
		}
		records = append(records, dependencyRecord{
			Kind:         dependency.Entry.Kind,
			ID:           dependency.Entry.ID,
			ResolvedRef:  dependency.ResolvedRef,
			Digest:       digest,
			Version:      dependency.Entry.Version,
			Status:       dependency.Entry.Status,
			CompatWindow: dependency.Entry.CompatWindow,
			DeprecatedAt: valueOrEmpty(dependency.Entry.DeprecatedAt),
			Allowlisted:  dependency.Entry.Trust != nil && dependency.Entry.Trust.Allowlisted,
		})
		if dependency.Entry.Trust != nil {
			records[len(records)-1].TrustSigner = dependency.Entry.Trust.Signer
		}
	}
	sort.Slice(records, func(i, j int) bool {
		if records[i].Kind != records[j].Kind {
			return records[i].Kind < records[j].Kind
		}
		if records[i].ID != records[j].ID {
			return records[i].ID < records[j].ID
		}
		return records[i].ResolvedRef < records[j].ResolvedRef
	})

	h := sha256.New()
	h.Write([]byte("registry"))
	h.Write([]byte{0})
	h.Write([]byte(filepath.Clean(registryPath)))
	h.Write([]byte{0})
	h.Write([]byte(registryDigest))
	h.Write([]byte{'\n'})
	for _, record := range records {
		h.Write([]byte(record.Kind))
		h.Write([]byte{0})
		h.Write([]byte(record.ID))
		h.Write([]byte{0})
		h.Write([]byte(record.ResolvedRef))
		h.Write([]byte{0})
		h.Write([]byte(record.Digest))
		h.Write([]byte{0})
		h.Write([]byte(record.Version))
		h.Write([]byte{0})
		h.Write([]byte(record.Status))
		h.Write([]byte{0})
		h.Write([]byte(record.CompatWindow))
		h.Write([]byte{0})
		h.Write([]byte(record.DeprecatedAt))
		h.Write([]byte{0})
		h.Write([]byte(record.TrustSigner))
		h.Write([]byte{0})
		if record.Allowlisted {
			h.Write([]byte("allowlisted"))
		} else {
			h.Write([]byte("not-allowlisted"))
		}
		h.Write([]byte{'\n'})
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

func describeDependencyDigests(dependencies []registry.Resolution) []identityDigestRecord {
	out := make([]identityDigestRecord, 0, len(dependencies))
	for _, dependency := range dependencies {
		digest := dependency.Entry.Digest
		if digest == "" {
			if computed, err := fileSHA256(dependency.ResolvedRef); err == nil {
				digest = computed
			}
		}
		out = append(out, identityDigestRecord{
			Kind:   dependency.Entry.Kind,
			ID:     dependency.Entry.ID,
			Digest: digest,
			Ref:    dependency.ResolvedRef,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func resolveVerifyPlugins(registryPath string, reg registry.Registry, requestedIDs []string, referenceTime time.Time) ([]registry.Resolution, []plugins.Manifest, error) {
	// Registry membership is discovery metadata, not a blanket execution
	// grant.  This keeps public verification usable while plugin execution is
	// fail-closed pending an enforcing isolated plugin runner.
	pluginIDs := append([]string{}, requestedIDs...)
	sort.Strings(pluginIDs)
	resolutions := make([]registry.Resolution, 0, len(pluginIDs))
	manifests := make([]plugins.Manifest, 0, len(pluginIDs))
	for _, pluginID := range pluginIDs {
		resolution, err := registry.ResolveEntryAt(registryPath, reg, "plugin", pluginID, referenceTime)
		if err != nil {
			return nil, nil, err
		}
		manifest, err := plugins.Load(resolution.ResolvedRef)
		if err != nil {
			return nil, nil, fmt.Errorf("plugin %s manifest invalid: %w", pluginID, err)
		}
		resolutions = append(resolutions, resolution)
		manifests = append(manifests, manifest)
	}
	return resolutions, manifests, nil
}

func computePluginSetHash(resolutions []registry.Resolution, manifests []plugins.Manifest) (string, []map[string]any, error) {
	h := sha256.New()
	records := make([]map[string]any, 0, len(manifests))
	for i, manifest := range manifests {
		resolvedCommand, err := plugins.ResolvedCommand(manifest)
		if err != nil {
			return "", nil, err
		}
		payload := map[string]any{
			"pluginId":        manifest.PluginID,
			"manifestRef":     resolutions[i].ResolvedRef,
			"version":         manifest.Version,
			"protocol":        manifest.Protocol,
			"runtime":         manifest.Runtime,
			"entryPoint":      manifest.EntryPoint,
			"resolvedCommand": resolvedCommand,
			"timeoutMs":       manifest.TimeoutMs,
			"envAllowlist":    manifest.EnvAllowlist,
			"capabilities":    manifest.Capabilities,
			"compatWindow": map[string]any{
				"minProtocol": manifest.CompatWindow.MinProtocol,
				"maxProtocol": manifest.CompatWindow.MaxProtocol,
			},
		}
		data, err := json.Marshal(payload)
		if err != nil {
			return "", nil, err
		}
		h.Write(data)
		h.Write([]byte{'\n'})
		records = append(records, payload)
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), records, nil
}

func resolveRootAnchor(cfg config.Config) (string, string) {
	if value := strings.TrimSpace(os.Getenv("CADENCE_ROOT_ANCHOR")); value != "" {
		return value, "env:CADENCE_ROOT_ANCHOR"
	}
	if value := strings.TrimSpace(cfg.RootAnchor); value != "" {
		return value, "cadence.yaml#rootAnchor"
	}
	return "operator-local", "default:operator-local"
}

func currentSigningMode() string {
	mode := strings.ToLower(strings.TrimSpace(os.Getenv("CADENCE_SIGNING_MODE")))
	if mode == "" {
		return "dev"
	}
	return mode
}

func resolveGovernedKeyIDs(rootAnchor string, defaultLeafKeyID string) (string, string, string) {
	rootKeyID := strings.TrimSpace(os.Getenv("CADENCE_GOVERNED_ROOT_KEY_ID"))
	if rootKeyID == "" {
		rootKeyID = "root-" + shortStableID(rootAnchor)
	}
	intermediateKeyID := strings.TrimSpace(os.Getenv("CADENCE_GOVERNED_INTERMEDIATE_KEY_ID"))
	if intermediateKeyID == "" {
		intermediateKeyID = rootKeyID + "-intermediate"
	}
	leafKeyID := strings.TrimSpace(os.Getenv("CADENCE_GOVERNED_LEAF_KEY_ID"))
	if leafKeyID == "" {
		leafKeyID = defaultLeafKeyID
	}
	return rootKeyID, intermediateKeyID, leafKeyID
}

func shortStableID(value string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(value)))
	return hex.EncodeToString(sum[:])[:16]
}

func computeEnvironmentSpec(cfg config.Config, sandboxProfile sandbox.Profile, manifests []plugins.Manifest, runnerBinaryDigest string) (map[string]any, string) {
	pluginRuntimes := make([]string, 0, len(manifests))
	pluginEnvKeys := map[string]bool{}
	for _, manifest := range manifests {
		pluginRuntimes = append(pluginRuntimes, manifest.Runtime)
		for _, key := range manifest.EnvAllowlist {
			pluginEnvKeys[key] = true
		}
	}
	sort.Strings(pluginRuntimes)
	pluginParentEnvKeys := sortedKeys(pluginEnvKeys)
	rootAnchor, rootAnchorSource := resolveRootAnchor(cfg)
	payload := map[string]any{
		"mode":                    cfg.Mode,
		"goos":                    runtime.GOOS,
		"goarch":                  runtime.GOARCH,
		"goVersion":               runtime.Version(),
		"goCompiler":              runtime.Compiler,
		"numCPU":                  runtime.NumCPU(),
		"cgroupVersion":           detectCgroupVersion(),
		"locale":                  detectLocale(),
		"ulimitNofile":            detectUlimitNofile(),
		"sandboxProfileId":        sandboxProfile.ProfileID,
		"sandboxBackend":          sandboxProfile.Backend,
		"sandboxFilesystem":       sandboxProfile.Filesystem,
		"sandboxNetwork":          sandboxProfile.NetworkAccess,
		"sandboxTimeSource":       sandboxProfile.TimeSource,
		"sandboxParentEnvKeys":    sandbox.AllowedParentEnvKeys(),
		"reservedParentEnvPrefix": sandbox.ReservedParentEnvPrefixes(),
		"pluginProtocol":          plugins.ProtocolVersion,
		"pluginRuntimes":          pluginRuntimes,
		"pluginParentEnvKeys":     pluginParentEnvKeys,
		"subprocessEnvKeys":       []string{"PYTHONDONTWRITEBYTECODE"},
		"runnerBinaryDigest":      runnerBinaryDigest,
		"rootAnchor":              rootAnchor,
		"rootAnchorSource":        rootAnchorSource,
	}
	data, _ := json.Marshal(payload)
	sum := sha256.Sum256(data)
	return payload, "sha256:" + hex.EncodeToString(sum[:])
}

func computeEnvironmentInputs(manifests []plugins.Manifest) ([]executionEnvRecord, string) {
	keys := map[string]bool{}
	for _, key := range sandbox.AllowedParentEnvKeys() {
		keys[key] = true
	}
	for _, manifest := range manifests {
		for _, key := range manifest.EnvAllowlist {
			keys[key] = true
		}
	}
	keys["PYTHONDONTWRITEBYTECODE"] = true
	keys["CADENCE_ROOT_ANCHOR"] = true

	records := make([]executionEnvRecord, 0, len(keys))
	for _, key := range sortedKeys(keys) {
		record := executionEnvRecord{Key: key}
		if value, ok := os.LookupEnv(key); ok {
			record.Present = true
			record.ValueHash = evidence.Sha256Prefixed([]byte(value))
		}
		records = append(records, record)
	}

	h := sha256.New()
	for _, record := range records {
		h.Write([]byte(record.Key))
		h.Write([]byte{0})
		if record.Present {
			h.Write([]byte("present"))
		} else {
			h.Write([]byte("absent"))
		}
		h.Write([]byte{0})
		h.Write([]byte(record.ValueHash))
		h.Write([]byte{'\n'})
	}
	return records, "sha256:" + hex.EncodeToString(h.Sum(nil))
}

func enrichSandboxResultWithIsolationProbe(result *sandbox.ExecutionResult, probe sandbox.IsolationProbe) {
	if result.BackendEvidence == nil {
		result.BackendEvidence = map[string]any{}
	}
	attestation := sandbox.DescribeBackendAttestation(sandbox.Profile{
		Backend:   result.Backend,
		ProfileID: result.ProfileID,
		SandboxID: result.ProfileID,
	}, probe)
	result.IsolationProbeRef = "isolation-probe.json"
	result.NamespaceProofHash = probe.NamespaceProofHash
	result.BackendEvidence["attestationStatus"] = attestation.AttestationStatus
	result.BackendEvidence["attestationLevel"] = attestation.AttestationLevel
	result.BackendEvidence["requiredChecks"] = attestation.RequiredChecks
	result.BackendEvidence["observedChecks"] = attestation.ObservedChecks
	if attestation.SeccompProfile != nil {
		result.BackendEvidence["seccompProfile"] = attestation.SeccompProfile
	}
	if len(attestation.FailureReasons) > 0 {
		result.BackendEvidence["attestationFailures"] = attestation.FailureReasons
	}
	if probe.NamespaceProofHash != "" {
		result.BackendEvidence["namespaceProofHash"] = probe.NamespaceProofHash
	}
	if len(probe.NamespaceProofs) > 0 {
		result.BackendEvidence["namespaceProofs"] = probe.NamespaceProofs
	}
}

func sortedKeys(values map[string]bool) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func detectCgroupVersion() string {
	if runtime.GOOS != "linux" {
		return "none"
	}
	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err == nil {
		return "v2"
	}
	if _, err := os.Stat("/sys/fs/cgroup"); err == nil {
		return "v1"
	}
	return "unknown"
}

func detectLocale() string {
	for _, key := range []string{"LC_ALL", "LC_CTYPE", "LANG"} {
		if v := os.Getenv(key); v != "" {
			return v
		}
	}
	return "unset"
}

func detectUlimitNofile() string {
	// Best-effort: read /proc/self/limits on Linux, otherwise "unknown".
	if runtime.GOOS != "linux" {
		return "not-linux"
	}
	data, err := os.ReadFile("/proc/self/limits")
	if err != nil {
		return "unknown"
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "Max open files") {
			fields := strings.Fields(line)
			if len(fields) >= 5 {
				return fields[3] // soft limit
			}
		}
	}
	return "unknown"
}

func computeReplayPlanHash(parts ...string) string {
	h := sha256.New()
	for _, part := range parts {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

func computeGovernedInputHash(parts ...string) string {
	h := sha256.New()
	for _, part := range parts {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

func fileSHA256(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func describeRegistryDependency(resolution registry.Resolution) map[string]string {
	payload := map[string]string{
		"kind":         resolution.Entry.Kind,
		"id":           resolution.Entry.ID,
		"ref":          resolution.Entry.Ref,
		"resolvedRef":  resolution.ResolvedRef,
		"status":       resolution.Entry.Status,
		"digest":       resolution.Entry.Digest,
		"compatWindow": resolution.Entry.CompatWindow,
	}
	if resolution.Entry.Kind == "policyPack" || resolution.Entry.Kind == "runtimeProfile" {
		payload["execution"] = "metadata-only; core uses built-in rules and sandboxRef controls"
		payload["runtimeCompatibility"] = "not-evaluated-for-execution"
	}
	if deprecatedAt := valueOrEmpty(resolution.Entry.DeprecatedAt); deprecatedAt != "" {
		payload["deprecatedAt"] = deprecatedAt
	}
	if reason := valueOrEmpty(resolution.Entry.DeprecationReason); reason != "" {
		payload["deprecationReason"] = reason
	}
	if resolution.Entry.Trust != nil {
		payload["trustSigner"] = resolution.Entry.Trust.Signer
		if resolution.Entry.Trust.Allowlisted {
			payload["trustAllowlisted"] = "true"
		} else {
			payload["trustAllowlisted"] = "false"
		}
	}
	return payload
}

func valueOrEmpty(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

// Stable input identity is separate from the identity of each execution attempt.
func allocateRunDirectory(root, prefix, alias string, automatic bool) (string, string, error) {
	if err := os.MkdirAll(root, 0o755); err != nil {
		return "", "", err
	}
	for attempt := 0; attempt < 8; attempt++ {
		id := prefix
		if automatic {
			var nonce [12]byte
			if _, err := rand.Read(nonce[:]); err != nil {
				return "", "", err
			}
			id += "-" + hex.EncodeToString(nonce[:])
		}
		if err := safePathComponent(id); err != nil {
			return "", "", err
		}
		if alias == id {
			return "", "", fmt.Errorf("alias and run id must be different")
		}
		dir := filepath.Join(root, id)
		if err := os.Mkdir(dir, 0o755); err != nil {
			if automatic && os.IsExist(err) {
				continue
			}
			return "", "", err
		}
		return id, dir, nil
	}
	return "", "", fmt.Errorf("automatic run id collision retry limit")
}

func deriveRunID(projectID string, profile string, configHash string, inputHash string, snapshotID string, dependencyHash string) string {
	h := sha256.New()
	for _, part := range []string{sanitizeID(projectID), strings.ToLower(strings.TrimSpace(profile)), configHash, inputHash, snapshotID, dependencyHash} {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	return fmt.Sprintf("%s_%s", sanitizeID(projectID), hex.EncodeToString(h.Sum(nil))[:24])
}

func gitHeadOrEmpty(repoRoot string) string {
	// Best-effort. If git is unavailable, return empty.
	cmd := exec.Command("git", "rev-parse", "HEAD")
	cmd.Dir = repoRoot
	out, err := cmd.CombinedOutput()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func computeSelfBinaryHashOrEmpty() string {
	// argv[0] can be relative, supplied by a caller, or resolve to another file
	// after chdir. Hash the executable the OS identifies for this process.
	p, err := os.Executable()
	if err != nil {
		return ""
	}
	if runtime.GOOS == "linux" {
		p = "/proc/self/exe"
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func topRuleIDs(vs []checks.Violation, n int) []string {
	m := map[string]struct{}{}
	for _, v := range vs {
		m[v.RuleID] = struct{}{}
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) > n {
		keys = keys[:n]
	}
	return keys
}

func countSeverity(vs []checks.Violation, s checks.Severity) int {
	c := 0
	for _, v := range vs {
		if v.Severity == s {
			c++
		}
	}
	return c
}

func minFloat(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

func maxFloat(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

// finalGateDecision preserves observations separately from profile enforcement.
func finalGateDecision(exitCode int, pipelineStatus string, waived bool) string {
	if exitCode != 0 {
		return "fail"
	}
	if waived {
		return "waived"
	}
	if pipelineStatus == "error" {
		return "fail"
	}
	if pipelineStatus == "degraded" {
		return "pass_with_warnings"
	}
	return "pass"
}

func governedInputExcludedPaths() []string {
	return []string{
		".cadence/out",
		".cadence/tmp",
		".cadence/bin",
	}
}

func prepareGovernedOutputRoots(repoRoot string, outDir string) ([]string, error) {
	// Only configured output roots are excluded. Artifact-looking names in a
	// source directory must never grant that directory an exemption.
	return combineExcludedPrefixes(governedInputExcludedPaths(), dynamicGovernedOutputPrefixes(repoRoot, outDir)), nil
}

func dynamicGovernedOutputPrefixes(repoRoot string, outDir string) []string {
	cleanRoot := filepath.Clean(repoRoot)
	cleanOut := outDir
	if !filepath.IsAbs(cleanOut) {
		cleanOut = filepath.Join(cleanRoot, cleanOut)
	}
	cleanOut = filepath.Clean(cleanOut)
	rel, err := filepath.Rel(cleanRoot, cleanOut)
	if err != nil {
		return nil
	}
	rel = filepath.ToSlash(rel)
	if rel == "." || rel == "" || rel == ".." || strings.HasPrefix(rel, "../") {
		return nil
	}
	return []string{rel}
}

func combineExcludedPrefixes(groups ...[]string) []string {
	seen := map[string]struct{}{}
	combined := []string{}
	for _, group := range groups {
		for _, prefix := range group {
			prefix = strings.TrimSpace(filepath.ToSlash(prefix))
			if prefix == "" {
				continue
			}
			if _, ok := seen[prefix]; ok {
				continue
			}
			seen[prefix] = struct{}{}
			combined = append(combined, prefix)
		}
	}
	sort.Strings(combined)
	return combined
}

func shouldExcludeIdentityPath(rel string, excludedPrefixes []string) bool {
	rel = filepath.ToSlash(strings.TrimSpace(rel))
	if rel == "" || rel == "." {
		return false
	}
	for _, prefix := range excludedPrefixes {
		if rel == prefix || strings.HasPrefix(rel, prefix+"/") {
			return true
		}
	}
	return false
}

func filterGovernedOutputViolations(violations []checks.Violation, excludedPrefixes []string) []checks.Violation {
	filtered := make([]checks.Violation, 0, len(violations))
	for _, violation := range violations {
		if shouldExcludeIdentityPath(violation.File, excludedPrefixes) {
			continue
		}
		filtered = append(filtered, violation)
	}
	return filtered
}

func normalizeSandboxResult(result sandbox.ExecutionResult) sandbox.ExecutionResult {
	result.StdoutHash = ""
	result.StderrHash = ""
	return result
}

func buildPrimaryRunManifest(manifest evidence.RunManifest) map[string]any {
	return map[string]any{
		"schemaVersion":   manifest.SchemaVersion,
		"runId":           manifest.RunID,
		"correlation":     manifest.Correlation,
		"pipeline":        manifest.Pipeline,
		"algorithm":       manifest.Algorithm,
		"contracts":       manifest.Contracts,
		"config":          manifest.Config,
		"inputRef":        manifest.InputRef,
		"sideEffectsMode": manifest.SideEffectsMode,
		"determinism":     manifest.Determinism,
		"diagnostics":     manifest.Diagnostics,
	}
}

func buildPrimaryPipelineResult(result evidence.PipelineResult) map[string]any {
	return map[string]any{
		"schemaVersion": result.SchemaVersion,
		"runId":         result.RunID,
		"pipeline":      result.Pipeline,
		"status":        result.Status,
		"output":        result.Output,
		"warnings":      result.Warnings,
		"diagnostics":   result.Diagnostics,
		"manifestRef":   result.ManifestRef,
		"error":         result.Error,
	}
}

func buildPrimaryJobEnvelope(job evidence.JobEnvelope) map[string]any {
	runs := make([]map[string]any, 0, len(job.Runs))
	for _, run := range job.Runs {
		runs = append(runs, map[string]any{
			"attempt":     run.Attempt,
			"manifestRef": run.ManifestRef,
			"result":      buildPrimaryPipelineResult(run.Result),
		})
	}
	return map[string]any{
		"schemaVersion":   job.SchemaVersion,
		"jobId":           job.JobID,
		"jobType":         job.JobType,
		"status":          job.Status,
		"correlation":     job.Correlation,
		"profileId":       job.ProfileID,
		"configId":        job.ConfigID,
		"configHash":      job.ConfigHash,
		"sideEffectsMode": job.SideEffectsMode,
		"inputRef":        job.InputRef,
		"runs":            runs,
		"diagnostics":     job.Diagnostics,
		"error":           job.Error,
	}
}

func canonicalTelemetryExcludedPaths() []string {
	return []string{
		"runManifest.createdAt",
		"runManifest.auditMeta",
		"runManifest.budget",
		"runManifest.stageSummaries.timeMs",
		"pipelineResult.budget",
		"pipelineResult.stageSummaries.timeMs",
		"jobEnvelope.createdAt",
		"jobEnvelope.updatedAt",
		"jobEnvelope.startedAt",
		"jobEnvelope.finishedAt",
		"jobEnvelope.runs[].startedAt",
		"jobEnvelope.runs[].finishedAt",
	}
}

func buildAuditTelemetry(manifest evidence.RunManifest, result evidence.PipelineResult, job evidence.JobEnvelope, elapsedMs float64) map[string]any {
	_ = elapsedMs
	return map[string]any{
		"schemaVersion":     "1.0.0",
		"runId":             manifest.RunID,
		"canonicalSurface":  "telemetry-normalized",
		"telemetryExcluded": canonicalTelemetryExcludedPaths(),
		"runManifest":       buildCanonicalRunManifest(manifest),
		"pipelineResult":    buildCanonicalPipelineResult(result),
		"jobEnvelope":       buildCanonicalJobEnvelope(job),
	}
}

func writeCanonicalProtocolArtifacts(runOut string, manifest evidence.RunManifest, result evidence.PipelineResult, job evidence.JobEnvelope) (map[string]string, error) {
	payloads := map[string]any{
		"run-manifest.canonical.json":    buildCanonicalRunManifest(manifest),
		"pipeline-result.canonical.json": buildCanonicalPipelineResult(result),
		"job-envelope.canonical.json":    buildCanonicalJobEnvelope(job),
	}
	hashes := make(map[string]string, len(payloads))
	for _, name := range []string{
		"run-manifest.canonical.json",
		"pipeline-result.canonical.json",
		"job-envelope.canonical.json",
	} {
		hash, err := evidence.WriteCanonicalJSON(filepath.Join(runOut, name), payloads[name])
		if err != nil {
			return nil, err
		}
		hashes[name] = hash
	}
	return hashes, nil
}

func buildCanonicalRunManifest(manifest evidence.RunManifest) map[string]any {
	return map[string]any{
		"schemaVersion":         manifest.SchemaVersion,
		"canonicalShapeVersion": "1.0.0",
		"canonicalSurface":      "telemetry-normalized",
		"telemetryExcluded":     canonicalTelemetryExcludedPaths(),
		"runId":                 manifest.RunID,
		"correlation":           manifest.Correlation,
		"pipeline":              manifest.Pipeline,
		"algorithm":             manifest.Algorithm,
		"contracts":             manifest.Contracts,
		"config":                manifest.Config,
		"inputRef":              manifest.InputRef,
		"sideEffectsMode":       manifest.SideEffectsMode,
		"determinism":           manifest.Determinism,
		"diagnostics":           manifest.Diagnostics,
	}
}

func buildCanonicalPipelineResult(result evidence.PipelineResult) map[string]any {
	return map[string]any{
		"schemaVersion":         result.SchemaVersion,
		"canonicalShapeVersion": "1.0.0",
		"canonicalSurface":      "telemetry-normalized",
		"telemetryExcluded":     canonicalTelemetryExcludedPaths(),
		"runId":                 result.RunID,
		"pipeline":              result.Pipeline,
		"status":                result.Status,
		"output":                result.Output,
		"warnings":              result.Warnings,
		"diagnostics":           result.Diagnostics,
		"manifestRef":           result.ManifestRef,
		"error":                 result.Error,
	}
}

func buildCanonicalJobEnvelope(job evidence.JobEnvelope) map[string]any {
	runs := make([]map[string]any, 0, len(job.Runs))
	for _, run := range job.Runs {
		runs = append(runs, map[string]any{
			"attempt":     run.Attempt,
			"manifestRef": run.ManifestRef,
			"result":      buildCanonicalPipelineResult(run.Result),
		})
	}
	return map[string]any{
		"schemaVersion":         job.SchemaVersion,
		"canonicalShapeVersion": "1.0.0",
		"canonicalSurface":      "telemetry-normalized",
		"telemetryExcluded":     canonicalTelemetryExcludedPaths(),
		"jobId":                 job.JobID,
		"jobType":               job.JobType,
		"status":                job.Status,
		"correlation":           job.Correlation,
		"profileId":             job.ProfileID,
		"configId":              job.ConfigID,
		"configHash":            job.ConfigHash,
		"sideEffectsMode":       job.SideEffectsMode,
		"inputRef":              job.InputRef,
		"runs":                  runs,
		"diagnostics":           job.Diagnostics,
		"error":                 job.Error,
	}
}

func writeDeterministicEvidence(path string, manifest evidence.RunManifest, result evidence.PipelineResult, job evidence.JobEnvelope, decision string, jobStatus string, dependencyHash string, sourceTreeHash string, runtimeInputsHash string, pluginSetHash string, environmentSpecHash string, replayPlanHash string, runnerBinaryDigest string, sandboxResult sandbox.ExecutionResult, isolationProbe sandbox.IsolationProbe, pluginResults []plugins.RunResult) (string, error) {
	runs := make([]map[string]any, 0, len(job.Runs))
	for _, run := range job.Runs {
		runs = append(runs, map[string]any{
			"attempt":      run.Attempt,
			"manifestRef":  run.ManifestRef,
			"resultStatus": run.Result.Status,
		})
	}

	payload := map[string]any{
		"schemaVersion":       "1.0.0",
		"runId":               manifest.RunID,
		"comparisonSurface":   "telemetry-normalized",
		"telemetryExcluded":   canonicalTelemetryExcludedPaths(),
		"decision":            decision,
		"jobStatus":           jobStatus,
		"dependencyHash":      dependencyHash,
		"sourceTreeHash":      sourceTreeHash,
		"runtimeInputsHash":   runtimeInputsHash,
		"pluginSetHash":       pluginSetHash,
		"environmentSpecHash": environmentSpecHash,
		"replayPlanHash":      replayPlanHash,
		"runnerBinaryDigest":  runnerBinaryDigest,
		"isolationProbeRef":   "isolation-probe.json",
		"namespaceProofHash":  isolationProbe.NamespaceProofHash,
		"sandboxResult":       sandboxResult,
		"pluginResults":       summarizePluginResults(pluginResults),
		"runManifest": map[string]any{
			"schemaVersion":   manifest.SchemaVersion,
			"runId":           manifest.RunID,
			"pipeline":        manifest.Pipeline,
			"algorithm":       manifest.Algorithm,
			"contracts":       manifest.Contracts,
			"config":          manifest.Config,
			"inputRef":        manifest.InputRef,
			"sideEffectsMode": manifest.SideEffectsMode,
			"determinism":     manifest.Determinism,
		},
		"pipelineResult": map[string]any{
			"schemaVersion": manifest.SchemaVersion,
			"runId":         result.RunID,
			"pipeline":      result.Pipeline,
			"status":        result.Status,
			"output":        result.Output,
			"warnings":      result.Warnings,
			"manifestRef":   result.ManifestRef,
			"error":         result.Error,
		},
		"jobEnvelope": map[string]any{
			"schemaVersion":   job.SchemaVersion,
			"jobId":           job.JobID,
			"jobType":         job.JobType,
			"status":          job.Status,
			"profileId":       job.ProfileID,
			"configHash":      job.ConfigHash,
			"sideEffectsMode": job.SideEffectsMode,
			"inputRef":        job.InputRef,
			"runs":            runs,
		},
	}

	return evidence.WriteCanonicalJSON(path, payload)
}

func executeVerifyPlugins(runOut string, repoRoot string, runID string, inputHash string, sourceTreeRecords []inputIdentityRecord, manifests []plugins.Manifest) ([]plugins.RunResult, []checks.Violation, error) {
	sourceFiles := make([]string, 0, len(sourceTreeRecords))
	for _, record := range sourceTreeRecords {
		sourceFiles = append(sourceFiles, record.Path)
	}
	sort.Strings(sourceFiles)

	resultsDir := filepath.Join(runOut, "plugin_results")
	if len(manifests) > 0 {
		if err := os.MkdirAll(resultsDir, 0o755); err != nil {
			return nil, nil, err
		}
	}

	results := make([]plugins.RunResult, 0, len(manifests))
	findings := []checks.Violation{}
	for _, manifest := range manifests {
		outputDir := filepath.Join(resultsDir, manifest.PluginID)
		if err := os.MkdirAll(outputDir, 0o755); err != nil {
			return nil, nil, err
		}
		result, err := plugins.Run(manifest, plugins.RunRequest{
			PluginID:        manifest.PluginID,
			ProtocolVersion: plugins.ProtocolVersion,
			RunID:           runID,
			InputHash:       inputHash,
			RepoRoot:        repoRoot,
			WorkingDir:      repoRoot,
			OutputDir:       outputDir,
			Files:           sourceFiles,
			Environment: map[string]string{
				"PYTHONDONTWRITEBYTECODE": "1",
			},
		})
		if err != nil {
			return nil, nil, err
		}
		if err := writeJSON(filepath.Join(outputDir, "result.json"), result); err != nil {
			return nil, nil, err
		}
		results = append(results, *result)
		for _, violation := range result.Response.Violations {
			severity := checks.SevP2
			switch strings.ToUpper(strings.TrimSpace(violation.Severity)) {
			case "P0":
				severity = checks.SevP0
			case "P1":
				severity = checks.SevP1
			}
			findings = append(findings, checks.New(
				violation.RuleID,
				severity,
				violation.Message,
				violation.File,
				violation.Line,
			))
		}
	}
	if len(results) > 0 {
		summary := summarizePluginResults(results)
		if err := writeJSON(filepath.Join(resultsDir, "summary.json"), summary); err != nil {
			return nil, nil, err
		}
		if err := writeJSON(filepath.Join(runOut, "plugin-results-summary.json"), summary); err != nil {
			return nil, nil, err
		}
	}
	return results, findings, nil
}

func summarizePluginResults(results []plugins.RunResult) []map[string]any {
	out := make([]map[string]any, 0, len(results))
	for _, result := range results {
		out = append(out, map[string]any{
			"pluginId":        result.PluginID,
			"manifestPath":    result.ManifestPath,
			"resolvedCommand": result.ResolvedCommand,
			"stdoutHash":      result.StdoutHash,
			"stderrHash":      result.StderrHash,
			"exitCode":        result.ExitCode,
			"status":          result.Response.Status,
			"violations":      len(result.Response.Violations),
			"protocolVersion": result.Response.ProtocolVersion,
		})
	}
	return out
}

func scanCmd(args []string) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	jsonOutput := fs.Bool("json", false, "emit machine-readable violations")
	ruleTrace := fs.Bool("with-rule-trace", false, "include executed built-in rule IDs in JSON")
	_ = fs.Parse(args)
	if *ruleTrace && !*jsonOutput {
		fmt.Fprintln(os.Stderr, "scan: --with-rule-trace requires --json")
		os.Exit(2)
	}

	repoRoot := physicalRepoRoot()
	vs, executed, err := checks.RunAllWithTrace(repoRoot)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scan failed: %v\n", err)
		os.Exit(1)
	}
	if *jsonOutput {
		var value any = vs
		if *ruleTrace {
			value = map[string]any{"violations": vs, "executedRules": executed}
		}
		payload, err := json.Marshal(value)
		if err != nil {
			fmt.Fprintf(os.Stderr, "scan failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(string(payload))
		return
	}
	counts := map[checks.Severity]int{}
	for _, v := range vs {
		counts[v.Severity]++
	}
	fmt.Printf("scan: P0=%d P1=%d P2=%d (total=%d)\n", counts[checks.SevP0], counts[checks.SevP1], counts[checks.SevP2], len(vs))
}

func adoptCmd(args []string) {
	fs := flag.NewFlagSet("adopt", flag.ExitOnError)
	_ = fs.Parse(args)
	if fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "adopt: unexpected positional arguments", fs.Args())
		os.Exit(2)
	}
	repoRoot := physicalRepoRoot()
	cfg, err := config.Load(repoRoot)
	if err != nil {
		fmt.Fprintf(os.Stderr, "adopt failed: %v\n", err)
		os.Exit(1)
	}
	vs, err := checks.RunAll(repoRoot)
	if err != nil {
		fmt.Fprintf(os.Stderr, "adopt failed: %v\n", err)
		os.Exit(1)
	}
	if err := baseline.Save(cfg.BaselinePath, vs); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write baseline: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("adopt: baseline written to %s (%d fingerprints)\n", cfg.BaselinePath, len(vs))
}

func reportCmd(args []string) {
	fs := flag.NewFlagSet("report", flag.ExitOnError)
	in := fs.String("in", "", "path to cadence-report.json (or summary.json)")
	_ = fs.Parse(args)
	if strings.TrimSpace(*in) == "" {
		fmt.Fprintln(os.Stderr, "report: --in is required")
		os.Exit(2)
	}
	b, err := os.ReadFile(*in)
	if err != nil {
		fmt.Fprintf(os.Stderr, "report failed: %v\n", err)
		os.Exit(1)
	}
	var obj map[string]any
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.UseNumber()
	if err := decoder.Decode(&obj); err != nil || obj == nil {
		fmt.Fprintln(os.Stderr, "report failed: expected a JSON object")
		os.Exit(1)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		fmt.Fprintln(os.Stderr, "report failed: trailing JSON data")
		os.Exit(1)
	}
	pretty, err := json.MarshalIndent(obj, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "report failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Cadence Report")
	fmt.Println("=============")
	fmt.Printf("Input: %q\n\n", *in)
	fmt.Println(string(pretty))
}

func lockCmd(args []string) {
	fs := flag.NewFlagSet("lock", flag.ExitOnError)
	out := fs.String("out", "cadence.lock", "output lock file")
	check := fs.Bool("check", false, "validate the lock file")
	_ = fs.Parse(args)

	lockPath := *out
	if *check {
		b, err := os.ReadFile(lockPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "lock check failed: cannot read %s: %v\n", lockPath, err)
			os.Exit(1)
		}
		ver, wantSha, parseErr := parseLegacyLock(b)
		if parseErr != nil {
			fmt.Fprintf(os.Stderr, "lock check failed: %v\n", parseErr)
			os.Exit(1)
		}
		if ver == "" {
			fmt.Fprintf(os.Stderr, "lock check failed: missing cadence_cli.version in %s\n", lockPath)
			os.Exit(1)
		}
		if ver != releaseVersion() {
			fmt.Fprintln(os.Stderr, "lock check failed: version differs from the current executable")
			os.Exit(1)
		}
		if wantSha != "" {
			gotSha := computeSelfBinaryHashOrEmpty()
			if gotSha == "" {
				fmt.Fprintf(os.Stderr, "lock check failed: unable to hash current binary\n")
				os.Exit(1)
			}
			if gotSha != wantSha {
				fmt.Fprintf(os.Stderr, "lock check failed: cadence_cli.sha256 mismatch\n  want %s\n  got  %s\n", wantSha, gotSha)
				os.Exit(1)
			}
		}
		fmt.Printf("lock: OK (%s)\n", lockPath)
		return
	}

	// Generate a minimal lock file. Additional plugin and runner pins can be layered on top by callers.
	sha := computeSelfBinaryHashOrEmpty()
	body := fmt.Sprintf("cadence_cli:\n  version: %q\n  sha256: %q\nplugins: []\nrunners: []\n", releaseVersion(), sha)
	if err := os.WriteFile(lockPath, []byte(body), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "lock write failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("lock: wrote %s\n", lockPath)
}

// The legacy cadence.lock is a YAML mapping, distinct from protocol lock schemas.
func parseLegacyLock(raw []byte) (string, string, error) {
	var root map[string]any
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	if err := decoder.Decode(&root); err != nil {
		return "", "", err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return "", "", fmt.Errorf("legacy lock must contain one YAML mapping")
	}
	if len(root) == 0 {
		return "", "", fmt.Errorf("legacy lock is empty")
	}
	for key := range root {
		if key != "cadence_cli" && key != "plugins" && key != "runners" {
			return "", "", fmt.Errorf("unknown legacy lock field %s", key)
		}
	}
	entry, ok := root["cadence_cli"].(map[string]any)
	if !ok {
		return "", "", fmt.Errorf("cadence_cli must be a mapping")
	}
	version, ok := entry["version"].(string)
	if !ok || version == "" {
		return "", "", fmt.Errorf("cadence_cli.version must be a string")
	}
	digest, ok := entry["sha256"].(string)
	if !ok || !evidence.ValidDigest(digest) {
		return "", "", fmt.Errorf("cadence_cli.sha256 must be a SHA-256 digest")
	}
	for key := range entry {
		if key != "version" && key != "sha256" {
			return "", "", fmt.Errorf("unknown cadence_cli field %s", key)
		}
	}
	for _, key := range []string{"plugins", "runners"} {
		if value, present := root[key]; present {
			if _, ok := value.([]any); !ok {
				return "", "", fmt.Errorf("%s must be an array", key)
			}
		}
	}
	return version, digest, nil
}

func doctorCmd(args []string) {
	fs := flag.NewFlagSet("doctor", flag.ExitOnError)
	checkLock := fs.Bool("lock", true, "validate the configured tooling_lock.json reference metadata")
	_ = fs.Parse(args)

	repoRoot := physicalRepoRoot()
	cfg, err := config.Load(repoRoot)
	if err != nil {
		fmt.Println("Cadence Doctor")
		fmt.Println("--------------")
		fmt.Printf("repoRoot:  %s\n", repoRoot)
		fmt.Printf("\nstatus: ISSUES FOUND\n- %s\n", err)
		os.Exit(1)
	}

	var problems []string

	if _, err := os.Stat(filepath.Join(repoRoot, "cadence.yaml")); err != nil {
		if _, err2 := os.Stat(filepath.Join(repoRoot, "cadence.yml")); err2 != nil {
			problems = append(problems, "missing cadence.yaml (or cadence.yml)")
		}
	}

	lockPath := filepath.Join(repoRoot, cfg.ToolingLock)
	if *checkLock {
		if b, err := os.ReadFile(lockPath); err == nil {
			if !strings.Contains(string(b), "schemaVersion") {
				problems = append(problems, "tooling_lock.json missing schemaVersion")
			}
		} else {
			problems = append(problems, "missing tooling_lock.json")
		}
	}

	// Ensure we can write to .cadence/ (local evidence cache).
	tmpDir := filepath.Join(repoRoot, ".cadence", "tmp")
	if err := os.MkdirAll(tmpDir, 0o755); err != nil {
		problems = append(problems, "cannot create .cadence/tmp (permissions)")
	}

	fmt.Println("Cadence Doctor")
	fmt.Println("--------------")
	fmt.Printf("projectId: %s\n", cfg.ProjectID)
	fmt.Printf("mode:      %s\n", cfg.Mode)
	fmt.Printf("baseline:  %s\n", cfg.BaselinePath)
	fmt.Printf("repoRoot:  %s\n", repoRoot)
	fmt.Printf("lockFile:  %s\n", lockPath)

	if len(problems) == 0 {
		fmt.Println("\nstatus: OK")
		os.Exit(0)
	}
	fmt.Println("\nstatus: ISSUES FOUND")
	for _, p := range problems {
		fmt.Printf("- %s\n", p)
	}
	os.Exit(1)
}

func mustCwd() string {
	d, err := os.Getwd()
	if err != nil {
		return "(unknown)"
	}
	return d
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

func resolveUserPath(repoRoot string, raw string) string {
	if filepath.IsAbs(raw) {
		return raw
	}
	return filepath.Join(repoRoot, raw)
}

func loadPersistedWaiverInputs(repoRoot string, waiverFilePath string, approvalChainPath string, ticket string) (waiver.Record, waiver.ApprovalChain, error) {
	var zeroRecord waiver.Record
	var zeroChain waiver.ApprovalChain

	if strings.TrimSpace(approvalChainPath) == "" {
		return zeroRecord, zeroChain, fmt.Errorf("--approval-chain-file is required with --waiver-file")
	}

	wf, err := waiver.LoadFile(resolveUserPath(repoRoot, waiverFilePath))
	if err != nil {
		return zeroRecord, zeroChain, err
	}
	if err := waiver.ValidateFile(wf); err != nil {
		return zeroRecord, zeroChain, err
	}
	record, err := waiver.SelectRecordByTicket(wf, ticket)
	if err != nil {
		return zeroRecord, zeroChain, err
	}
	chain, err := waiver.LoadApprovalChain(resolveUserPath(repoRoot, approvalChainPath))
	if err != nil {
		return zeroRecord, zeroChain, err
	}
	return record, chain, nil
}

func persistWaiverEvidence(runOut string, record waiver.Record, chain waiver.ApprovalChain, trail waiver.AuditTrail) error {
	if err := waiver.SaveFile(filepath.Join(runOut, "waiver.json"), &waiver.WaiverFile{
		SchemaVersion: waiver.SchemaVersion,
		Waivers:       []waiver.Record{record},
	}); err != nil {
		return err
	}
	if err := waiver.SaveApprovalChain(filepath.Join(runOut, "approval-chain.json"), chain); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(runOut, "waiver-audit-trail.json"), trail); err != nil {
		return err
	}
	return nil
}

func renderMarkdownSummary(summary map[string]any, violations []checks.Violation) string {
	var sb strings.Builder
	sb.WriteString("# Cadence Summary\n\n")
	sb.WriteString(fmt.Sprintf("- status: **%v**\n", summary["status"]))
	sb.WriteString(fmt.Sprintf("- runId: `%v`\n", summary["runId"]))
	sb.WriteString(fmt.Sprintf("- projectId: `%v`\n", summary["projectId"]))
	sb.WriteString(fmt.Sprintf("- violations: `%v`\n", summary["violations"]))
	if summary["waiver_applied"] == true {
		source := "waiver"
		if raw, ok := summary["waiver_source"].(string); ok && strings.TrimSpace(raw) != "" {
			source = raw
		}
		sb.WriteString(fmt.Sprintf("- waiver: **%s** (waiver.json, approval-chain.json emitted)\n", source))
	}
	if len(violations) == 0 {
		sb.WriteString("\nNo violations.\n")
		return sb.String()
	}
	sb.WriteString("\n## Violations\n\n")
	sb.WriteString("| Severity | Rule | File | Message |\n")
	sb.WriteString("|---|---|---|---|\n")
	for _, v := range violations {
		sb.WriteString(fmt.Sprintf("| %s | %s | %s | %s |\n", v.Severity, v.RuleID, v.File, escapePipes(v.Message)))
	}
	return sb.String()
}

func escapePipes(s string) string {
	return strings.ReplaceAll(s, "|", "\\|")
}
