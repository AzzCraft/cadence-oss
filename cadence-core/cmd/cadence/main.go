package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/azzcraft/cadence-core/internal/baseline"
	"github.com/azzcraft/cadence-core/internal/checks"
	"github.com/azzcraft/cadence-core/internal/config"
	"github.com/azzcraft/cadence-core/internal/evidence"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	cmd := os.Args[1]
	switch cmd {
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
  cadence scan
  cadence adopt
  cadence report [--format html|md]
  cadence lock [--check]
  cadence doctor

This repo pack is intended as a runnable reference scaffold.
The checks are intentionally small and conservative.
`)
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
	validateProtocol := fs.Bool("protocol-validate", true, "validate generated evidence against Cadence protocol invariants")
	_ = fs.Parse(args)

	repoRoot, _ := os.Getwd()
	cfg, _ := config.Load(repoRoot)

	started := time.Now().UTC()
	runID := strings.TrimSpace(*runIDFlag)
	if runID == "" {
		runID = fmt.Sprintf("%s_%s_%d", started.Format("20060102T150405Z"), sanitizeID(cfg.ProjectID), started.UnixNano()%1_000_000_000)
	} else {
		runID = sanitizeID(runID)
	}
	runOut := filepath.Join(*outDir, runID)

	if err := os.MkdirAll(runOut, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "failed to create out dir: %v\n", err)
		os.Exit(1)
	}

	// Compute strong references for evidence provenance.
	configHash := computeConfigHash(repoRoot)
	inputHash := computeRepoInputHash(repoRoot)
	snapshotID := gitHeadOrEmpty(repoRoot)

	// Execute checks.
	violations, err := checks.RunAll(repoRoot)
	if err != nil {
		fmt.Fprintf(os.Stderr, "verify failed: %v\n", err)
		os.Exit(1)
	}

	// Ratchet: suppress baseline fingerprints (if baseline exists).
	baselinePath := cfg.BaselinePath
	var bl baseline.Baseline
	if b, err := baseline.Load(baselinePath); err == nil {
		bl = b
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
	if maxSev == checks.SevP1 {
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

	waived := false
	if *breakGlass && exitCode != 0 {
		if strings.TrimSpace(*reason) == "" || strings.TrimSpace(*ticket) == "" {
			fmt.Fprintln(os.Stderr, "break-glass requires --reason and --ticket")
			os.Exit(2)
		}
		waived = true
		exitCode = 0
	}

	decision := "pass"
	if pipelineStatus == "degraded" {
		decision = "pass_with_warnings"
	}
	if pipelineStatus == "error" {
		decision = "fail"
	}
	if waived {
		decision = "waived"
	}

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
		Correlation:   corr,
		Pipeline:      evidence.Pipeline{ID: "cadence.verify"},
		Algorithm: evidence.Algorithm{
			Version: "cadence-core@0.7.0-demo",
			Build:   "scaffold",
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
			RawInputID: "file://" + filepath.ToSlash(repoRoot),
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
				"projectId":    cfg.ProjectID,
				"mode":         cfg.Mode,
				"baselinePath": baselinePath,
				"decision":     decision,
				"waived":       waived,
			},
			Counters: map[string]float64{
				"violations.total": float64(len(violations)),
				"violations.p0":    float64(countSeverity(violations, checks.SevP0)),
				"violations.p1":    float64(countSeverity(violations, checks.SevP1)),
				"violations.p2":    float64(countSeverity(violations, checks.SevP2)),
			},
		},
	}

	manifestPath := filepath.Join(runOut, "run-manifest.json")
	manifestHash, err := evidence.WriteCanonicalJSON(manifestPath, manifest)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to write run-manifest.json: %v\n", err)
		os.Exit(1)
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
			"decision":     decision,
			"reportRef":    "cadence-report.json",
			"summaryRef":   "summary.md",
			"violations":   vs,
			"breakGlass":   waived,
			"breakReason":  strings.TrimSpace(*reason),
			"breakTicket":  strings.TrimSpace(*ticket),
			"baselineUsed": len(bl.Fingerprints) > 0,
		},
		Warnings:       []string{},
		StageSummaries: []evidence.StageSummary{stage},
		Budget:         budget,
		Diagnostics: &evidence.Diagnostics{
			Codes: []string{"cadence.pipeline.completed"},
		},
		ManifestRef: evidence.ManifestRef{RunID: runID, ManifestHash: manifestHash},
		Error:       errEnv,
	}

	resultPath := filepath.Join(runOut, "pipeline-result.json")
	if _, err := evidence.WriteCanonicalJSON(resultPath, result); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write pipeline-result.json: %v\n", err)
		os.Exit(1)
	}

	jobStatus := "succeeded"
	if pipelineStatus == "degraded" {
		jobStatus = "degraded"
	}
	if pipelineStatus == "error" && !waived {
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
				"decision": decision,
			},
		},
	}

	jobPath := filepath.Join(runOut, "job-envelope.json")
	if _, err := evidence.WriteCanonicalJSON(jobPath, job); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write job-envelope.json: %v\n", err)
		os.Exit(1)
	}

	// Optional offline attestation (best-effort, self-declared in this scaffold).
	if strings.ToLower(cfg.Mode) == "strict_offline" {
		att := map[string]any{
			"schemaVersion": "1.0.0",
			"runId":         runID,
			"mode":          "strict_offline",
			"egressPolicy":  "deny",
			"createdAt":     finished.Format(time.RFC3339),
			"claims": []string{
				"cadence-core verify does not perform network I/O in this scaffold",
			},
			"toolchainHash": computeSelfBinaryHashOrEmpty(),
		}
		_ = writeJSON(filepath.Join(runOut, "offline-attestation.json"), att)
	}

	if waived {
		waiver := map[string]any{
			"schemaVersion": "1.0.0",
			"runId":         runID,
			"ticket":        strings.TrimSpace(*ticket),
			"reason":        strings.TrimSpace(*reason),
			"createdAt":     finished.Format(time.RFC3339),
			"expiresAt":     finished.Add(48 * time.Hour).Format(time.RFC3339),
		}
		_ = writeJSON(filepath.Join(runOut, "waiver.json"), waiver)
	}

	// Human-friendly summary + machine report.
	summary := map[string]any{
		"decision":     decision,
		"status":       pipelineStatus,
		"jobStatus":    jobStatus,
		"runId":        runID,
		"projectId":    cfg.ProjectID,
		"profile":      *profile,
		"violations":   len(violations),
		"break_glass":  waived,
		"baselinePath": baselinePath,
	}
	b, _ := json.MarshalIndent(summary, "", "  ")
	_ = os.WriteFile(filepath.Join(runOut, "summary.json"), b, 0o644)
	_ = os.WriteFile(filepath.Join(runOut, "summary.md"), []byte(renderMarkdownSummary(summary, violations)), 0o644)
	_ = writeJSON(filepath.Join(runOut, "cadence-report.json"), map[string]any{"runId": runID, "decision": decision, "status": pipelineStatus, "violations": vs})

	if *validateProtocol {
		if err := evidence.ValidateRunManifest(manifest); err != nil {
			fmt.Fprintf(os.Stderr, "protocol validate failed (run-manifest): %v\n", err)
			os.Exit(2)
		}
		if err := evidence.ValidatePipelineResult(result); err != nil {
			fmt.Fprintf(os.Stderr, "protocol validate failed (pipeline-result): %v\n", err)
			os.Exit(2)
		}
		if err := evidence.ValidateJobEnvelope(job); err != nil {
			fmt.Fprintf(os.Stderr, "protocol validate failed (job-envelope): %v\n", err)
			os.Exit(2)
		}
	}

	// Update a stable alias directory (default: .cadence/out/latest) to reduce "where did the files go" issues
	// for humans and automation.
	if strings.TrimSpace(*alias) != "" {
		if err := writeStableAlias(filepath.Join(*outDir, strings.TrimSpace(*alias)), runOut, runID); err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to update alias '%s': %v\n", strings.TrimSpace(*alias), err)
		}
	}

	fmt.Printf("verify: %s (decision=%s)\nEvidence written to %s\n", pipelineStatus, decision, runOut)
	if strings.TrimSpace(*alias) != "" {
		fmt.Printf("Alias updated: %s\n", filepath.Join(*outDir, strings.TrimSpace(*alias)))
	}
	os.Exit(exitCode)
}

func writeStableAlias(aliasDir string, runOut string, runID string) error {
	// Start clean each time so consumers can rely on a stable file set.
	_ = os.RemoveAll(aliasDir)
	if err := os.MkdirAll(aliasDir, 0o755); err != nil {
		return err
	}
	// Minimal manifest for humans & scripts.
	_ = os.WriteFile(filepath.Join(aliasDir, "RUN_ID"), []byte(runID+"\n"), 0o644)
	_ = os.WriteFile(filepath.Join(aliasDir, "RUN_PATH"), []byte(runOut+"\n"), 0o644)

	files := []string{
		"run-manifest.json",
		"pipeline-result.json",
		"job-envelope.json",
		"summary.json",
		"summary.md",
		"cadence-report.json",
		"offline-attestation.json",
		"waiver.json",
	}
	for _, name := range files {
		src := filepath.Join(runOut, name)
		if _, err := os.Stat(src); err != nil {
			continue
		}
		dst := filepath.Join(aliasDir, name)
		if err := copyFile(src, dst); err != nil {
			return err
		}
	}
	return nil
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
		case r == '-' || r == '_' || r == '.':
			out = append(out, r)
		default:
			out = append(out, '_')
		}
	}
	return string(out)
}

func computeConfigHash(repoRoot string) string {
	var parts [][]byte
	for _, p := range []string{"cadence.yaml", "cadence.yml", "cadence.lock"} {
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

func computeRepoInputHash(repoRoot string) string {
	type fh struct {
		Path string
		Sum  string
	}
	var files []fh
	_ = checks.WalkFiles(repoRoot, func(relPath string, b []byte) error {
		sum := sha256.Sum256(b)
		files = append(files, fh{Path: relPath, Sum: hex.EncodeToString(sum[:])})
		return nil
	})
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	h := sha256.New()
	for _, f := range files {
		h.Write([]byte(f.Path))
		h.Write([]byte{0})
		h.Write([]byte(f.Sum))
		h.Write([]byte{'\n'})
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
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
	p := os.Args[0]
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

func scanCmd(args []string) {
	// Minimal scan: show counts by severity.
	repoRoot, _ := os.Getwd()
	vs, err := checks.RunAll(repoRoot)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scan failed: %v\n", err)
		os.Exit(1)
	}
	counts := map[checks.Severity]int{}
	for _, v := range vs {
		counts[v.Severity]++
	}
	fmt.Printf("scan: P0=%d P1=%d P2=%d (total=%d)\n", counts[checks.SevP0], counts[checks.SevP1], counts[checks.SevP2], len(vs))
}

func adoptCmd(args []string) {
	repoRoot, _ := os.Getwd()
	cfg, _ := config.Load(repoRoot)
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
	// Render a very small human summary.
	var obj map[string]any
	_ = json.Unmarshal(b, &obj)
	fmt.Println("Cadence Report")
	fmt.Println("=============")
	fmt.Printf("Input: %s\n\n", *in)
	pretty, _ := json.MarshalIndent(obj, "", "  ")
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
		ver := extractYAMLScalar(string(b), "cadence_cli.version")
		if ver == "" {
			fmt.Fprintf(os.Stderr, "lock check failed: missing cadence_cli.version in %s\n", lockPath)
			os.Exit(1)
		}
		if !regexp.MustCompile(`^\d+\.\d+\.\d+(-[A-Za-z0-9\.]+)?$`).MatchString(ver) {
			fmt.Fprintf(os.Stderr, "lock check failed: cadence_cli.version not semver-ish: %q\n", ver)
			os.Exit(1)
		}
		wantSha := extractYAMLScalar(string(b), "cadence_cli.sha256")
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

	// Generate a minimal lock file. In production this would include plugin and runner pins.
	sha := computeSelfBinaryHashOrEmpty()
	body := fmt.Sprintf("cadence_cli:\n  version: %q\n  sha256: %q\nplugins: []\nrunners: []\n", "0.7.0-demo", sha)
	if err := os.WriteFile(lockPath, []byte(body), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "lock write failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("lock: wrote %s\n", lockPath)
}

func extractYAMLScalar(yamlText string, dottedKey string) string {
	// Very small YAML subset parser for this scaffold:
	// Supports:
	//   cadence_cli:
	//     version: "x"
	//     sha256: "sha256:..."
	parts := strings.Split(dottedKey, ".")
	if len(parts) != 2 {
		return ""
	}
	section, key := parts[0], parts[1]

	lines := strings.Split(yamlText, "\n")
	inSection := false
	for _, line := range lines {
		if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		if !strings.HasPrefix(line, " ") && strings.HasSuffix(strings.TrimSpace(line), ":") {
			inSection = strings.TrimSuffix(strings.TrimSpace(line), ":") == section
			continue
		}
		if !inSection {
			continue
		}
		trim := strings.TrimSpace(line)
		if strings.HasPrefix(trim, key+":") {
			val := strings.TrimSpace(strings.TrimPrefix(trim, key+":"))
			val = strings.Trim(val, "\"'")
			return val
		}
	}
	return ""
}

func doctorCmd(args []string) {
	fs := flag.NewFlagSet("doctor", flag.ExitOnError)
	checkLock := fs.Bool("lock", true, "validate cadence.lock (best-effort)")
	_ = fs.Parse(args)

	repoRoot, _ := os.Getwd()
	cfg, _ := config.Load(repoRoot)

	var problems []string

	if _, err := os.Stat(filepath.Join(repoRoot, "cadence.yaml")); err != nil {
		if _, err2 := os.Stat(filepath.Join(repoRoot, "cadence.yml")); err2 != nil {
			problems = append(problems, "missing cadence.yaml (or cadence.yml)")
		}
	}

	lockPath := filepath.Join(repoRoot, "cadence.lock")
	if *checkLock {
		if b, err := os.ReadFile(lockPath); err == nil {
			ver := extractYAMLScalar(string(b), "cadence_cli.version")
			if ver == "" {
				problems = append(problems, "cadence.lock missing cadence_cli.version")
			}
		} else {
			problems = append(problems, "missing cadence.lock")
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

func renderMarkdownSummary(summary map[string]any, violations []checks.Violation) string {
	var sb strings.Builder
	sb.WriteString("# Cadence Summary\n\n")
	sb.WriteString(fmt.Sprintf("- status: **%v**\n", summary["status"]))
	sb.WriteString(fmt.Sprintf("- runId: `%v`\n", summary["runId"]))
	sb.WriteString(fmt.Sprintf("- projectId: `%v`\n", summary["projectId"]))
	sb.WriteString(fmt.Sprintf("- violations: `%v`\n", summary["violations"]))
	if summary["break_glass"] == true {
		sb.WriteString("- break-glass: **true** (waiver.json emitted)\n")
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
