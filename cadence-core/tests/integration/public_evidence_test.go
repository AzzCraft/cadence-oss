package integration

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AzzCraft/cadence-oss/cadence-core/internal/evidence"
	"github.com/AzzCraft/cadence-oss/cadence-core/internal/signing"
)

func TestPublicContractHubScanAndVerify(t *testing.T) {
	bin := buildBinary(t)
	repo := setupTestRepo(t)
	source := filepath.Join(coreRoot(t), "..", "contracts-hub-template", "contracts")
	if err := os.CopyFS(filepath.Join(repo, "contracts"), os.DirFS(source)); err != nil {
		t.Fatal(err)
	}
	for _, missing := range []bool{false, true} {
		runID := "fixtures-good"
		if missing {
			runID = "fixtures-missing"
			if err := os.RemoveAll(filepath.Join(repo, "contracts", "fixtures", "payment", "invalid")); err != nil {
				t.Fatal(err)
			}
		}
		for _, args := range [][]string{{"scan", "--json"}, {"verify", "--profile", "ci", "--run-id", runID}} {
			cmd := exec.Command(bin, args...)
			cmd.Dir = repo
			for _, item := range os.Environ() {
				if !strings.HasPrefix(item, "CADENCE_") {
					cmd.Env = append(cmd.Env, item)
				}
			}
			out, err := cmd.CombinedOutput()
			if args[0] == "scan" {
				var findings []struct {
					RuleID string `json:"ruleId"`
				}
				if err != nil || json.Unmarshal(out, &findings) != nil {
					t.Fatalf("scan failed: %v %s", err, out)
				}
				count := 0
				for _, finding := range findings {
					if finding.RuleID == "CONTRACT_FIXTURE_MISSING" {
						count++
					}
				}
				if (!missing && count != 0) || (missing && count != 1) {
					t.Fatalf("fixture findings missing=%v: %s", missing, out)
				}
			} else if (err != nil) != missing {
				t.Fatalf("verify missing=%v: %v %s", missing, err, out)
			} else if missing {
				var result map[string]any
				loadJSON(t, filepath.Join(repo, ".cadence", "out", runID, "pipeline-result.json"), &result)
				output, ok := result["output"].(map[string]any)
				if !ok || output["decision"] != "fail" || result["status"] != "degraded" {
					t.Fatalf("P1 rejection misreported: %v", result)
				}
			}
		}
	}
}

func TestPersistedRejectedPolicyIsRecorded(t *testing.T) {
	bin := buildBinary(t)
	repo := setupTestRepo(t)
	if err := os.WriteFile(filepath.Join(repo, "app.env"), []byte("TEST_AUTH_TOKEN=synthetic-secret-token\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, defect := range []string{"repeated-principal", "unordered-role", "future-created", "negative-interval"} {
		t.Run(defect, func(t *testing.T) {
			record := map[string]any{"reason": "synthetic exception", "ticket": "TEST-WAIVER", "owner": "requester-a", "approvedBy": "approver-d", "createdAt": "2026-10-19T00:00:00Z", "referenceTime": "2026-10-19T00:00:00Z", "signature": "metadata-only", "scope": "profile"}
			entries := []map[string]any{}
			for i, role := range []string{"requester", "manager", "security", "approver"} {
				entries = append(entries, map[string]any{"role": role, "identity": []string{"requester-a", "manager-b", "security-c", "approver-d"}[i], "timestamp": record["referenceTime"]})
			}
			if defect == "repeated-principal" {
				entries[2]["identity"] = entries[1]["identity"]
			} else if defect == "unordered-role" {
				entries[1]["role"] = "security"
			} else if defect == "future-created" {
				record["createdAt"] = "2026-10-21T00:00:00Z"
			} else {
				record["expiresAt"] = "2026-10-18T00:00:00Z"
			}
			writeTestJSON(t, filepath.Join(repo, "waivers.json"), map[string]any{"schemaVersion": "1.0.0", "waivers": []any{record}})
			writeTestJSON(t, filepath.Join(repo, "approval.json"), map[string]any{"waiverTicket": "TEST-WAIVER", "depth": 4, "entries": entries})
			cmd := exec.Command(bin, "verify", "--run-id", defect, "--waiver-file", "waivers.json", "--approval-chain-file", "approval.json", "--ticket", "TEST-WAIVER")
			cmd.Dir = repo
			for _, item := range os.Environ() {
				if !strings.HasPrefix(item, "CADENCE_") {
					cmd.Env = append(cmd.Env, item)
				}
			}
			out, err := cmd.CombinedOutput()
			if defect == "future-created" || defect == "negative-interval" {
				if err == nil || !strings.Contains(string(out), "waiver record warning:") {
					t.Fatalf("contradictory waiver accepted: %v %s", err, out)
				}
				if _, statErr := os.Stat(filepath.Join(repo, ".cadence/out", defect, "pipeline-result.json")); !os.IsNotExist(statErr) {
					t.Fatal("invalid waiver emitted a result", statErr)
				}
			} else if err == nil || !strings.Contains(string(out), "distinct principals and ordered roles") {
				t.Fatalf("fixture did not reach persisted policy refusal: %v\n%s", err, out)
			}
			var trail map[string]any
			loadJSON(t, filepath.Join(repo, ".cadence/out", defect, "waiver-audit-trail.json"), &trail)
			if trail["compliant"] != false {
				t.Fatalf("policy refusal recorded as compliant: %v", trail)
			}
			found := false
			for _, item := range trail["decisions"].([]any) {
				d := item.(map[string]any)
				found = found || d["check"] == "persisted-policy" && d["status"] == "fail"
			}
			if !found {
				t.Fatal("missing persisted policy refusal in retained trail")
			}
		})
	}
}

// One producer build and one reader build cover the actual public boundary.
func TestPublicNativeEvidenceRoundTripAndRefusal(t *testing.T) {
	bin := buildBinary(t)
	reader := filepath.Join(t.TempDir(), "evidence-verify")
	build := exec.Command("go", "build", "-buildvcs=false", "-o", reader, "./cmd/evidence-verify")
	build.Dir = coreRoot(t)
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("reader build: %v\n%s", err, out)
	}
	repo := setupTestRepo(t)
	outDir := filepath.Join(repo, ".cadence", "out")
	env := []string{}
	for _, item := range os.Environ() {
		if !strings.HasPrefix(item, "CADENCE_") {
			env = append(env, item)
		}
	}
	run := func(args ...string) ([]byte, error) {
		cmd := exec.Command(bin, args...)
		cmd.Dir = repo
		cmd.Env = env
		return cmd.CombinedOutput()
	}
	if out, err := run("verify", "--run-id", "good", "--out", outDir); err != nil {
		t.Fatalf("producer: %v\n%s", err, out)
	}
	bundle := filepath.Join(outDir, "good", "evidence-bundle.json")
	cmd := exec.Command(reader, "--profile", "cadence-run/v2", "--bundle", bundle)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("native round trip: %v\n%s", err, out)
	}
	var inventory map[string]any
	loadJSON(t, bundle, &inventory)
	if inventory["schemaVersion"] != "cadence-evidence-bundle/v2" {
		t.Fatal("wrong producer identity")
	}
	original, err := os.Readlink(filepath.Join(outDir, "latest"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(outDir, "latest", "evidence-bundle.json")); err != nil {
		t.Fatal("alias omitted inventory")
	}
	if _, err := os.Stat(filepath.Join(outDir, "good", "hsm-anchor.json")); !os.IsNotExist(err) {
		t.Fatal("unsigned run fabricated an active signer")
	}
	for _, profile := range []string{"cad002/v1", "cadence-run/v1", "unknown"} {
		if out, err := exec.Command(reader, "--profile", profile, "--bundle", bundle).CombinedOutput(); err == nil {
			t.Fatalf("wrong profile accepted: %s", out)
		}
	}
	// Inventory and step-chain are separate structures; rebuilding only the
	// inventory must not conceal a stale producer-declared artifact binding.
	for _, name := range []string{"run-manifest.json", "run-manifest.canonical.json", "pipeline-result.json", "pipeline-result.canonical.json", "job-envelope.json", "job-envelope.canonical.json", "input-identity.json", "audit-telemetry.json", "deterministic-evidence.json"} {
		t.Run("chain-binding-"+name, func(t *testing.T) {
			dir := filepath.Join(outDir, "good")
			path := filepath.Join(dir, name)
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			oldInventory, err := os.ReadFile(bundle)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { os.WriteFile(path, raw, 0600); os.WriteFile(bundle, oldInventory, 0600) }()
			if err := os.WriteFile(path, append(raw, '\n'), 0600); err != nil {
				t.Fatal(err)
			}
			updated, err := evidence.BuildEvidenceBundle(dir, "run-manifest.json", "pipeline-result.json")
			if err != nil {
				t.Fatal(err)
			}
			writeTestJSON(t, bundle, updated)
			if out, err := exec.Command(reader, "--profile", "cadence-run/v2", "--bundle", bundle).CombinedOutput(); err == nil {
				t.Fatalf("stale %s binding accepted: %s", name, out)
			}
		})
	}

	// A newly valid chain cannot replace the defined input/dependency relation.
	for _, target := range []string{"input", "dependency"} {
		t.Run("chain-relation-"+target, func(t *testing.T) {
			dir := filepath.Join(outDir, "good")
			path := filepath.Join(dir, "step-hash-chain.json")
			raw, _ := os.ReadFile(path)
			oldInventory, _ := os.ReadFile(bundle)
			defer func() { os.WriteFile(path, raw, 0600); os.WriteFile(bundle, oldInventory, 0600) }()
			var original signing.Chain
			loadJSON(t, path, &original)
			rebuilt := signing.NewChain()
			for _, step := range original.Steps {
				input, output := step.InputHash, step.OutputHash
				if target == "input" && step.StepID == "manifest" {
					input = "sha256:" + strings.Repeat("1", 64)
				}
				if target == "dependency" && step.StepID == "dependencies" {
					output = "sha256:" + strings.Repeat("1", 64)
				}
				rebuilt.Append(step.StepID, input, output)
			}
			if err := signing.VerifyChain(rebuilt); err != nil {
				t.Fatal(err)
			}
			writeTestJSON(t, path, rebuilt)
			updated, err := evidence.BuildEvidenceBundle(dir, "run-manifest.json", "pipeline-result.json")
			if err != nil {
				t.Fatal(err)
			}
			writeTestJSON(t, bundle, updated)
			out, err := exec.Command(reader, "--profile", "cadence-run/v2", "--bundle", bundle).CombinedOutput()
			if err == nil || !strings.Contains(string(out), "binding mismatch") {
				t.Fatalf("unbound valid chain: %v %s", err, out)
			}
		})
	}
	// Recompute the inventory after each mutation: a stale digest alone must
	// not be what rejects inconsistent identities or nullable scalar fields.
	for _, mutation := range []string{"result-run", "nested-result-run", "manifest-hash", "audit-null", "signature-null"} {
		t.Run(mutation, func(t *testing.T) {
			dir := filepath.Join(outDir, "good")
			originals := map[string][]byte{}
			for _, name := range []string{"pipeline-result.json", "job-envelope.json", "evidence-bundle.json"} {
				data, err := os.ReadFile(filepath.Join(dir, name))
				if err != nil {
					t.Fatal(err)
				}
				originals[name] = data
			}
			defer func() {
				for name, data := range originals {
					if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
						t.Error(err)
					}
				}
			}()
			var result, job map[string]any
			loadJSON(t, filepath.Join(dir, "pipeline-result.json"), &result)
			loadJSON(t, filepath.Join(dir, "job-envelope.json"), &job)
			switch mutation {
			case "result-run":
				result["runId"] = "another-run"
			case "nested-result-run":
				job["runs"].([]any)[0].(map[string]any)["result"].(map[string]any)["runId"] = "another-run"
			case "manifest-hash":
				result["manifestRef"].(map[string]any)["manifestHash"] = "sha256:" + strings.Repeat("0", 64)
			}
			writeTestJSON(t, filepath.Join(dir, "pipeline-result.json"), result)
			writeTestJSON(t, filepath.Join(dir, "job-envelope.json"), job)
			inventory, err := evidence.BuildEvidenceBundle(dir, "run-manifest.json", "pipeline-result.json")
			if err != nil {
				t.Fatal(err)
			}
			if err := evidence.VerifyBundleIntegrity(*inventory, dir); err != nil {
				t.Fatal(err)
			}
			writeTestJSON(t, bundle, inventory)
			var envelope map[string]any
			loadJSON(t, bundle, &envelope)
			if mutation == "audit-null" {
				envelope["audit"].(map[string]any)["operator"] = nil
			}
			if mutation == "signature-null" {
				envelope["signature"] = nil
			}
			writeTestJSON(t, bundle, envelope)
			if out, err := exec.Command(reader, "--profile", "cadence-run/v2", "--bundle", bundle).CombinedOutput(); err == nil {
				t.Fatalf("accepted rebound %s: %s", mutation, out)
			}
		})
	}
	path := filepath.Join(outDir, "good", "summary.md")
	originalSummary, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, []byte("tampered"), 0600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(reader, "--profile", "cadence-run/v2", "--bundle", bundle).CombinedOutput(); err == nil {
		t.Fatalf("tampered primary accepted: %s", out)
	}
	os.WriteFile(path, originalSummary, 0600)
	// A failed or reused run cannot overwrite a successful run or advance latest.
	if out, err := run("verify", "--run-id", "good", "--out", outDir); err == nil {
		t.Fatalf("overwrote immutable run: %s", out)
	}
	after, err := os.Readlink(filepath.Join(outDir, "latest"))
	if err != nil || after != original {
		t.Fatal("failure advanced success pointer")
	}

	// Default runs retain stable inputs but allocate a fresh immutable attempt.
	var stable map[string]any
	for i := 0; i < 2; i++ {
		if out, err := run("verify", "--out", outDir); err != nil {
			t.Fatalf("default retry: %v %s", err, out)
		}
		id, err := os.Readlink(filepath.Join(outDir, "latest"))
		if err != nil || id == original {
			t.Fatal("default run reused prior output")
		}
		dir := filepath.Join(outDir, id)
		if out, err := exec.Command(reader, "--profile", "cadence-run/v2", "--bundle", filepath.Join(dir, "evidence-bundle.json")).CombinedOutput(); err != nil {
			t.Fatalf("default reader: %v %s", err, out)
		}
		var identity map[string]any
		loadJSON(t, filepath.Join(dir, "input-identity.json"), &identity)
		if stable != nil {
			for _, key := range []string{"inputHash", "snapshotId", "replayPlanHash"} {
				if identity[key] == nil || identity[key] != stable[key] {
					t.Fatalf("unstable %s: %v vs %v", key, identity[key], stable[key])
				}
			}
		}
		stable = identity
		original = id
	}
	// Actual late CLI failures, after scan/bundle creation, must retain a
	// structured failed delivery rather than only stderr + a nonzero exit.
	for _, failure := range []string{"signer", "alias"} {
		t.Run(failure, func(t *testing.T) {
			id := "delivery-" + failure
			args := []string{"verify", "--run-id", id, "--out", outDir}
			command := exec.Command(bin, args...)
			command.Dir = repo
			command.Env = append([]string{}, env...)
			if failure == "signer" {
				command.Env = append(command.Env, "CADENCE_SIGNING_MODE=governed",
					"CADENCE_ROOT_ANCHOR=software://synthetic-review",
					"CADENCE_GOVERNED_SIGNING_PUBLIC_KEY="+strings.Repeat("00", 32),
					"CADENCE_GOVERNED_SIGNER_COMMAND=false")
			} else {
				legacy := filepath.Join(outDir, "legacy")
				if err := os.Mkdir(legacy, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(legacy, "kept"), []byte("prior"), 0600); err != nil {
					t.Fatal(err)
				}
				command.Args = append(command.Args, "--alias", "legacy")
			}
			out, err := command.CombinedOutput()
			if err == nil {
				t.Fatalf("late failure returned success: %s", out)
			}
			if !strings.Contains(string(out), "evidence delivery incomplete") {
				t.Fatalf("fixture did not reach delivery: %s", out)
			}
			var delivery, summary map[string]any
			loadJSON(t, filepath.Join(outDir, id, "delivery-error.json"), &delivery)
			loadJSON(t, filepath.Join(outDir, id, "summary.json"), &summary)
			if delivery["deliveryComplete"] != false || summary["deliveryComplete"] != false || (summary["decision"] != "fail" || summary["scanDecision"] != "pass") {
				t.Fatalf("lost scan/delivery facts: %v %v", summary, delivery)
			}
			if !strings.Contains(delivery["error"].(string), map[string]string{"signer": "sign evidence bundle", "alias": "update alias"}[failure]) {
				t.Fatalf("did not reach intended late failure: %s", out)
			}
			if after, err := os.Readlink(filepath.Join(outDir, "latest")); err != nil || after != original {
				t.Fatal("late failure advanced prior successful alias")
			}
			if failure == "alias" {
				if kept, err := os.ReadFile(filepath.Join(outDir, "legacy", "kept")); err != nil || string(kept) != "prior" {
					t.Fatal("lost legacy alias")
				}
			}
		})
	}
	beforeEntries, _ := os.ReadDir(outDir)
	if out, err := run("verify", "--out", outDir, "--alias", "legacy"); err == nil || !strings.Contains(string(out), "evidence delivery incomplete") {
		t.Fatalf("expected late default failure: %v %s", err, out)
	}
	afterEntries, _ := os.ReadDir(outDir)
	if len(afterEntries) != len(beforeEntries)+1 {
		t.Fatal("default failure did not preserve an independent attempt")
	}
	if after, err := os.Readlink(filepath.Join(outDir, "latest")); err != nil || after != original {
		t.Fatal("default failure advanced success pointer")
	}
	// Two real default CLI executions also share the input safely.
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() { _, err := run("verify", "--out", outDir); results <- err }()
	}
	for i := 0; i < 2; i++ {
		if err := <-results; err != nil {
			t.Fatalf("concurrent default retry: %v", err)
		}
	}
	finalEntries, _ := os.ReadDir(outDir)
	if len(finalEntries) != len(afterEntries)+2 {
		t.Fatal("concurrent runs reused a directory")
	}
	original, err = os.Readlink(filepath.Join(outDir, "latest"))
	if err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(reader, "--profile", "cadence-run/v2", "--bundle", filepath.Join(outDir, original, "evidence-bundle.json")).CombinedOutput(); err != nil {
		t.Fatalf("retry reader: %v %s", err, out)
	}
	// Synthetic policy failures have actual violations to waive.
	os.WriteFile(filepath.Join(repo, "app.env"), []byte("TEST_AUTH_TOKEN=synthetic-secret-token\n"), 0600)
	record := map[string]any{"reason": "synthetic exception", "ticket": "TEST-WAIVER", "owner": "requester-a", "approvedBy": "requester-a", "createdAt": "2026-10-19T00:00:00Z", "referenceTime": "2026-10-19T00:00:00Z", "signature": "metadata-only", "scope": "profile"}
	entries := []map[string]any{}
	for i, role := range []string{"requester", "manager", "security", "approver"} {
		principal := []string{"requester-a", "manager-b", "manager-b", "requester-a"}[i]
		entries = append(entries, map[string]any{"role": role, "identity": principal, "timestamp": "2026-10-19T00:00:00Z"})
	}
	writeTestJSON(t, filepath.Join(repo, "waivers.json"), map[string]any{"schemaVersion": "1.0.0", "waivers": []any{record}})
	for _, size := range []int{2, 4} {
		writeTestJSON(t, filepath.Join(repo, "approval.json"), map[string]any{"waiverTicket": "TEST-WAIVER", "depth": size, "entries": entries[:size]})
		id := "refused-" + string(rune('0'+size))
		out, err := run("verify", "--run-id", id, "--out", outDir, "--waiver-file", "waivers.json", "--approval-chain-file", "approval.json", "--ticket", "TEST-WAIVER")
		if err == nil {
			t.Fatalf("accepted insufficient/self approval: %s", out)
		}
		data, err := os.ReadFile(filepath.Join(outDir, id, "waiver-audit-trail.json"))
		if err != nil {
			t.Fatal(err)
		}
		var trail map[string]any
		if err = json.Unmarshal(data, &trail); err != nil || trail["compliant"] != false {
			t.Fatalf("rejected trail missing: %s", data)
		}
		after, _ := os.Readlink(filepath.Join(outDir, "latest"))
		if after != original {
			t.Fatal("waiver refusal advanced success pointer")
		}
	}
}

// A single producer build checks both scan exclusion and all profile summaries.
func TestNativeReportsMatchGateAndDoNotTrustArtifactNames(t *testing.T) {
	bin := buildBinary(t)
	for _, severity := range []string{"clean", "P0", "P1", "waived"} {
		for _, profile := range []string{"dev", "ci", "full"} {
			t.Run(severity+"-"+profile, func(t *testing.T) {
				repo := setupTestRepo(t)
				fake := filepath.Join(repo, "src", "example-run")
				if err := os.MkdirAll(fake, 0700); err != nil {
					t.Fatal(err)
				}
				for _, name := range []string{"run-manifest.json", "pipeline-result.json", "job-envelope.json"} {
					if err := os.WriteFile(filepath.Join(fake, name), []byte("{}"), 0600); err != nil {
						t.Fatal(err)
					}
				}
				content := "# clean source\n"
				if severity == "P0" || severity == "waived" {
					content = "TEST_AUTH_TOKEN=synthetic\n"
				}
				if severity == "P1" {
					content = "password = 'synthetic-example'\n"
				}
				if err := os.WriteFile(filepath.Join(repo, "src", "app.py"), []byte(content), 0600); err != nil {
					t.Fatal(err)
				}
				cmd := exec.Command(bin, "verify", "--profile", profile, "--run-id", "case", "--out", "custom-output")
				if severity == "waived" {
					cmd.Args = append(cmd.Args, "--break-glass", "--reason", "synthetic test", "--ticket", "TEST-1", "--waiver-approved-by", "test-approver", "--waiver-reference-time", "2026-10-21T00:00:00Z", "--waiver-signature", "test-metadata")
				}
				cmd.Dir = repo
				for _, item := range os.Environ() {
					if !strings.HasPrefix(item, "CADENCE_") {
						cmd.Env = append(cmd.Env, item)
					}
				}
				output, err := cmd.CombinedOutput()
				refuse := severity == "P0" || severity == "P1" && profile != "dev"
				if (err != nil) != refuse {
					t.Fatalf("exit mismatch: %v\n%s", err, output)
				}
				dir := filepath.Join(repo, "custom-output", "case")
				var summary, reportSummary, cadenceReport map[string]any
				loadJSON(t, filepath.Join(dir, "summary.json"), &summary)
				loadJSON(t, filepath.Join(dir, "report-summary.json"), &reportSummary)
				loadJSON(t, filepath.Join(dir, "cadence-report.json"), &cadenceReport)
				native := reportSummary["summary"].(map[string]any)
				if summary["decision"] != native["status"] || cadenceReport["decision"] != native["status"] {
					t.Fatalf("inconsistent summaries: %v / %v / %v", summary, native, cadenceReport)
				}
				if (native["status"] == "fail") != refuse {
					t.Fatalf("false gate decision: %v", native)
				}
				findings, _ := reportSummary["findings"].([]any)
				if native["violations"] != float64(len(findings)) || severity != "clean" && len(findings) == 0 {
					t.Fatalf("lost violations: %v", native)
				}
			})
		}
	}
	physical := setupTestRepo(t)
	logical := filepath.Join(t.TempDir(), "linked-project")
	if err := os.Symlink(physical, logical); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(physical, "app.txt"), []byte("TEST_AUTH_TOKEN=synthetic"), 0600)
	var scan string
	for _, dir := range []string{physical, logical} {
		cmd := exec.Command(bin, "scan", "--json")
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "PWD="+dir)
		out, err := cmd.CombinedOutput()
		if err != nil || !strings.Contains(string(out), "SEC_TEST_AUTH_TOKEN") {
			t.Fatalf("logical root lost finding: %v %s", err, out)
		}
		if scan != "" && scan != string(out) {
			t.Fatal("logical/physical findings differ")
		}
		scan = string(out)
	}
	repo := setupTestRepo(t)
	baseEnv := []string{}
	for _, item := range os.Environ() {
		if !strings.HasPrefix(item, "CADENCE_") {
			baseEnv = append(baseEnv, item)
		}
	}
	for _, args := range [][]string{
		{"verify", ".", "--profile", "ci"}, {"verify", "stray"}, {"verify", "--", "--profile", "ci"},
		{"verify", "--profile", "ful"}, {"verify", "--profile", " "},
		{"adopt", "--unsupported"}, {"adopt", "stray"},
	} {
		cmd := exec.Command(bin, args...)
		cmd.Dir = repo
		cmd.Env = baseEnv
		if out, err := cmd.CombinedOutput(); err == nil {
			t.Fatalf("invalid argv accepted: %v %s", args, out)
		}
	}
	for _, env := range [][]string{{"CADENCE_SIGNING_MODE=goverend"}, {"CADENCE_SIGNING_MODE=goverend", "CADENCE_SIGNING_KEY=synthetic"}, {"CADENCE_SIGNING_MODE=goverend", "CADENCE_GOVERNED_PRIVATE_KEY=synthetic"}} {
		cmd := exec.Command(bin, "verify")
		cmd.Dir = repo
		cmd.Env = append(append([]string{}, baseEnv...), env...)
		if out, err := cmd.CombinedOutput(); err == nil || !strings.Contains(string(out), "SIGNING_MODE") {
			t.Fatalf("invalid mode accepted: %v %s", err, out)
		}
	}
	for _, dir := range []string{repo, t.TempDir()} {
		cmd := exec.Command(bin, "adopt", "--help")
		cmd.Dir = dir
		cmd.Env = baseEnv
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("help failed: %v %s", err, out)
		}
		if _, err := os.Stat(filepath.Join(dir, ".cadence")); !os.IsNotExist(err) {
			t.Fatal("invalid/help command wrote artifacts")
		}
	}
	configPath := filepath.Join(repo, "cadence.yaml")
	configBytes, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, append(configBytes, []byte("ui:\n  enabled: true\n")...), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "verify")
	cmd.Dir = repo
	cmd.Env = baseEnv
	if out, err := cmd.CombinedOutput(); err == nil || !strings.Contains(string(out), "UI verification unavailable") {
		t.Fatalf("unexecuted UI accepted: %v %s", err, out)
	}
	for _, value := range []string{`{"status":"pass",`, `[1,2]`, `null`, `{} {}`} {
		path := filepath.Join(repo, "invalid-report.json")
		os.WriteFile(path, []byte(value), 0600)
		cmd := exec.Command(bin, "report", "--in", path)
		cmd.Dir = repo
		if out, err := cmd.CombinedOutput(); err == nil {
			t.Fatalf("invalid report accepted: %s", out)
		}
	}
	path := filepath.Join(repo, "exact-report.json")
	os.WriteFile(path, []byte(`{"counter":9007199254740993}`), 0600)
	cmd = exec.Command(bin, "report", "--in", path)
	if out, err := cmd.CombinedOutput(); err != nil || !strings.Contains(string(out), "9007199254740993") {
		t.Fatalf("report rounded: %v %s", err, out)
	}

}

func TestSelectedPolicyAndRuntimeMetadataRefuseMalformedBytes(t *testing.T) {
	bin := buildBinary(t)
	for _, target := range []string{"pack.yaml", "runtime.json"} {
		repo := setupTestRepo(t)
		path := filepath.Join(repo, target)
		original, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		bad := []byte("rules: [unterminated")
		if target == "runtime.json" {
			bad = []byte(`{"runtimeId":`)
		}
		if err := os.WriteFile(path, bad, 0600); err != nil {
			t.Fatal(err)
		}
		var registry map[string]any
		registryPath := filepath.Join(repo, "registry.json")
		loadJSON(t, registryPath, &registry)
		for _, raw := range registry["entries"].([]any) {
			entry := raw.(map[string]any)
			if entry["ref"] == target {
				entry["digest"] = sha256Path(t, path)
			}
		}
		writeTestJSON(t, registryPath, registry)
		cmd := exec.Command(bin, "verify", "--run-id", "invalid")
		cmd.Dir = repo
		out, err := cmd.CombinedOutput()
		if err == nil || !strings.Contains(string(out), "metadata invalid") {
			t.Fatalf("%s malformed accepted: %v %s", target, err, out)
		}
		os.WriteFile(path, original, 0600)
		for _, raw := range registry["entries"].([]any) {
			entry := raw.(map[string]any)
			if entry["ref"] == target {
				entry["digest"] = sha256Path(t, path)
			}
		}
		writeTestJSON(t, registryPath, registry)
		cmd = exec.Command(bin, "verify", "--run-id", "valid")
		cmd.Dir = repo
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("valid metadata rejected: %v %s", err, out)
		}
		var report map[string]any
		loadJSON(t, filepath.Join(repo, ".cadence/out/valid/pipeline-result.json"), &report)
		found := false
		for _, raw := range report["output"].(map[string]any)["registryDependencies"].([]any) {
			row := raw.(map[string]any)
			if row["ref"] == target {
				found = true
				if row["execution"] != "metadata-only; core uses built-in rules and sandboxRef controls" || row["runtimeCompatibility"] != "not-evaluated-for-execution" {
					t.Fatal("metadata mistaken for executed policy", row)
				}
			}
		}
		if !found {
			t.Fatal("selected dependency missing from result", target)
		}
	}
}

// A single executable exercises the remaining small CLI entrypoint contracts.
func TestReviewedCLIRefusalsAndBaselineControls(t *testing.T) {
	bin := buildBinary(t)
	repo := setupTestRepo(t)
	run := func(args ...string) ([]byte, error) {
		cmd := exec.Command(bin, args...)
		cmd.Dir = repo
		return cmd.CombinedOutput()
	}
	for _, args := range [][]string{{"verify", "--profile", "unknown"}, {"verify", "unexpected"}} {
		if out, err := run(args...); err == nil {
			t.Fatalf("invalid arguments accepted %v: %s", args, out)
		}
	}
	badMode := exec.Command(bin, "verify")
	badMode.Dir = repo
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "CADENCE_") {
			badMode.Env = append(badMode.Env, entry)
		}
	}
	badMode.Env = append(badMode.Env, "CADENCE_SIGNING_MODE=typo")
	if out, err := badMode.CombinedOutput(); err == nil || !strings.Contains(string(out), "CADENCE_SIGNING_MODE must be dev or governed") {
		t.Fatalf("unknown signing mode accepted: %v %s", err, out)
	}
	if out, err := run("adopt", "--help"); err != nil {
		t.Fatalf("help: %v %s", err, out)
	}
	if _, err := os.Stat(filepath.Join(repo, ".cadence")); !os.IsNotExist(err) {
		t.Fatal("argument/help request mutated repository", err)
	}
	configPath := filepath.Join(repo, "cadence.yaml")
	original, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(configPath, append(append([]byte{}, original...), []byte("\nui:\n  enabled: true\n")...), 0600)
	if out, err := run("verify", "--run-id", "ui-request"); err == nil || !strings.Contains(string(out), "UI verification unavailable") {
		t.Fatalf("UI request not refused: %v %s", err, out)
	}
	os.WriteFile(configPath, original, 0600)
	if out, err := run("verify", "--run-id", "baseline-default"); err != nil {
		t.Fatalf("implicit absent baseline: %v %s", err, out)
	}
	os.WriteFile(configPath, append(append([]byte{}, original...), []byte("\nbaselinePath: explicit.json\n")...), 0600)
	for _, bad := range []string{"missing", "{}", "not json"} {
		if bad != "missing" {
			os.WriteFile(filepath.Join(repo, "explicit.json"), []byte(bad), 0600)
		}
		if out, err := run("verify", "--run-id", "baseline-"+strings.ReplaceAll(bad, " ", "-")); err == nil || !strings.Contains(string(out), "baseline") {
			t.Fatalf("bad baseline accepted: %v %s", err, out)
		}
	}
	os.WriteFile(filepath.Join(repo, "explicit.json"), []byte(`{"schemaVersion":"1.0.0","fingerprints":[]}`), 0600)
	if out, err := run("verify", "--run-id", "baseline-valid"); err != nil {
		t.Fatalf("valid baseline: %v %s", err, out)
	}
	if out, err := run("lock", "--out", "cadence.lock"); err != nil {
		t.Fatalf("generate lock: %v %s", err, out)
	}
	if out, err := run("lock", "--check", "--out", "cadence.lock"); err != nil {
		t.Fatalf("check generated lock: %v %s", err, out)
	}
	os.WriteFile(filepath.Join(repo, "broken-report.json"), []byte("null"), 0600)
	if out, err := run("report", "--in", "broken-report.json"); err == nil {
		t.Fatalf("bad report accepted: %s", out)
	}
	os.WriteFile(filepath.Join(repo, "large-report.json"), []byte(`{"value":9007199254740993}`), 0600)
	if out, err := run("report", "--in", "large-report.json"); err != nil || !strings.Contains(string(out), "9007199254740993") {
		t.Fatalf("report number changed: %v %s", err, out)
	}
}

func TestExternalBaselineBytesAndRuleMetricsUseActualInputs(t *testing.T) {
	bin := buildBinary(t)
	repo := setupTestRepo(t)
	baselinePath := filepath.Join(t.TempDir(), "external-baseline.json")
	configPath := filepath.Join(repo, "cadence.yaml")
	config, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(baselinePath)
	if err := os.WriteFile(configPath, append(config, []byte("\nbaselinePath: "+string(encoded)+"\n")...), 0600); err != nil {
		t.Fatal(err)
	}
	hashes := []string{}
	for i, body := range []string{`{"schemaVersion":"1.0.0","fingerprints":[]}`, `{"schemaVersion":"1.0.0","fingerprints":["sha256:1111111111111111111111111111111111111111111111111111111111111111"]}`} {
		if err := os.WriteFile(baselinePath, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		run := fmt.Sprintf("baseline-input-%d", i)
		cmd := exec.Command(bin, "verify", "--run-id", run)
		cmd.Dir = repo
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("verify: %v %s", err, out)
		}
		raw, err := os.ReadFile(filepath.Join(repo, ".cadence", "out", run, "input-identity.json"))
		if err != nil {
			t.Fatal(err)
		}
		var identity map[string]any
		if err := json.Unmarshal(raw, &identity); err != nil {
			t.Fatal(err)
		}
		hashes = append(hashes, identity["inputHash"].(string))
		raw, err = os.ReadFile(filepath.Join(repo, ".cadence", "out", run, "report-summary.json"))
		if err != nil {
			t.Fatal(err)
		}
		var report map[string]any
		if err := json.Unmarshal(raw, &report); err != nil {
			t.Fatal(err)
		}
		if report["metrics"].(map[string]any)["rulesEvaluated"].(float64) <= 0 || report["summary"].(map[string]any)["violations"].(float64) != 0 {
			t.Fatal("rule coverage was derived from findings", report)
		}
	}
	if hashes[0] == hashes[1] {
		t.Fatal("external baseline bytes not bound")
	}
}
