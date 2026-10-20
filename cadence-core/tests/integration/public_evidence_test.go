package integration

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AzzCraft/cadence-oss/cadence-core/internal/evidence"
)

func TestPersistedRejectedPolicyIsRecorded(t *testing.T) {
	bin := buildBinary(t)
	repo := setupTestRepo(t)
	if err := os.WriteFile(filepath.Join(repo, "app.env"), []byte("TEST_AUTH_TOKEN=synthetic-secret-token\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, defect := range []string{"repeated-principal", "unordered-role"} {
		t.Run(defect, func(t *testing.T) {
			record := map[string]any{"reason": "synthetic exception", "ticket": "TEST-WAIVER", "owner": "requester-a", "approvedBy": "approver-d", "createdAt": "2026-10-19T00:00:00Z", "referenceTime": "2026-10-19T00:00:00Z", "signature": "metadata-only", "scope": "profile"}
			entries := []map[string]any{}
			for i, role := range []string{"requester", "manager", "security", "approver"} {
				entries = append(entries, map[string]any{"role": role, "identity": []string{"requester-a", "manager-b", "security-c", "approver-d"}[i], "timestamp": record["referenceTime"]})
			}
			if defect == "repeated-principal" {
				entries[2]["identity"] = entries[1]["identity"]
			} else {
				entries[1]["role"] = "security"
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
			if err == nil || !strings.Contains(string(out), "distinct principals and ordered roles") {
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
			if delivery["deliveryComplete"] != false || summary["deliveryComplete"] != false || summary["decision"] != "pass" {
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
