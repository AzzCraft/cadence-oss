package integration

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/AzzCraft/cadence-oss/cadence-core/internal/signing"
)

// buildBinary compiles the cadence CLI binary and returns the path.
func buildBinary(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "cadence")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	cmd := exec.Command("go", "build", "-buildvcs=false", "-o", bin, "./cmd/cadence")
	cmd.Dir = coreRoot(t)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to build cadence binary: %v\n%s", err, out)
	}
	return bin
}

// coreRoot is relative to this Go test package, independent of checkout name.
func coreRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Clean(filepath.Join(dir, "..", ".."))
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("cannot locate cadence-core from integration test directory: %v", err)
	}
	return root
}

// setupTestRepo creates a minimal repo structure with cadence.yaml and supporting files.
func setupTestRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	// sandbox_profile.json
	writeTestJSON(t, filepath.Join(dir, "sandbox.json"), map[string]any{
		"schemaVersion": "1.0.0",
		"sandboxId":     "test-sandbox",
		"allowedEnv":    []string{"PYTHONDONTWRITEBYTECODE"},
		"filesystem":    "workspace-only",
		"networkAccess": false,
		"timeSource":    "injected",
	})

	// runtime_profile.json
	writeTestJSON(t, filepath.Join(dir, "runtime.json"), map[string]any{
		"schemaVersion": "1.0.0",
		"runtimeId":     "test-runtime",
		"networkAccess": false,
	})
	if err := os.WriteFile(filepath.Join(dir, "pack.yaml"), []byte("id: test-pack\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	writeTestJSON(t, filepath.Join(dir, "suite_lock.json"), map[string]any{
		"schemaVersion": "1.0.0",
	})

	// closure ref — schema-conformant suite version closure artifact
	writeTestJSON(t, filepath.Join(dir, "suite_version_closure.json"), map[string]any{
		"schemaVersion":           "1.0.0",
		"standardVersion":         "1.4.0",
		"standardManifestVersion": "1.4.0",
		"suiteVersion":            "1.0.0",
		"factoryVersion":          "test",
		"verifyRuntimeVersion":    "test",
		"closureUpdatedAt":        "2026-04-10T00:00:00Z",
		"suiteLockRef": map[string]any{
			"kind": "file", "uri": "./suite_lock.json",
			"pinType": "manifest", "pinValue": "suite_lock.json", "floating": false,
		},
		"lockRefs": map[string]any{
			"suiteToolingLock": map[string]any{
				"kind": "file", "uri": "./tooling_lock.json",
				"pinType": "manifest", "pinValue": "tooling_lock.json", "floating": false,
			},
		},
		"refs": map[string]any{
			"standard": map[string]any{
				"kind": "git", "uri": "../das-standard",
				"pinType": "commit", "pinValue": "abc123", "floating": false,
			},
			"suite": map[string]any{
				"kind": "git", "uri": ".",
				"pinType": "commit", "pinValue": "def456", "floating": false,
			},
			"factory": map[string]any{
				"kind": "git", "uri": "../dasops",
				"pinType": "commit", "pinValue": "ghi789", "floating": false,
			},
			"verifyRuntime": map[string]any{
				"kind": "git", "uri": "../cadence-oss",
				"pinType": "commit", "pinValue": "jkl012", "floating": false,
			},
		},
	})

	// tooling_lock.json — schema-conformant and aligned with the closure artifact
	writeTestJSON(t, filepath.Join(dir, "tooling_lock.json"), map[string]any{
		"schemaVersion":           "1.0.0",
		"standardManifestVersion": "1.4.0",
		"sourceOfTruth": map[string]any{
			"kind": "git", "uri": "git@example.com:product.git",
			"pinType": "commit", "pinValue": "repo123", "floating": false,
		},
		"verifyRuntime": map[string]any{
			"kind": "git", "uri": "../cadence-oss",
			"pinType": "commit", "pinValue": "jkl012", "floating": false,
		},
		"suiteVersionClosureRef": map[string]any{
			"kind": "file", "uri": "./suite_version_closure.json",
			"pinType": "manifest", "pinValue": "suite_version_closure.json", "floating": false,
		},
		"suiteLockRef": map[string]any{
			"kind": "file", "uri": "./suite_lock.json",
			"pinType": "manifest", "pinValue": "suite_lock.json", "floating": false,
		},
		"verifyRegistryRef": map[string]any{
			"kind": "file", "uri": "./registry.json",
			"pinType": "manifest", "pinValue": "registry.json", "floating": false,
		},
		"toolchain": []map[string]any{
			{"name": "go", "version": "1.22.x", "manager": "system"},
		},
	})

	// registry.json
	writeTestJSON(t, filepath.Join(dir, "registry.json"), map[string]any{
		"schemaVersion": "1.0.0",
		"registryId":    "test-registry",
		"entries": []map[string]any{
			{
				"kind":              "policyPack",
				"id":                "test-pack",
				"ref":               "pack.yaml",
				"status":            "active",
				"deprecatedAt":      nil,
				"deprecationReason": nil,
				"compatWindow":      "current",
				"digest":            sha256Path(t, filepath.Join(dir, "pack.yaml")),
				"trust": map[string]any{
					"signer":      "cadence-test",
					"allowlisted": true,
				},
			},
			{
				"kind":              "runtimeProfile",
				"id":                "test-runtime",
				"ref":               "runtime.json",
				"status":            "active",
				"deprecatedAt":      nil,
				"deprecationReason": nil,
				"compatWindow":      "current",
				"digest":            sha256Path(t, filepath.Join(dir, "runtime.json")),
				"trust": map[string]any{
					"signer":      "cadence-test",
					"allowlisted": true,
				},
			},
			{
				"kind":              "sandboxProfile",
				"id":                "test-sandbox",
				"ref":               "sandbox.json",
				"status":            "active",
				"deprecatedAt":      nil,
				"deprecationReason": nil,
				"compatWindow":      "current",
				"digest":            sha256Path(t, filepath.Join(dir, "sandbox.json")),
				"trust": map[string]any{
					"signer":      "cadence-test",
					"allowlisted": true,
				},
			},
		},
	})

	// cadence.yaml
	yaml := `projectId: integration-test
mode: strict_offline
closureRef: suite_version_closure.json
toolingLock: tooling_lock.json
runtimeRef: runtime.json
registryRef: registry.json
sandboxRef: sandbox.json
policies:
  - test-pack
`
	if err := os.WriteFile(filepath.Join(dir, "cadence.yaml"), []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}

	return dir
}

func writeTestJSON(t *testing.T, path string, v any) {
	t.Helper()
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeRuntimeAdapterScript(t *testing.T, dir string, response string) string {
	t.Helper()
	path := filepath.Join(dir, "runtime-adapter.sh")
	body := "#!/bin/sh\ncat <<'EOF'\n" + response + "\nEOF\n"
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func configureRuntimeBackend(t *testing.T, repo, backend, filesystemMode string) {
	t.Helper()
	writeTestJSON(t, filepath.Join(repo, "sandbox.json"), map[string]any{
		"schemaVersion": "1.0.0",
		"sandboxId":     "test-sandbox",
		"backend":       backend,
		"allowedEnv":    []string{"PYTHONDONTWRITEBYTECODE"},
		"filesystem": map[string]any{
			"mode":              filesystemMode,
			"readOnlyInputs":    true,
			"writableOutputDir": "/workspace/.cadence/out",
		},
		"network": map[string]any{
			"access": false,
		},
		"resources": map[string]any{
			"cpuLimit":       2,
			"memoryLimitMB":  1024,
			"pidsLimit":      128,
			"timeoutSeconds": 60,
		},
		"timeSource": "injected",
	})
	writeTestJSON(t, filepath.Join(repo, "registry.json"), map[string]any{
		"schemaVersion": "1.0.0",
		"registryId":    "test-registry",
		"entries": []map[string]any{
			{
				"kind":              "policyPack",
				"id":                "test-pack",
				"ref":               "pack.yaml",
				"status":            "active",
				"deprecatedAt":      nil,
				"deprecationReason": nil,
				"compatWindow":      "current",
				"digest":            sha256Path(t, filepath.Join(repo, "pack.yaml")),
				"trust": map[string]any{
					"signer":      "cadence-test",
					"allowlisted": true,
				},
			},
			{
				"kind":              "runtimeProfile",
				"id":                "test-runtime",
				"ref":               "runtime.json",
				"status":            "active",
				"deprecatedAt":      nil,
				"deprecationReason": nil,
				"compatWindow":      "current",
				"digest":            sha256Path(t, filepath.Join(repo, "runtime.json")),
				"trust": map[string]any{
					"signer":      "cadence-test",
					"allowlisted": true,
				},
			},
			{
				"kind":              "sandboxProfile",
				"id":                "test-sandbox",
				"ref":               "sandbox.json",
				"status":            "active",
				"deprecatedAt":      nil,
				"deprecationReason": nil,
				"compatWindow":      "current",
				"digest":            sha256Path(t, filepath.Join(repo, "sandbox.json")),
				"trust": map[string]any{
					"signer":      "cadence-test",
					"allowlisted": true,
				},
			},
		},
	})
}

func sha256Path(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	return "sha256:" + fmt.Sprintf("%x", sum[:])
}

// TestFullVerifyFlow exercises the complete verify pipeline:
// config load → checks → evidence generation → chain → replay package.
func TestFullVerifyFlow(t *testing.T) {
	bin := buildBinary(t)
	repo := setupTestRepo(t)
	outDir := filepath.Join(repo, ".cadence", "out")

	cmd := exec.Command(bin, "verify", "--run-id", "test-run", "--out", outDir)
	cmd.Dir = repo
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("verify failed: %v\n%s", err, output)
	}

	runDir := filepath.Join(outDir, "test-run")

	// Assert all expected evidence artifacts exist.
	expectedFiles := []string{
		"input-identity.json",
		"isolation-probe.json",
		"key-hierarchy.json",
		"run-manifest.json",
		"run-manifest.canonical.json",
		"pipeline-result.json",
		"pipeline-result.canonical.json",
		"job-envelope.json",
		"job-envelope.canonical.json",
		"audit-telemetry.json",
		"deterministic-evidence.json",
		"step-hash-chain.json",
		"replay-package.json",
		"replay-bundle.json",
		"sandbox-result.json",
		"offline-attestation.json",
		"report-summary.json",
		"summary.json",
		"summary.md",
		"cadence-report.json",
	}
	for _, f := range expectedFiles {
		path := filepath.Join(runDir, f)
		if _, err := os.Stat(path); err != nil {
			t.Errorf("missing evidence artifact: %s", f)
		}
	}

	replayPackage := filepath.Join(runDir, "replay-package.json")
	replayBundle := filepath.Join(runDir, "replay-bundle.json")
	left, err := os.ReadFile(replayPackage)
	if err != nil {
		t.Fatalf("failed to read replay-package.json: %v", err)
	}
	right, err := os.ReadFile(replayBundle)
	if err != nil {
		t.Fatalf("failed to read replay-bundle.json: %v", err)
	}
	if string(left) != string(right) {
		t.Error("replay-package.json and replay-bundle.json diverged; expected compatibility alias copy")
	}

	// Validate run-manifest.json schema fields.
	var manifest map[string]any
	loadJSON(t, filepath.Join(runDir, "run-manifest.json"), &manifest)
	requireField(t, manifest, "schemaVersion", "run-manifest")
	requireField(t, manifest, "runId", "run-manifest")
	requireField(t, manifest, "pipeline", "run-manifest")
	requireField(t, manifest, "config", "run-manifest")
	requireField(t, manifest, "inputRef", "run-manifest")
	diagnostics, ok := manifest["diagnostics"].(map[string]any)
	if !ok {
		t.Fatalf("run-manifest diagnostics missing or wrong type")
	}
	kv, ok := diagnostics["kv"].(map[string]any)
	if !ok {
		t.Fatalf("run-manifest diagnostics.kv missing or wrong type")
	}
	if _, ok := kv["dependencyHash"]; !ok {
		t.Fatal("run-manifest diagnostics.kv missing dependencyHash")
	}
	if _, ok := kv["inputIdentityHash"]; !ok {
		t.Fatal("run-manifest diagnostics.kv missing inputIdentityHash")
	}
	if manifest["runId"] != "test-run" {
		t.Errorf("run-manifest runId: got %v, want test-run", manifest["runId"])
	}

	// Validate pipeline-result.json.
	var result map[string]any
	loadJSON(t, filepath.Join(runDir, "pipeline-result.json"), &result)
	requireField(t, result, "schemaVersion", "pipeline-result")
	requireField(t, result, "status", "pipeline-result")
	requireField(t, result, "output", "pipeline-result")
	if warnings, ok := result["warnings"]; ok {
		if _, ok := warnings.([]any); !ok {
			t.Fatalf("pipeline-result warnings has wrong type: %T", warnings)
		}
	}

	// Validate job-envelope.json.
	var job map[string]any
	loadJSON(t, filepath.Join(runDir, "job-envelope.json"), &job)
	requireField(t, job, "schemaVersion", "job-envelope")
	requireField(t, job, "jobId", "job-envelope")
	requireField(t, job, "status", "job-envelope")
	requireField(t, job, "runs", "job-envelope")
	for _, name := range []string{
		"run-manifest.json",
		"pipeline-result.json",
		"job-envelope.json",
		"run-manifest.canonical.json",
		"pipeline-result.canonical.json",
		"job-envelope.canonical.json",
	} {
		payloadBytes, err := os.ReadFile(filepath.Join(runDir, name))
		if err != nil {
			t.Fatalf("failed to read %s: %v", name, err)
		}
		var payload any
		if err := json.Unmarshal(payloadBytes, &payload); err != nil {
			t.Fatalf("failed to decode %s: %v", name, err)
		}
		for _, forbiddenKey := range []string{"createdAt", "updatedAt", "startedAt", "finishedAt", "elapsedMs", "timeMs"} {
			if hasJSONKey(payload, forbiddenKey) {
				t.Fatalf("%s unexpectedly contains key %q", name, forbiddenKey)
			}
		}
	}

	deterministicBytes, err := os.ReadFile(filepath.Join(runDir, "deterministic-evidence.json"))
	if err != nil {
		t.Fatalf("failed to read deterministic-evidence.json: %v", err)
	}
	var deterministic map[string]any
	if err := json.Unmarshal(deterministicBytes, &deterministic); err != nil {
		t.Fatalf("failed to decode deterministic-evidence.json: %v", err)
	}
	for _, forbiddenKey := range []string{"createdAt", "startedAt", "finishedAt", "elapsedMs", "timeMs"} {
		if hasJSONKey(deterministic, forbiddenKey) {
			t.Fatalf("deterministic-evidence.json unexpectedly contains key %q", forbiddenKey)
		}
	}
	if deterministic["isolationProbeRef"] != "isolation-probe.json" {
		t.Fatalf("deterministic-evidence isolationProbeRef = %v, want isolation-probe.json", deterministic["isolationProbeRef"])
	}

	var isolationProbe map[string]any
	loadJSON(t, filepath.Join(runDir, "isolation-probe.json"), &isolationProbe)

	var sandboxResult map[string]any
	loadJSON(t, filepath.Join(runDir, "sandbox-result.json"), &sandboxResult)
	for _, key := range []string{"schemaVersion", "profileId", "backend", "mode", "isolationLevel", "command", "workDir", "networkAccess", "checks", "passed", "status"} {
		requireField(t, sandboxResult, key, "sandbox-result")
	}
	if sandboxResult["isolationProbeRef"] != "isolation-probe.json" {
		t.Fatalf("sandbox-result isolationProbeRef = %v, want isolation-probe.json", sandboxResult["isolationProbeRef"])
	}

	probeHash, _ := isolationProbe["namespaceProofHash"].(string)
	if probeHash != "" {
		if sandboxResult["namespaceProofHash"] != probeHash {
			t.Fatalf("sandbox-result namespaceProofHash = %v, want %s", sandboxResult["namespaceProofHash"], probeHash)
		}
		if deterministic["namespaceProofHash"] != probeHash {
			t.Fatalf("deterministic-evidence namespaceProofHash = %v, want %s", deterministic["namespaceProofHash"], probeHash)
		}
	}
	if proofs, ok := isolationProbe["namespaceProofs"].([]any); ok && len(proofs) > 0 {
		backendEvidence, ok := sandboxResult["backendEvidence"].(map[string]any)
		if !ok {
			t.Fatal("sandbox-result backendEvidence missing despite namespace proofs in isolation-probe")
		}
		if _, ok := backendEvidence["namespaceProofs"]; !ok {
			t.Fatal("sandbox-result backendEvidence missing namespaceProofs")
		}
	}
	backendEvidence, ok := sandboxResult["backendEvidence"].(map[string]any)
	if !ok {
		t.Fatal("sandbox-result backendEvidence missing")
	}
	if backendEvidence["attestationStatus"] != "launcher-only" {
		t.Fatalf("sandbox-result attestationStatus = %v, want launcher-only", backendEvidence["attestationStatus"])
	}
	if _, ok := backendEvidence["observedChecks"]; !ok {
		t.Fatal("sandbox-result backendEvidence missing observedChecks")
	}

	for _, name := range []string{
		"run-manifest.canonical.json",
		"pipeline-result.canonical.json",
		"job-envelope.canonical.json",
	} {
		payloadBytes, err := os.ReadFile(filepath.Join(runDir, name))
		if err != nil {
			t.Fatalf("failed to read %s: %v", name, err)
		}
		var payload any
		if err := json.Unmarshal(payloadBytes, &payload); err != nil {
			t.Fatalf("failed to decode %s: %v", name, err)
		}
		for _, forbiddenKey := range []string{"createdAt", "startedAt", "finishedAt", "elapsedMs", "timeMs"} {
			if hasJSONKey(payload, forbiddenKey) {
				t.Fatalf("%s unexpectedly contains key %q", name, forbiddenKey)
			}
		}

		var inputIdentity map[string]any
		loadJSON(t, filepath.Join(runDir, "input-identity.json"), &inputIdentity)
		requireField(t, inputIdentity, "environmentSpec", "input-identity")
		requireField(t, inputIdentity, "environmentSpecHash", "input-identity")
		requireField(t, inputIdentity, "environmentInputs", "input-identity")
		requireField(t, inputIdentity, "environmentInputsHash", "input-identity")
		envSpec, ok := inputIdentity["environmentSpec"].(map[string]any)
		if !ok {
			t.Fatalf("input-identity environmentSpec missing or wrong type")
		}
		if _, ok := envSpec["goVersion"]; !ok {
			t.Fatal("input-identity environmentSpec missing goVersion")
		}
		if _, ok := envSpec["sandboxParentEnvKeys"]; !ok {
			t.Fatal("input-identity environmentSpec missing sandboxParentEnvKeys")
		}
	}
}

// TestChainIntegrity verifies that the step-hash-chain links are cryptographically valid.
func TestChainIntegrity(t *testing.T) {
	bin := buildBinary(t)
	repo := setupTestRepo(t)
	outDir := filepath.Join(repo, ".cadence", "out")

	cmd := exec.Command(bin, "verify", "--run-id", "chain-test", "--out", outDir)
	cmd.Dir = repo
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("verify failed: %v\n%s", err, out)
	}

	runDir := filepath.Join(outDir, "chain-test")

	var chain struct {
		Steps []struct {
			StepID       string `json:"stepId"`
			InputHash    string `json:"inputHash"`
			OutputHash   string `json:"outputHash"`
			PreviousHash string `json:"previousHash"`
			ChainHash    string `json:"chainHash"`
		} `json:"steps"`
	}
	loadJSON(t, filepath.Join(runDir, "step-hash-chain.json"), &chain)

	if len(chain.Steps) == 0 {
		t.Fatal("chain has no steps")
	}

	zeroHash := "sha256:0000000000000000000000000000000000000000000000000000000000000000"

	// Verify each step: chainHash = sha256(previousHash + ":" + inputHash + ":" + outputHash).
	for i, step := range chain.Steps {
		combined := step.PreviousHash + ":" + step.InputHash + ":" + step.OutputHash
		expected := "sha256:" + sha256Hex(combined)
		if step.ChainHash != expected {
			t.Errorf("chain step %d (%s): chainHash mismatch\n  got:  %s\n  want: %s",
				i, step.StepID, step.ChainHash, expected)
		}
		// Verify chain linkage.
		if i == 0 {
			if step.PreviousHash != zeroHash {
				t.Errorf("chain step 0: previousHash should be zero hash, got %s", step.PreviousHash)
			}
		} else {
			if step.PreviousHash != chain.Steps[i-1].ChainHash {
				t.Errorf("chain step %d: previousHash does not link to step %d chainHash", i, i-1)
			}
		}
	}
}

// TestDeterminism replays an explicit run identity in independent output roots.
// Default invocations allocate distinct attempts; their stable input identity is
// checked separately by TestPublicNativeEvidenceRoundTripAndRefusal.
func TestDeterminism(t *testing.T) {
	bin := buildBinary(t)
	repo := setupTestRepo(t)
	outDir1 := filepath.Join(repo, "out-a")
	outDir2 := filepath.Join(repo, "out-b")
	runID := "deterministic-replay"

	// First run.
	cmd1 := exec.Command(bin, "verify", "--run-id", runID, "--out", outDir1, "--alias", "")
	cmd1.Dir = repo
	cmd1.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1")
	if out, err := cmd1.CombinedOutput(); err != nil {
		t.Fatalf("verify run 1 failed: %v\n%s", err, out)
	}

	// Second run.
	cmd2 := exec.Command(bin, "verify", "--run-id", runID, "--out", outDir2, "--alias", "")
	cmd2.Dir = repo
	cmd2.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1")
	if out, err := cmd2.CombinedOutput(); err != nil {
		t.Fatalf("verify run 2 failed: %v\n%s", err, out)
	}

	runDir1 := singleRunDir(t, outDir1)
	runDir2 := singleRunDir(t, outDir2)

	// Compare: run identity, configHash, and inputHash should be identical across runs.
	var m1, m2 map[string]any
	loadJSON(t, filepath.Join(runDir1, "run-manifest.json"), &m1)
	loadJSON(t, filepath.Join(runDir2, "run-manifest.json"), &m2)

	runID1 := m1["runId"]
	runID2 := m2["runId"]
	if runID1 != runID || runID2 != runID {
		t.Fatalf("determinism: explicit runId %q not preserved: %v vs %v", runID, runID1, runID2)
	}

	cfg1 := m1["config"].(map[string]any)["configHash"]
	cfg2 := m2["config"].(map[string]any)["configHash"]
	if cfg1 != cfg2 {
		t.Errorf("determinism: configHash differs between runs: %v vs %v", cfg1, cfg2)
	}

	inp1 := m1["inputRef"].(map[string]any)["inputHash"]
	inp2 := m2["inputRef"].(map[string]any)["inputHash"]
	if inp1 != inp2 {
		t.Errorf("determinism: inputHash differs between runs: %v vs %v", inp1, inp2)
	}

	for _, rel := range []string{
		"run-manifest.json",
		"run-manifest.canonical.json",
		"pipeline-result.json",
		"pipeline-result.canonical.json",
		"job-envelope.json",
		"job-envelope.canonical.json",
		"deterministic-evidence.json",
		"step-hash-chain.json",
		"replay-package.json",
	} {
		left, err := os.ReadFile(filepath.Join(runDir1, rel))
		if err != nil {
			t.Fatalf("read %s run1: %v", rel, err)
		}
		right, err := os.ReadFile(filepath.Join(runDir2, rel))
		if err != nil {
			t.Fatalf("read %s run2: %v", rel, err)
		}
		if string(left) != string(right) {
			t.Fatalf("determinism: %s differs between runs", rel)
		}
	}

	var replay1, replay2 map[string]any
	loadJSON(t, filepath.Join(runDir1, "replay-package.json"), &replay1)
	loadJSON(t, filepath.Join(runDir2, "replay-package.json"), &replay2)
	if replay1["bundleHash"] != replay2["bundleHash"] {
		t.Fatalf("determinism: bundleHash differs between runs: %v vs %v", replay1["bundleHash"], replay2["bundleHash"])
	}
}

// TestSignatureVerification runs verify with a signing key and validates the signature.
func TestSignatureVerification(t *testing.T) {
	bin := buildBinary(t)
	repo := setupTestRepo(t)
	outDir := filepath.Join(repo, ".cadence", "out")

	cmd := exec.Command(bin, "verify", "--run-id", "sig-test", "--out", outDir)
	cmd.Dir = repo
	cmd.Env = append(os.Environ(), "CADENCE_SIGNING_KEY=test-signing-key-32bytes-long!!")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("verify failed: %v\n%s", err, out)
	}

	runDir := filepath.Join(outDir, "sig-test")

	// Signature file should exist when signing key is set.
	sigPath := filepath.Join(runDir, "manifest-signature.json")
	if _, err := os.Stat(sigPath); err != nil {
		t.Fatal("manifest-signature.json not created when CADENCE_SIGNING_KEY is set")
	}

	var sig map[string]any
	loadJSON(t, sigPath, &sig)
	requireField(t, sig, "signatureId", "signature")
	requireField(t, sig, "algorithm", "signature")
	requireField(t, sig, "payloadHash", "signature")
	requireField(t, sig, "signature", "signature")

	if sig["algorithm"] != "hmac-sha256" {
		t.Errorf("signature algorithm: got %v, want hmac-sha256", sig["algorithm"])
	}
}

func TestGovernedSignatureVerification(t *testing.T) {
	bin := buildBinary(t)
	repo := setupTestRepo(t)
	outDir := filepath.Join(repo, ".cadence", "out")

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	privateKeyPath := filepath.Join(repo, "governed-signing.key")
	publicKeyPath := filepath.Join(repo, "governed-signing.pub")
	if err := os.WriteFile(privateKeyPath, priv, 0o600); err != nil {
		t.Fatalf("write private key: %v", err)
	}
	if err := os.WriteFile(publicKeyPath, pub, 0o644); err != nil {
		t.Fatalf("write public key: %v", err)
	}

	cmd := exec.Command(bin, "verify", "--run-id", "governed-sig-test", "--out", outDir)
	cmd.Dir = repo
	cmd.Env = append(
		os.Environ(),
		"CADENCE_SIGNING_MODE=governed",
		"CADENCE_ROOT_ANCHOR=hsm://tenant/root-key",
		"CADENCE_GOVERNED_SIGNING_PRIVATE_KEY_FILE="+privateKeyPath,
		"CADENCE_GOVERNED_SIGNING_PUBLIC_KEY_FILE="+publicKeyPath,
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("verify failed: %v\n%s", err, out)
	}

	runDir := filepath.Join(outDir, "governed-sig-test")

	var keyHierarchy map[string]any
	loadJSON(t, filepath.Join(runDir, "key-hierarchy.json"), &keyHierarchy)
	if keyHierarchy["depth"] != float64(3) {
		t.Fatalf("key-hierarchy depth = %v, want 3", keyHierarchy["depth"])
	}
	if keyHierarchy["rootAnchor"] != "hsm://tenant/root-key" {
		t.Fatalf("key-hierarchy rootAnchor = %v, want hsm://tenant/root-key", keyHierarchy["rootAnchor"])
	}

	var hsmAnchor map[string]any
	loadJSON(t, filepath.Join(runDir, "hsm-anchor.json"), &hsmAnchor)
	if hsmAnchor["status"] != "active" {
		t.Fatalf("hsm-anchor status = %v, want active", hsmAnchor["status"])
	}
	if hsmAnchor["provider"] != "software-ed25519" {
		t.Fatalf("hsm-anchor provider = %v, want verified local software-ed25519", hsmAnchor["provider"])
	}

	if hsmAnchor["hardwareBacked"] != false {
		t.Fatal("local key incorrectly claimed hardware")
	}

	var detached signing.DetachedSignature
	detachedBytes, err := os.ReadFile(filepath.Join(runDir, "run-manifest.json.signature.json"))
	if err != nil {
		t.Fatalf("read detached signature: %v", err)
	}
	if err := json.Unmarshal(detachedBytes, &detached); err != nil {
		t.Fatalf("unmarshal detached signature: %v", err)
	}
	if detached.Algorithm != "ed25519" {
		t.Fatalf("detached signature algorithm = %s, want ed25519", detached.Algorithm)
	}
	verifier := &signing.Ed25519VerifierOnly{PublicKey: pub, ID: detached.KeyID, IssuerID: detached.Issuer}
	manifestPayload, err := os.ReadFile(filepath.Join(runDir, "run-manifest.json"))
	if err != nil {
		t.Fatalf("read run-manifest.json: %v", err)
	}
	if err := signing.VerifyDetachedSignature(detached, verifier, manifestPayload); err != nil {
		t.Fatalf("VerifyDetachedSignature: %v", err)
	}

	var dual signing.DualLayerSignature
	bundleBytes, err := os.ReadFile(filepath.Join(runDir, "bundle-signature.json"))
	if err != nil {
		t.Fatalf("read bundle signature: %v", err)
	}
	if err := json.Unmarshal(bundleBytes, &dual); err != nil {
		t.Fatalf("unmarshal bundle signature: %v", err)
	}
	if dual.BundleLayer.Algorithm != "ed25519" {
		t.Fatalf("bundle signature algorithm = %s, want ed25519", dual.BundleLayer.Algorithm)
	}
	if err := signing.VerifyDualLayerSignature(dual, verifier); err != nil {
		t.Fatalf("VerifyDualLayerSignature: %v", err)
	}
}

func TestConfiguredURIWithoutSignerProducesNoHardwareAnchor(t *testing.T) {
	bin := buildBinary(t)
	repo := setupTestRepo(t)
	outDir := filepath.Join(repo, ".cadence", "out")
	cmd := exec.Command(bin, "verify", "--run-id", "configured-only", "--out", outDir)
	cmd.Dir = repo
	cmd.Env = append(os.Environ(), "CADENCE_SIGNING_MODE=dev", "CADENCE_SIGNING_KEY=", "CADENCE_ROOT_ANCHOR=hsm://synthetic/no-device")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("verify failed: %v\n%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(outDir, "configured-only", "hsm-anchor.json")); !os.IsNotExist(err) {
		t.Fatal("URI configuration fabricated an active anchor")
	}
}

func TestDevModeExplicitlyOptInToSoftwareHmac(t *testing.T) {
	bin := buildBinary(t)
	repo := setupTestRepo(t)
	outDir := filepath.Join(repo, ".cadence", "out")

	cmd := exec.Command(bin, "verify", "--run-id", "dev-hmac-test", "--out", outDir)
	cmd.Dir = repo
	cmd.Env = append(
		os.Environ(),
		"CADENCE_SIGNING_MODE=dev",
		"CADENCE_SIGNING_KEY=test-signing-key-32bytes-long!!",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("verify failed: %v\n%s", err, out)
	}

	runDir := filepath.Join(outDir, "dev-hmac-test")
	var hsmAnchor map[string]any
	loadJSON(t, filepath.Join(runDir, "hsm-anchor.json"), &hsmAnchor)
	if hsmAnchor["status"] != "active" {
		t.Fatalf("hsm-anchor status = %v, want active", hsmAnchor["status"])
	}
	if hsmAnchor["provider"] != "software-hmac" {
		t.Fatalf("hsm-anchor provider = %v, want software-hmac", hsmAnchor["provider"])
	}
	if hsmAnchor["hardwareBacked"] != false {
		t.Fatalf("hsm-anchor hardwareBacked = %v, want false", hsmAnchor["hardwareBacked"])
	}

	var sig map[string]any
	loadJSON(t, filepath.Join(runDir, "manifest-signature.json"), &sig)
	if sig["algorithm"] != "hmac-sha256" {
		t.Fatalf("manifest-signature algorithm = %v, want hmac-sha256", sig["algorithm"])
	}
}

func TestBreakGlassWritesWaiverAuditTrail(t *testing.T) {
	bin := buildBinary(t)
	repo := setupTestRepo(t)
	outDir := filepath.Join(repo, ".cadence", "out")
	if err := os.WriteFile(filepath.Join(repo, "app.env"), []byte("TEST_AUTH_TOKEN=super-secret-token\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(
		bin,
		"verify",
		"--run-id", "break-glass-test",
		"--out", outDir,
		"--break-glass",
		"--reason", "temporary operator override",
		"--ticket", "OPS-123",
		"--waiver-approved-by", "release-manager",
		"--waiver-reference-time", "2026-04-15T00:00:00Z",
		"--waiver-expires-at", "2026-04-20T00:00:00Z",
		"--waiver-signature", "unsigned-local-break-glass",
	)
	cmd.Dir = repo
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("verify failed unexpectedly: %v\n%s", err, output)
	}

	runDir := filepath.Join(outDir, "break-glass-test")
	for _, name := range []string{"waiver.json", "approval-chain.json", "waiver-audit-trail.json"} {
		if _, err := os.Stat(filepath.Join(runDir, name)); err != nil {
			t.Fatalf("missing waiver evidence artifact %s: %v", name, err)
		}
	}

	var trail map[string]any
	loadJSON(t, filepath.Join(runDir, "waiver-audit-trail.json"), &trail)
	if trail["scope"] != "profile" {
		t.Fatalf("expected profile scope, got %v", trail["scope"])
	}
	if trail["escalationLevel"] != "tier2" {
		t.Fatalf("expected tier2 escalation level, got %v", trail["escalationLevel"])
	}
	if trail["compliant"] != false {
		t.Fatalf("expected non-compliant operator-surface trail, got %v", trail["compliant"])
	}
	decisions, ok := trail["decisions"].([]any)
	if !ok || len(decisions) == 0 {
		t.Fatalf("expected decisions array, got %v", trail["decisions"])
	}
	if !containsSubstring(string(output), "waiver escalation warning") {
		t.Fatalf("expected escalation warning in output, got %s", output)
	}
}

func TestVerifyUsesPersistedWaiverAndApprovalChain(t *testing.T) {
	bin := buildBinary(t)
	repo := setupTestRepo(t)
	outDir := filepath.Join(repo, ".cadence", "out")
	if err := os.WriteFile(filepath.Join(repo, "app.env"), []byte("TEST_AUTH_TOKEN=super-secret-token\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	writeTestJSON(t, filepath.Join(repo, "waivers.json"), map[string]any{
		"schemaVersion": "1.0.0",
		"waivers": []map[string]any{
			{
				"reason":        "approved external override",
				"ticket":        "OPS-124",
				"owner":         "integration-test",
				"approvedBy":    "exec-approver",
				"createdAt":     "2026-04-15T00:00:00Z",
				"expiresAt":     "2026-04-20T00:00:00Z",
				"referenceTime": "2026-04-15T00:00:00Z",
				"signature":     "signed-external-approval",
				"scope":         "profile",
			},
		},
	})
	writeTestJSON(t, filepath.Join(repo, "approval-chain-input.json"), map[string]any{
		"waiverTicket": "OPS-124",
		"entries": []map[string]any{
			{"role": "requester", "identity": "integration-test", "timestamp": "2026-04-15T00:00:00Z"},
			{"role": "manager", "identity": "team-manager", "timestamp": "2026-04-15T00:05:00Z"},
			{"role": "security", "identity": "security-lead", "timestamp": "2026-04-15T00:10:00Z"},
			{"role": "approver", "identity": "exec-approver", "timestamp": "2026-04-15T00:15:00Z"},
		},
		"depth": 4,
	})

	cmd := exec.Command(
		bin,
		"verify",
		"--run-id", "waiver-file-test",
		"--out", outDir,
		"--ticket", "OPS-124",
		"--waiver-file", "waivers.json",
		"--approval-chain-file", "approval-chain-input.json",
	)
	cmd.Dir = repo
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("verify failed unexpectedly: %v\n%s", err, output)
	}

	runDir := filepath.Join(outDir, "waiver-file-test")
	for _, name := range []string{"waiver.json", "approval-chain.json", "waiver-audit-trail.json"} {
		if _, err := os.Stat(filepath.Join(runDir, name)); err != nil {
			t.Fatalf("missing waiver evidence artifact %s: %v", name, err)
		}
	}

	var trail map[string]any
	loadJSON(t, filepath.Join(runDir, "waiver-audit-trail.json"), &trail)
	if trail["scope"] != "profile" {
		t.Fatalf("expected profile scope, got %v", trail["scope"])
	}
	if trail["compliant"] != true {
		t.Fatalf("expected compliant persisted waiver trail, got %v", trail["compliant"])
	}
	if trail["actualChainDepth"] != float64(4) {
		t.Fatalf("expected chain depth 4, got %v", trail["actualChainDepth"])
	}

	var approvalChain map[string]any
	loadJSON(t, filepath.Join(runDir, "approval-chain.json"), &approvalChain)
	if approvalChain["waiverTicket"] != "OPS-124" {
		t.Fatalf("approval-chain waiverTicket = %v, want OPS-124", approvalChain["waiverTicket"])
	}
}

func TestVerifyRejectsLegacyPipelineWaiverScope(t *testing.T) {
	bin := buildBinary(t)
	repo := setupTestRepo(t)
	outDir := filepath.Join(repo, ".cadence", "out")
	if err := os.WriteFile(filepath.Join(repo, "app.env"), []byte("TEST_AUTH_TOKEN=super-secret-token\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	writeTestJSON(t, filepath.Join(repo, "waivers.json"), map[string]any{
		"schemaVersion": "1.0.0",
		"waivers": []map[string]any{
			{
				"reason":        "legacy pipeline scope",
				"ticket":        "OPS-125",
				"owner":         "integration-test",
				"approvedBy":    "exec-approver",
				"createdAt":     "2026-04-15T00:00:00Z",
				"expiresAt":     "2026-04-20T00:00:00Z",
				"referenceTime": "2026-04-15T00:00:00Z",
				"signature":     "signed-external-approval",
				"scope":         "pipeline",
			},
		},
	})
	writeTestJSON(t, filepath.Join(repo, "approval-chain-input.json"), map[string]any{
		"waiverTicket": "OPS-125",
		"entries": []map[string]any{
			{"role": "requester", "identity": "integration-test", "timestamp": "2026-04-15T00:00:00Z"},
			{"role": "manager", "identity": "team-manager", "timestamp": "2026-04-15T00:05:00Z"},
			{"role": "security", "identity": "security-lead", "timestamp": "2026-04-15T00:10:00Z"},
			{"role": "approver", "identity": "exec-approver", "timestamp": "2026-04-15T00:15:00Z"},
		},
		"depth": 4,
	})

	cmd := exec.Command(
		bin,
		"verify",
		"--run-id", "waiver-file-legacy-scope",
		"--out", outDir,
		"--ticket", "OPS-125",
		"--waiver-file", "waivers.json",
		"--approval-chain-file", "approval-chain-input.json",
	)
	cmd.Dir = repo
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected verify to reject legacy pipeline scope\n%s", output)
	}
	if !containsSubstring(string(output), `invalid scope "pipeline"`) {
		t.Fatalf("unexpected verify failure output: %s", output)
	}
}

func TestVerifyFailsWhenRegistryPolicyIsMissing(t *testing.T) {
	bin := buildBinary(t)
	repo := setupTestRepo(t)
	outDir := filepath.Join(repo, ".cadence", "out")

	writeTestJSON(t, filepath.Join(repo, "registry.json"), map[string]any{
		"schemaVersion": "1.0.0",
		"registryId":    "test-registry",
		"entries": []map[string]any{
			{
				"kind":              "runtimeProfile",
				"id":                "test-runtime",
				"ref":               "runtime.json",
				"status":            "active",
				"deprecatedAt":      nil,
				"deprecationReason": nil,
				"compatWindow":      "current",
				"digest":            sha256Path(t, filepath.Join(repo, "runtime.json")),
				"trust": map[string]any{
					"signer":      "cadence-test",
					"allowlisted": true,
				},
			},
			{
				"kind":              "sandboxProfile",
				"id":                "test-sandbox",
				"ref":               "sandbox.json",
				"status":            "active",
				"deprecatedAt":      nil,
				"deprecationReason": nil,
				"compatWindow":      "current",
				"digest":            sha256Path(t, filepath.Join(repo, "sandbox.json")),
				"trust": map[string]any{
					"signer":      "cadence-test",
					"allowlisted": true,
				},
			},
		},
	})

	cmd := exec.Command(bin, "verify", "--run-id", "missing-policy", "--out", outDir)
	cmd.Dir = repo
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected verify to fail when registry policy is missing\n%s", output)
	}
	if !containsSubstring(string(output), "policy registry invalid") {
		t.Fatalf("unexpected verify failure output: %s", output)
	}
}

func TestVerifyDegradesForDeprecatedRegistryDependency(t *testing.T) {
	bin := buildBinary(t)
	repo := setupTestRepo(t)
	outDir := filepath.Join(repo, ".cadence", "out")

	writeTestJSON(t, filepath.Join(repo, "registry.json"), map[string]any{
		"schemaVersion": "1.0.0",
		"registryId":    "test-registry",
		"entries": []map[string]any{
			{
				"kind":              "policyPack",
				"id":                "test-pack",
				"ref":               "pack.yaml",
				"status":            "deprecated",
				"digest":            sha256Path(t, filepath.Join(repo, "pack.yaml")),
				"deprecatedAt":      "2026-04-13T00:00:00Z",
				"deprecationReason": "use test-pack-v2",
				"compatWindow":      "until 2027-06-01",
				"trust": map[string]any{
					"signer":      "cadence-test",
					"allowlisted": true,
				},
			},
			{
				"kind":              "runtimeProfile",
				"id":                "test-runtime",
				"ref":               "runtime.json",
				"status":            "active",
				"deprecatedAt":      nil,
				"deprecationReason": nil,
				"compatWindow":      "current",
				"digest":            sha256Path(t, filepath.Join(repo, "runtime.json")),
				"trust": map[string]any{
					"signer":      "cadence-test",
					"allowlisted": true,
				},
			},
			{
				"kind":              "sandboxProfile",
				"id":                "test-sandbox",
				"ref":               "sandbox.json",
				"status":            "active",
				"deprecatedAt":      nil,
				"deprecationReason": nil,
				"compatWindow":      "current",
				"digest":            sha256Path(t, filepath.Join(repo, "sandbox.json")),
				"trust": map[string]any{
					"signer":      "cadence-test",
					"allowlisted": true,
				},
			},
		},
	})

	cmd := exec.Command(bin, "verify", "--run-id", "deprecated-policy", "--out", outDir)
	cmd.Dir = repo
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("verify failed unexpectedly: %v\n%s", err, output)
	}

	var result map[string]any
	loadJSON(t, filepath.Join(outDir, "deprecated-policy", "pipeline-result.json"), &result)
	if result["status"] != "degraded" {
		t.Fatalf("expected degraded pipeline status, got %v", result["status"])
	}
	warnings, ok := result["warnings"].([]any)
	if !ok || len(warnings) == 0 {
		t.Fatalf("expected registry deprecation warning, got %v", result["warnings"])
	}
}

func TestVerifyFailsWhenRegistryTrustIsNotAllowlisted(t *testing.T) {
	bin := buildBinary(t)
	repo := setupTestRepo(t)
	outDir := filepath.Join(repo, ".cadence", "out")

	writeTestJSON(t, filepath.Join(repo, "registry.json"), map[string]any{
		"schemaVersion": "1.0.0",
		"registryId":    "test-registry",
		"entries": []map[string]any{
			{
				"kind":              "policyPack",
				"id":                "test-pack",
				"ref":               "pack.yaml",
				"status":            "active",
				"deprecatedAt":      nil,
				"deprecationReason": nil,
				"compatWindow":      "current",
				"digest":            sha256Path(t, filepath.Join(repo, "pack.yaml")),
				"trust": map[string]any{
					"signer":      "unknown",
					"allowlisted": false,
				},
			},
			{
				"kind":              "runtimeProfile",
				"id":                "test-runtime",
				"ref":               "runtime.json",
				"status":            "active",
				"deprecatedAt":      nil,
				"deprecationReason": nil,
				"compatWindow":      "current",
				"digest":            sha256Path(t, filepath.Join(repo, "runtime.json")),
				"trust": map[string]any{
					"signer":      "cadence-test",
					"allowlisted": true,
				},
			},
			{
				"kind":              "sandboxProfile",
				"id":                "test-sandbox",
				"ref":               "sandbox.json",
				"status":            "active",
				"deprecatedAt":      nil,
				"deprecationReason": nil,
				"compatWindow":      "current",
				"digest":            sha256Path(t, filepath.Join(repo, "sandbox.json")),
				"trust": map[string]any{
					"signer":      "cadence-test",
					"allowlisted": true,
				},
			},
		},
	})

	cmd := exec.Command(bin, "verify", "--run-id", "trust-fail", "--out", outDir)
	cmd.Dir = repo
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected verify to fail for non-allowlisted trust\n%s", output)
	}
	if !containsSubstring(string(output), "not allowlisted") {
		t.Fatalf("unexpected verify failure output: %s", output)
	}
}

func TestVerifyFailsWhenDeprecatedRuntimeUsesCurrentCompatWindow(t *testing.T) {
	bin := buildBinary(t)
	repo := setupTestRepo(t)
	outDir := filepath.Join(repo, ".cadence", "out")

	writeTestJSON(t, filepath.Join(repo, "registry.json"), map[string]any{
		"schemaVersion": "1.0.0",
		"registryId":    "test-registry",
		"entries": []map[string]any{
			{
				"kind":              "policyPack",
				"id":                "test-pack",
				"ref":               "pack.yaml",
				"status":            "active",
				"deprecatedAt":      nil,
				"deprecationReason": nil,
				"compatWindow":      "current",
				"digest":            sha256Path(t, filepath.Join(repo, "pack.yaml")),
				"trust": map[string]any{
					"signer":      "cadence-test",
					"allowlisted": true,
				},
			},
			{
				"kind":              "runtimeProfile",
				"id":                "test-runtime",
				"ref":               "runtime.json",
				"status":            "deprecated",
				"deprecatedAt":      "2026-04-13T00:00:00Z",
				"deprecationReason": "migrate runtime",
				"compatWindow":      "current",
				"digest":            sha256Path(t, filepath.Join(repo, "runtime.json")),
				"trust": map[string]any{
					"signer":      "cadence-test",
					"allowlisted": true,
				},
			},
			{
				"kind":              "sandboxProfile",
				"id":                "test-sandbox",
				"ref":               "sandbox.json",
				"status":            "active",
				"deprecatedAt":      nil,
				"deprecationReason": nil,
				"compatWindow":      "current",
				"digest":            sha256Path(t, filepath.Join(repo, "sandbox.json")),
				"trust": map[string]any{
					"signer":      "cadence-test",
					"allowlisted": true,
				},
			},
		},
	})

	cmd := exec.Command(bin, "verify", "--run-id", "runtime-compat-invalid", "--out", outDir)
	cmd.Dir = repo
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected verify to fail when deprecated runtime uses current compatWindow\n%s", output)
	}
	if !containsSubstring(string(output), "compatWindow") {
		t.Fatalf("unexpected verify failure output: %s", output)
	}
}

func TestVerifyFailsWhenDeprecatedRuntimeCompatWindowHasExpired(t *testing.T) {
	bin := buildBinary(t)
	repo := setupTestRepo(t)
	outDir := filepath.Join(repo, ".cadence", "out")

	writeTestJSON(t, filepath.Join(repo, "registry.json"), map[string]any{
		"schemaVersion": "1.0.0",
		"registryId":    "test-registry",
		"entries": []map[string]any{
			{
				"kind":              "policyPack",
				"id":                "test-pack",
				"ref":               "pack.yaml",
				"status":            "active",
				"deprecatedAt":      nil,
				"deprecationReason": nil,
				"compatWindow":      "current",
				"digest":            sha256Path(t, filepath.Join(repo, "pack.yaml")),
				"trust": map[string]any{
					"signer":      "cadence-test",
					"allowlisted": true,
				},
			},
			{
				"kind":              "runtimeProfile",
				"id":                "test-runtime",
				"ref":               "runtime.json",
				"status":            "deprecated",
				"deprecatedAt":      "2026-04-13T00:00:00Z",
				"deprecationReason": "migrate runtime",
				"compatWindow":      "until 2026-04-14",
				"digest":            sha256Path(t, filepath.Join(repo, "runtime.json")),
				"trust": map[string]any{
					"signer":      "cadence-test",
					"allowlisted": true,
				},
			},
			{
				"kind":              "sandboxProfile",
				"id":                "test-sandbox",
				"ref":               "sandbox.json",
				"status":            "active",
				"deprecatedAt":      nil,
				"deprecationReason": nil,
				"compatWindow":      "current",
				"digest":            sha256Path(t, filepath.Join(repo, "sandbox.json")),
				"trust": map[string]any{
					"signer":      "cadence-test",
					"allowlisted": true,
				},
			},
		},
	})

	cmd := exec.Command(bin, "verify", "--run-id", "runtime-expired", "--out", outDir)
	cmd.Dir = repo
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected verify to fail when runtime compatWindow has expired\n%s", output)
	}
	if !containsSubstring(string(output), "reference time") {
		t.Fatalf("unexpected verify failure output: %s", output)
	}
}

func TestVerifyFailsWhenDeprecatedSandboxCompatWindowHasExpired(t *testing.T) {
	bin := buildBinary(t)
	repo := setupTestRepo(t)
	outDir := filepath.Join(repo, ".cadence", "out")

	writeTestJSON(t, filepath.Join(repo, "registry.json"), map[string]any{
		"schemaVersion": "1.0.0",
		"registryId":    "test-registry",
		"entries": []map[string]any{
			{
				"kind":              "policyPack",
				"id":                "test-pack",
				"ref":               "pack.yaml",
				"status":            "active",
				"deprecatedAt":      nil,
				"deprecationReason": nil,
				"compatWindow":      "current",
				"digest":            sha256Path(t, filepath.Join(repo, "pack.yaml")),
				"trust": map[string]any{
					"signer":      "cadence-test",
					"allowlisted": true,
				},
			},
			{
				"kind":              "runtimeProfile",
				"id":                "test-runtime",
				"ref":               "runtime.json",
				"status":            "active",
				"deprecatedAt":      nil,
				"deprecationReason": nil,
				"compatWindow":      "current",
				"digest":            sha256Path(t, filepath.Join(repo, "runtime.json")),
				"trust": map[string]any{
					"signer":      "cadence-test",
					"allowlisted": true,
				},
			},
			{
				"kind":              "sandboxProfile",
				"id":                "test-sandbox",
				"ref":               "sandbox.json",
				"status":            "deprecated",
				"deprecatedAt":      "2026-04-13T00:00:00Z",
				"deprecationReason": "migrate sandbox",
				"compatWindow":      "until 2026-04-14",
				"digest":            sha256Path(t, filepath.Join(repo, "sandbox.json")),
				"trust": map[string]any{
					"signer":      "cadence-test",
					"allowlisted": true,
				},
			},
		},
	})

	cmd := exec.Command(bin, "verify", "--run-id", "sandbox-expired", "--out", outDir)
	cmd.Dir = repo
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected verify to fail when sandbox compatWindow has expired\n%s", output)
	}
	if !containsSubstring(string(output), "reference time") {
		t.Fatalf("unexpected verify failure output: %s", output)
	}
}

func TestVerifyFailsWhenDeprecatedPluginCompatWindowHasExpired(t *testing.T) {
	bin := buildBinary(t)
	repo := setupTestRepo(t)
	outDir := filepath.Join(repo, ".cadence", "out")
	// Plugins are discovered through the registry but require an explicit
	// repository-level execution grant. Request the deprecated plugin here so
	// this test continues to exercise its compatibility-window validation.
	if err := os.WriteFile(filepath.Join(repo, "cadence.yaml"), []byte(`projectId: integration-test
mode: strict_offline
closureRef: suite_version_closure.json
toolingLock: tooling_lock.json
runtimeRef: runtime.json
registryRef: registry.json
sandboxRef: sandbox.json
policies:
  - test-pack
plugins:
  - expired-plugin
`), 0o644); err != nil {
		t.Fatalf("write cadence.yaml with requested plugin: %v", err)
	}

	pluginDir := filepath.Join(repo, "plugins")
	if err := os.MkdirAll(pluginDir, 0o755); err != nil {
		t.Fatalf("mkdir plugins: %v", err)
	}
	pluginManifest := filepath.Join(pluginDir, "expired-plugin.json")
	pluginEntrypoint := filepath.Join(pluginDir, "expired-plugin.py")
	writeTestJSON(t, pluginManifest, map[string]any{
		"schemaVersion": "1.0.0",
		"pluginId":      "expired-plugin",
		"version":       "1.0.0",
		"protocol":      "1.0.0",
		"entryPoint":    "expired-plugin.py",
		"runtime":       "python3",
		"capabilities":  []string{"lint"},
		"compatWindow": map[string]any{
			"minProtocol": "1.0.0",
			"maxProtocol": "1.0.x",
		},
	})
	if err := os.WriteFile(pluginEntrypoint, []byte("import json\nprint(json.dumps({'status':'ok','pluginId':'expired-plugin'}))\n"), 0o755); err != nil {
		t.Fatalf("write plugin entrypoint: %v", err)
	}
	writeTestJSON(t, filepath.Join(repo, "registry.json"), map[string]any{
		"schemaVersion": "1.0.0",
		"registryId":    "test-registry",
		"entries": []map[string]any{
			{
				"kind":              "policyPack",
				"id":                "test-pack",
				"ref":               "pack.yaml",
				"status":            "active",
				"deprecatedAt":      nil,
				"deprecationReason": nil,
				"compatWindow":      "current",
				"digest":            sha256Path(t, filepath.Join(repo, "pack.yaml")),
				"trust": map[string]any{
					"signer":      "cadence-test",
					"allowlisted": true,
				},
			},
			{
				"kind":              "runtimeProfile",
				"id":                "test-runtime",
				"ref":               "runtime.json",
				"status":            "active",
				"deprecatedAt":      nil,
				"deprecationReason": nil,
				"compatWindow":      "current",
				"digest":            sha256Path(t, filepath.Join(repo, "runtime.json")),
				"trust": map[string]any{
					"signer":      "cadence-test",
					"allowlisted": true,
				},
			},
			{
				"kind":              "sandboxProfile",
				"id":                "test-sandbox",
				"ref":               "sandbox.json",
				"status":            "active",
				"deprecatedAt":      nil,
				"deprecationReason": nil,
				"compatWindow":      "current",
				"digest":            sha256Path(t, filepath.Join(repo, "sandbox.json")),
				"trust": map[string]any{
					"signer":      "cadence-test",
					"allowlisted": true,
				},
			},
			{
				"kind":              "plugin",
				"id":                "expired-plugin",
				"ref":               "plugins/expired-plugin.json",
				"status":            "deprecated",
				"deprecatedAt":      "2026-04-13T00:00:00Z",
				"deprecationReason": "migrate plugin",
				"compatWindow":      "until 2026-04-14",
				"digest":            sha256Path(t, pluginManifest),
				"trust": map[string]any{
					"signer":      "cadence-test",
					"allowlisted": true,
				},
			},
		},
	})

	cmd := exec.Command(bin, "verify", "--run-id", "plugin-expired", "--out", outDir)
	cmd.Dir = repo
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected verify to fail when plugin compatWindow has expired\n%s", output)
	}
	if !containsSubstring(string(output), "reference time") {
		t.Fatalf("unexpected verify failure output: %s", output)
	}
}

func TestVerifyFailsClosedWhenContainerRuntimeAdapterIsMissing(t *testing.T) {
	bin := buildBinary(t)
	repo := setupTestRepo(t)
	outDir := filepath.Join(repo, ".cadence", "out")

	writeTestJSON(t, filepath.Join(repo, "sandbox.json"), map[string]any{
		"schemaVersion": "1.0.0",
		"sandboxId":     "test-sandbox",
		"backend":       "container-runtime",
		"allowedEnv":    []string{"PYTHONDONTWRITEBYTECODE"},
		"filesystem": map[string]any{
			"mode":              "container-isolated",
			"readOnlyInputs":    true,
			"writableOutputDir": "/workspace/.cadence/out",
		},
		"network": map[string]any{
			"access": false,
		},
		"resources": map[string]any{
			"cpuLimit":       2,
			"memoryLimitMB":  1024,
			"pidsLimit":      128,
			"timeoutSeconds": 60,
		},
		"timeSource": "injected",
	})
	writeTestJSON(t, filepath.Join(repo, "registry.json"), map[string]any{
		"schemaVersion": "1.0.0",
		"registryId":    "test-registry",
		"entries": []map[string]any{
			{
				"kind":              "policyPack",
				"id":                "test-pack",
				"ref":               "pack.yaml",
				"status":            "active",
				"deprecatedAt":      nil,
				"deprecationReason": nil,
				"compatWindow":      "current",
				"digest":            sha256Path(t, filepath.Join(repo, "pack.yaml")),
				"trust": map[string]any{
					"signer":      "cadence-test",
					"allowlisted": true,
				},
			},
			{
				"kind":              "runtimeProfile",
				"id":                "test-runtime",
				"ref":               "runtime.json",
				"status":            "active",
				"deprecatedAt":      nil,
				"deprecationReason": nil,
				"compatWindow":      "current",
				"digest":            sha256Path(t, filepath.Join(repo, "runtime.json")),
				"trust": map[string]any{
					"signer":      "cadence-test",
					"allowlisted": true,
				},
			},
			{
				"kind":              "sandboxProfile",
				"id":                "test-sandbox",
				"ref":               "sandbox.json",
				"status":            "active",
				"deprecatedAt":      nil,
				"deprecationReason": nil,
				"compatWindow":      "current",
				"digest":            sha256Path(t, filepath.Join(repo, "sandbox.json")),
				"trust": map[string]any{
					"signer":      "cadence-test",
					"allowlisted": true,
				},
			},
		},
	})

	cmd := exec.Command(bin, "verify", "--run-id", "container-attestation-missing", "--out", outDir)
	cmd.Dir = repo
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected verify to fail when container runtime adapter is missing\n%s", output)
	}
	if !containsSubstring(string(output), "CADENCE_SANDBOX_CONTAINER_ADAPTER") {
		t.Fatalf("unexpected verify failure output: %s", output)
	}

	var sandboxResult map[string]any
	loadJSON(t, filepath.Join(outDir, "container-attestation-missing", "sandbox-result.json"), &sandboxResult)
	backendEvidence, ok := sandboxResult["backendEvidence"].(map[string]any)
	if !ok {
		t.Fatal("sandbox-result backendEvidence missing")
	}
	if backendEvidence["attestationStatus"] != "pending-runtime-proof" {
		t.Fatalf("sandbox-result attestationStatus = %v, want pending-runtime-proof", backendEvidence["attestationStatus"])
	}
}

func TestVerifyUsesContainerRuntimeAdapterExecution(t *testing.T) {
	bin := buildBinary(t)
	repo := setupTestRepo(t)
	outDir := filepath.Join(repo, ".cadence", "out")

	writeTestJSON(t, filepath.Join(repo, "sandbox.json"), map[string]any{
		"schemaVersion": "1.0.0",
		"sandboxId":     "test-sandbox",
		"backend":       "container-runtime",
		"allowedEnv":    []string{"PYTHONDONTWRITEBYTECODE"},
		"filesystem": map[string]any{
			"mode":              "container-isolated",
			"readOnlyInputs":    true,
			"writableOutputDir": "/workspace/.cadence/out",
		},
		"network": map[string]any{
			"access": false,
		},
		"resources": map[string]any{
			"cpuLimit":       2,
			"memoryLimitMB":  1024,
			"pidsLimit":      128,
			"timeoutSeconds": 60,
		},
		"timeSource": "injected",
	})
	writeTestJSON(t, filepath.Join(repo, "registry.json"), map[string]any{
		"schemaVersion": "1.0.0",
		"registryId":    "test-registry",
		"entries": []map[string]any{
			{
				"kind":              "policyPack",
				"id":                "test-pack",
				"ref":               "pack.yaml",
				"status":            "active",
				"deprecatedAt":      nil,
				"deprecationReason": nil,
				"compatWindow":      "current",
				"digest":            sha256Path(t, filepath.Join(repo, "pack.yaml")),
				"trust": map[string]any{
					"signer":      "cadence-test",
					"allowlisted": true,
				},
			},
			{
				"kind":              "runtimeProfile",
				"id":                "test-runtime",
				"ref":               "runtime.json",
				"status":            "active",
				"deprecatedAt":      nil,
				"deprecationReason": nil,
				"compatWindow":      "current",
				"digest":            sha256Path(t, filepath.Join(repo, "runtime.json")),
				"trust": map[string]any{
					"signer":      "cadence-test",
					"allowlisted": true,
				},
			},
			{
				"kind":              "sandboxProfile",
				"id":                "test-sandbox",
				"ref":               "sandbox.json",
				"status":            "active",
				"deprecatedAt":      nil,
				"deprecationReason": nil,
				"compatWindow":      "current",
				"digest":            sha256Path(t, filepath.Join(repo, "sandbox.json")),
				"trust": map[string]any{
					"signer":      "cadence-test",
					"allowlisted": true,
				},
			},
		},
	})

	adapter := writeRuntimeAdapterScript(t, repo, `{"exitCode":0,"stdout":"[]\n","stderr":"","observedChecks":["cgroup-fenced","mount-namespace","namespace-proof-hash","network-namespace","pid-namespace","seccomp-active"],"namespaceProofHash":"sha256:test","namespaceProofs":[{"namespace":"pid","selfDescriptor":"pid:[2]","initDescriptor":"pid:[1]","matchesInit":false}],"backendEvidence":{"cgroupVersion":"v2"}}`)
	cmd := exec.Command(bin, "verify", "--run-id", "container-runtime-exec", "--out", outDir)
	cmd.Dir = repo
	cmd.Env = append(os.Environ(), "CADENCE_SANDBOX_CONTAINER_ADAPTER="+adapter)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("expected verify to pass with runtime adapter: %v\n%s", err, out)
	}

	runDir := filepath.Join(outDir, "container-runtime-exec")
	var sandboxResult map[string]any
	loadJSON(t, filepath.Join(runDir, "sandbox-result.json"), &sandboxResult)
	if sandboxResult["mode"] != "runtime-exec" {
		t.Fatalf("sandbox-result mode = %v, want runtime-exec", sandboxResult["mode"])
	}
	if sandboxResult["isolationLevel"] != "backend-container-runtime-enforced" {
		t.Fatalf("sandbox-result isolationLevel = %v, want backend-container-runtime-enforced", sandboxResult["isolationLevel"])
	}
	backendEvidence, ok := sandboxResult["backendEvidence"].(map[string]any)
	if !ok {
		t.Fatal("sandbox-result backendEvidence missing")
	}
	if backendEvidence["attestationStatus"] != "verified" {
		t.Fatalf("sandbox-result attestationStatus = %v, want verified", backendEvidence["attestationStatus"])
	}
	if backendEvidence["adapterEnvVar"] != "CADENCE_SANDBOX_CONTAINER_ADAPTER" {
		t.Fatalf("sandbox-result adapterEnvVar = %v, want CADENCE_SANDBOX_CONTAINER_ADAPTER", backendEvidence["adapterEnvVar"])
	}

	var isolationProbe map[string]any
	loadJSON(t, filepath.Join(runDir, "isolation-probe.json"), &isolationProbe)
	if isolationProbe["namespaceProofHash"] != "sha256:test" {
		t.Fatalf("isolation-probe namespaceProofHash = %v, want sha256:test", isolationProbe["namespaceProofHash"])
	}
}

func TestVerifyUsesMicrovmRuntimeAdapterExecution(t *testing.T) {
	bin := buildBinary(t)
	repo := setupTestRepo(t)
	outDir := filepath.Join(repo, ".cadence", "out")

	writeTestJSON(t, filepath.Join(repo, "sandbox.json"), map[string]any{
		"schemaVersion": "1.0.0",
		"sandboxId":     "test-sandbox",
		"backend":       "microvm-runtime",
		"allowedEnv":    []string{"PYTHONDONTWRITEBYTECODE"},
		"filesystem": map[string]any{
			"mode":              "microvm-isolated",
			"readOnlyInputs":    true,
			"writableOutputDir": "/workspace/.cadence/out",
		},
		"network": map[string]any{
			"access": false,
		},
		"resources": map[string]any{
			"cpuLimit":       2,
			"memoryLimitMB":  1024,
			"pidsLimit":      128,
			"timeoutSeconds": 60,
		},
		"timeSource": "injected",
	})
	writeTestJSON(t, filepath.Join(repo, "registry.json"), map[string]any{
		"schemaVersion": "1.0.0",
		"registryId":    "test-registry",
		"entries": []map[string]any{
			{
				"kind":              "policyPack",
				"id":                "test-pack",
				"ref":               "pack.yaml",
				"status":            "active",
				"deprecatedAt":      nil,
				"deprecationReason": nil,
				"compatWindow":      "current",
				"digest":            sha256Path(t, filepath.Join(repo, "pack.yaml")),
				"trust": map[string]any{
					"signer":      "cadence-test",
					"allowlisted": true,
				},
			},
			{
				"kind":              "runtimeProfile",
				"id":                "test-runtime",
				"ref":               "runtime.json",
				"status":            "active",
				"deprecatedAt":      nil,
				"deprecationReason": nil,
				"compatWindow":      "current",
				"digest":            sha256Path(t, filepath.Join(repo, "runtime.json")),
				"trust": map[string]any{
					"signer":      "cadence-test",
					"allowlisted": true,
				},
			},
			{
				"kind":              "sandboxProfile",
				"id":                "test-sandbox",
				"ref":               "sandbox.json",
				"status":            "active",
				"deprecatedAt":      nil,
				"deprecationReason": nil,
				"compatWindow":      "current",
				"digest":            sha256Path(t, filepath.Join(repo, "sandbox.json")),
				"trust": map[string]any{
					"signer":      "cadence-test",
					"allowlisted": true,
				},
			},
		},
	})

	adapter := writeRuntimeAdapterScript(t, repo, `{"exitCode":0,"stdout":"[]\n","stderr":"","observedChecks":["cgroup-fenced","mount-namespace","namespace-proof-hash","network-namespace","pid-namespace","seccomp-active"],"namespaceProofHash":"sha256:microvm","namespaceProofs":[{"namespace":"mnt","selfDescriptor":"mnt:[2]","initDescriptor":"mnt:[1]","matchesInit":false}],"backendEvidence":{"cgroupVersion":"v2"}}`)
	cmd := exec.Command(bin, "verify", "--run-id", "microvm-runtime-exec", "--out", outDir)
	cmd.Dir = repo
	cmd.Env = append(os.Environ(), "CADENCE_SANDBOX_MICROVM_ADAPTER="+adapter)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("expected verify to pass with microvm runtime adapter: %v\n%s", err, out)
	}

	runDir := filepath.Join(outDir, "microvm-runtime-exec")
	var sandboxResult map[string]any
	loadJSON(t, filepath.Join(runDir, "sandbox-result.json"), &sandboxResult)
	if sandboxResult["mode"] != "runtime-exec" {
		t.Fatalf("sandbox-result mode = %v, want runtime-exec", sandboxResult["mode"])
	}
	if sandboxResult["isolationLevel"] != "backend-microvm-runtime-enforced" {
		t.Fatalf("sandbox-result isolationLevel = %v, want backend-microvm-runtime-enforced", sandboxResult["isolationLevel"])
	}
	backendEvidence, ok := sandboxResult["backendEvidence"].(map[string]any)
	if !ok {
		t.Fatal("sandbox-result backendEvidence missing")
	}
	if backendEvidence["attestationStatus"] != "verified" {
		t.Fatalf("sandbox-result attestationStatus = %v, want verified", backendEvidence["attestationStatus"])
	}
	if backendEvidence["adapterEnvVar"] != "CADENCE_SANDBOX_MICROVM_ADAPTER" {
		t.Fatalf("sandbox-result adapterEnvVar = %v, want CADENCE_SANDBOX_MICROVM_ADAPTER", backendEvidence["adapterEnvVar"])
	}
}

func TestVerifyUsesRealContainerRuntime(t *testing.T) {
	if os.Getenv("CADENCE_TEST_REAL_CONTAINER_RUNTIME") != "1" {
		t.Skip("set CADENCE_TEST_REAL_CONTAINER_RUNTIME=1 to run against a real container runtime")
	}
	adapter := strings.TrimSpace(os.Getenv("CADENCE_SANDBOX_CONTAINER_ADAPTER"))
	if adapter == "" {
		t.Fatal("CADENCE_TEST_REAL_CONTAINER_RUNTIME=1 requires CADENCE_SANDBOX_CONTAINER_ADAPTER")
	}

	bin := buildBinary(t)
	repo := setupTestRepo(t)
	outDir := filepath.Join(repo, ".cadence", "out")
	configureRuntimeBackend(t, repo, "container-runtime", "container-isolated")

	cmd := exec.Command(bin, "verify", "--run-id", "real-container-runtime", "--out", outDir)
	cmd.Dir = repo
	cmd.Env = append(os.Environ(), "CADENCE_SANDBOX_CONTAINER_ADAPTER="+adapter)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("expected verify to pass with a real container runtime: %v\n%s", err, out)
	}

	runDir := filepath.Join(outDir, "real-container-runtime")
	var sandboxResult map[string]any
	loadJSON(t, filepath.Join(runDir, "sandbox-result.json"), &sandboxResult)
	backendEvidence, ok := sandboxResult["backendEvidence"].(map[string]any)
	if !ok {
		t.Fatal("sandbox-result backendEvidence missing")
	}
	if sandboxResult["mode"] != "runtime-exec" {
		t.Fatalf("sandbox-result mode = %v, want runtime-exec", sandboxResult["mode"])
	}
	if backendEvidence["attestationStatus"] != "verified" {
		t.Fatalf("sandbox-result attestationStatus = %v, want verified", backendEvidence["attestationStatus"])
	}
	if strings.TrimSpace(fmt.Sprint(backendEvidence["engine"])) == "" {
		t.Fatalf("backendEvidence.engine missing: %v", backendEvidence)
	}
	if strings.TrimSpace(fmt.Sprint(backendEvidence["containerId"])) == "" {
		t.Fatalf("backendEvidence.containerId missing: %v", backendEvidence)
	}
	observed := fmt.Sprint(backendEvidence["observedChecks"])
	for _, needle := range []string{"cgroup", "namespace", "seccomp"} {
		if !strings.Contains(observed, needle) {
			t.Fatalf("backendEvidence.observedChecks missing %q: %s", needle, observed)
		}
	}
	for _, rel := range []string{"deterministic-evidence.json", "replay-package.json"} {
		if _, err := os.Stat(filepath.Join(runDir, rel)); err != nil {
			t.Fatalf("missing %s: %v", rel, err)
		}
	}
}

func TestVerifyUsesRealMicrovmRuntime(t *testing.T) {
	if os.Getenv("CADENCE_TEST_REAL_MICROVM_RUNTIME") != "1" {
		t.Skip("set CADENCE_TEST_REAL_MICROVM_RUNTIME=1 to run against a real microVM runtime")
	}
	adapter := strings.TrimSpace(os.Getenv("CADENCE_SANDBOX_MICROVM_ADAPTER"))
	if adapter == "" {
		t.Fatal("CADENCE_TEST_REAL_MICROVM_RUNTIME=1 requires CADENCE_SANDBOX_MICROVM_ADAPTER")
	}

	bin := buildBinary(t)
	repo := setupTestRepo(t)
	outDir := filepath.Join(repo, ".cadence", "out")
	configureRuntimeBackend(t, repo, "microvm-runtime", "microvm-isolated")

	cmd := exec.Command(bin, "verify", "--run-id", "real-microvm-runtime", "--out", outDir)
	cmd.Dir = repo
	cmd.Env = append(os.Environ(), "CADENCE_SANDBOX_MICROVM_ADAPTER="+adapter)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("expected verify to pass with a real microvm runtime: %v\n%s", err, out)
	}

	runDir := filepath.Join(outDir, "real-microvm-runtime")
	var sandboxResult map[string]any
	loadJSON(t, filepath.Join(runDir, "sandbox-result.json"), &sandboxResult)
	backendEvidence, ok := sandboxResult["backendEvidence"].(map[string]any)
	if !ok {
		t.Fatal("sandbox-result backendEvidence missing")
	}
	if sandboxResult["mode"] != "runtime-exec" {
		t.Fatalf("sandbox-result mode = %v, want runtime-exec", sandboxResult["mode"])
	}
	if backendEvidence["attestationStatus"] != "verified" {
		t.Fatalf("sandbox-result attestationStatus = %v, want verified", backendEvidence["attestationStatus"])
	}
	if strings.TrimSpace(fmt.Sprint(backendEvidence["hypervisor"])) == "" {
		t.Fatalf("backendEvidence.hypervisor missing: %v", backendEvidence)
	}
	if strings.TrimSpace(fmt.Sprint(backendEvidence["vmId"])) == "" {
		t.Fatalf("backendEvidence.vmId missing: %v", backendEvidence)
	}
	observed := fmt.Sprint(backendEvidence["observedChecks"])
	for _, needle := range []string{"cgroup", "namespace", "seccomp"} {
		if !strings.Contains(observed, needle) {
			t.Fatalf("backendEvidence.observedChecks missing %q: %s", needle, observed)
		}
	}
	for _, rel := range []string{"deterministic-evidence.json", "replay-package.json"} {
		if _, err := os.Stat(filepath.Join(runDir, rel)); err != nil {
			t.Fatalf("missing %s: %v", rel, err)
		}
	}
}

func TestVerifyFailsClosedWhenContainerRuntimeProofIsInvalid(t *testing.T) {
	bin := buildBinary(t)
	repo := setupTestRepo(t)
	outDir := filepath.Join(repo, ".cadence", "out")

	writeTestJSON(t, filepath.Join(repo, "sandbox.json"), map[string]any{
		"schemaVersion": "1.0.0",
		"sandboxId":     "test-sandbox",
		"backend":       "container-runtime",
		"allowedEnv":    []string{"PYTHONDONTWRITEBYTECODE"},
		"filesystem": map[string]any{
			"mode":              "container-isolated",
			"readOnlyInputs":    true,
			"writableOutputDir": "/workspace/.cadence/out",
		},
		"network": map[string]any{
			"access": false,
		},
		"resources": map[string]any{
			"cpuLimit":       2,
			"memoryLimitMB":  1024,
			"pidsLimit":      128,
			"timeoutSeconds": 60,
		},
		"timeSource": "injected",
	})
	writeTestJSON(t, filepath.Join(repo, "registry.json"), map[string]any{
		"schemaVersion": "1.0.0",
		"registryId":    "test-registry",
		"entries": []map[string]any{
			{
				"kind":              "policyPack",
				"id":                "test-pack",
				"ref":               "pack.yaml",
				"status":            "active",
				"deprecatedAt":      nil,
				"deprecationReason": nil,
				"compatWindow":      "current",
				"digest":            sha256Path(t, filepath.Join(repo, "pack.yaml")),
				"trust": map[string]any{
					"signer":      "cadence-test",
					"allowlisted": true,
				},
			},
			{
				"kind":              "runtimeProfile",
				"id":                "test-runtime",
				"ref":               "runtime.json",
				"status":            "active",
				"deprecatedAt":      nil,
				"deprecationReason": nil,
				"compatWindow":      "current",
				"digest":            sha256Path(t, filepath.Join(repo, "runtime.json")),
				"trust": map[string]any{
					"signer":      "cadence-test",
					"allowlisted": true,
				},
			},
			{
				"kind":              "sandboxProfile",
				"id":                "test-sandbox",
				"ref":               "sandbox.json",
				"status":            "active",
				"deprecatedAt":      nil,
				"deprecationReason": nil,
				"compatWindow":      "current",
				"digest":            sha256Path(t, filepath.Join(repo, "sandbox.json")),
				"trust": map[string]any{
					"signer":      "cadence-test",
					"allowlisted": true,
				},
			},
		},
	})

	adapter := writeRuntimeAdapterScript(t, repo, `{"exitCode":0,"stdout":"[]\n","stderr":"","observedChecks":["cgroup-fenced"],"failureReasons":["adapter observed partial fences only"]}`)
	cmd := exec.Command(bin, "verify", "--run-id", "container-attestation-invalid", "--out", outDir)
	cmd.Dir = repo
	cmd.Env = append(os.Environ(), "CADENCE_SANDBOX_CONTAINER_ADAPTER="+adapter)
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected verify to fail when container backend proof is invalid\n%s", output)
	}

	var sandboxResult map[string]any
	loadJSON(t, filepath.Join(outDir, "container-attestation-invalid", "sandbox-result.json"), &sandboxResult)
	backendEvidence, ok := sandboxResult["backendEvidence"].(map[string]any)
	if !ok {
		t.Fatal("sandbox-result backendEvidence missing")
	}
	if backendEvidence["attestationStatus"] != "insufficient" {
		t.Fatalf("sandbox-result attestationStatus = %v, want insufficient", backendEvidence["attestationStatus"])
	}
}

func TestInputIdentityIncludesGovernedCadenceFiles(t *testing.T) {
	bin := buildBinary(t)
	repo := setupTestRepo(t)
	outDir := filepath.Join(repo, ".cadence", "out")

	governed := filepath.Join(repo, ".cadence", "governed-config.json")
	if err := os.MkdirAll(filepath.Dir(governed), 0o755); err != nil {
		t.Fatalf("mkdir governed cadence dir: %v", err)
	}
	if err := os.WriteFile(governed, []byte("{\"mode\":\"strict\"}\n"), 0o644); err != nil {
		t.Fatalf("write governed cadence file: %v", err)
	}

	cmd1 := exec.Command(bin, "verify", "--run-id", "identity-run-1", "--out", outDir)
	cmd1.Dir = repo
	if out, err := cmd1.CombinedOutput(); err != nil {
		t.Fatalf("verify run 1 failed: %v\n%s", err, out)
	}

	if err := os.WriteFile(governed, []byte("{\"mode\":\"relaxed\"}\n"), 0o644); err != nil {
		t.Fatalf("rewrite governed cadence file: %v", err)
	}

	cmd2 := exec.Command(bin, "verify", "--run-id", "identity-run-2", "--out", outDir)
	cmd2.Dir = repo
	if out, err := cmd2.CombinedOutput(); err != nil {
		t.Fatalf("verify run 2 failed: %v\n%s", err, out)
	}

	var m1, m2 map[string]any
	loadJSON(t, filepath.Join(outDir, "identity-run-1", "run-manifest.json"), &m1)
	loadJSON(t, filepath.Join(outDir, "identity-run-2", "run-manifest.json"), &m2)
	inp1 := m1["inputRef"].(map[string]any)["inputHash"]
	inp2 := m2["inputRef"].(map[string]any)["inputHash"]
	if inp1 == inp2 {
		t.Fatalf("expected governed .cadence change to alter inputHash, both were %v", inp1)
	}
}

func TestInputIdentityTracksAllowedEnvironmentInputs(t *testing.T) {
	bin := buildBinary(t)
	repo := setupTestRepo(t)
	outDir := filepath.Join(repo, ".cadence", "out")

	cmd1 := exec.Command(bin, "verify", "--run-id", "env-run-1", "--out", outDir)
	cmd1.Dir = repo
	cmd1.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1")
	if out, err := cmd1.CombinedOutput(); err != nil {
		t.Fatalf("verify run 1 failed: %v\n%s", err, out)
	}

	cmd2 := exec.Command(bin, "verify", "--run-id", "env-run-2", "--out", outDir)
	cmd2.Dir = repo
	cmd2.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=0")
	if out, err := cmd2.CombinedOutput(); err != nil {
		t.Fatalf("verify run 2 failed: %v\n%s", err, out)
	}

	var m1, m2 map[string]any
	loadJSON(t, filepath.Join(outDir, "env-run-1", "input-identity.json"), &m1)
	loadJSON(t, filepath.Join(outDir, "env-run-2", "input-identity.json"), &m2)
	if m1["environmentInputsHash"] == m2["environmentInputsHash"] {
		t.Fatalf("expected environmentInputsHash to change when allowlisted env input changes")
	}
}

func TestVerifyUsesConfiguredRootAnchor(t *testing.T) {
	bin := buildBinary(t)
	repo := setupTestRepo(t)
	outDir := filepath.Join(repo, ".cadence", "out")

	cadencePath := filepath.Join(repo, "cadence.yaml")
	content, err := os.ReadFile(cadencePath)
	if err != nil {
		t.Fatalf("read cadence.yaml: %v", err)
	}
	content = append(content, []byte("rootAnchor: hsm://tenant/root\n")...)
	if err := os.WriteFile(cadencePath, content, 0o644); err != nil {
		t.Fatalf("write cadence.yaml: %v", err)
	}

	cmd := exec.Command(bin, "verify", "--run-id", "root-anchor-config", "--out", outDir)
	cmd.Dir = repo
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("verify failed: %v\n%s", err, out)
	}

	runDir := filepath.Join(outDir, "root-anchor-config")

	var keyHierarchy map[string]any
	loadJSON(t, filepath.Join(runDir, "key-hierarchy.json"), &keyHierarchy)
	if keyHierarchy["rootAnchor"] != "hsm://tenant/root" {
		t.Fatalf("key-hierarchy rootAnchor = %v, want hsm://tenant/root", keyHierarchy["rootAnchor"])
	}

	levels, ok := keyHierarchy["levels"].([]any)
	if !ok || len(levels) != 1 {
		t.Fatalf("unexpected key-hierarchy levels: %#v", keyHierarchy["levels"])
	}
	level0, ok := levels[0].(map[string]any)
	if !ok {
		t.Fatalf("unexpected level payload: %#v", levels[0])
	}
	if level0["anchor"] != "hsm://tenant/root" {
		t.Fatalf("key-hierarchy levels[0].anchor = %v, want hsm://tenant/root", level0["anchor"])
	}

	if _, err := os.Stat(filepath.Join(runDir, "hsm-anchor.json")); !os.IsNotExist(err) {
		t.Fatal("root URI configuration is not hardware evidence")
	}

	var inputIdentity map[string]any
	loadJSON(t, filepath.Join(runDir, "input-identity.json"), &inputIdentity)
	envSpec, ok := inputIdentity["environmentSpec"].(map[string]any)
	if !ok {
		t.Fatalf("input-identity environmentSpec missing or wrong type")
	}
	if envSpec["rootAnchor"] != "hsm://tenant/root" {
		t.Fatalf("input-identity environmentSpec.rootAnchor = %v, want hsm://tenant/root", envSpec["rootAnchor"])
	}
	if envSpec["rootAnchorSource"] != "cadence.yaml#rootAnchor" {
		t.Fatalf("input-identity environmentSpec.rootAnchorSource = %v, want cadence.yaml#rootAnchor", envSpec["rootAnchorSource"])
	}
}

func TestVerifyEnvironmentRootAnchorOverrideWins(t *testing.T) {
	bin := buildBinary(t)
	repo := setupTestRepo(t)
	outDir := filepath.Join(repo, ".cadence", "out")

	cadencePath := filepath.Join(repo, "cadence.yaml")
	content, err := os.ReadFile(cadencePath)
	if err != nil {
		t.Fatalf("read cadence.yaml: %v", err)
	}
	content = append(content, []byte("rootAnchor: hsm://tenant/root\n")...)
	if err := os.WriteFile(cadencePath, content, 0o644); err != nil {
		t.Fatalf("write cadence.yaml: %v", err)
	}

	cmd := exec.Command(bin, "verify", "--run-id", "root-anchor-env", "--out", outDir)
	cmd.Dir = repo
	cmd.Env = append(os.Environ(), "CADENCE_ROOT_ANCHOR=kms://tenant/root")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("verify failed: %v\n%s", err, out)
	}

	runDir := filepath.Join(outDir, "root-anchor-env")

	var keyHierarchy map[string]any
	loadJSON(t, filepath.Join(runDir, "key-hierarchy.json"), &keyHierarchy)
	if keyHierarchy["rootAnchor"] != "kms://tenant/root" {
		t.Fatalf("key-hierarchy rootAnchor = %v, want kms://tenant/root", keyHierarchy["rootAnchor"])
	}

	if _, err := os.Stat(filepath.Join(runDir, "hsm-anchor.json")); !os.IsNotExist(err) {
		t.Fatal("root URI configuration is not hardware evidence")
	}

	var inputIdentity map[string]any
	loadJSON(t, filepath.Join(runDir, "input-identity.json"), &inputIdentity)
	envSpec, ok := inputIdentity["environmentSpec"].(map[string]any)
	if !ok {
		t.Fatalf("input-identity environmentSpec missing or wrong type")
	}
	if envSpec["rootAnchor"] != "kms://tenant/root" {
		t.Fatalf("input-identity environmentSpec.rootAnchor = %v, want kms://tenant/root", envSpec["rootAnchor"])
	}
	if envSpec["rootAnchorSource"] != "env:CADENCE_ROOT_ANCHOR" {
		t.Fatalf("input-identity environmentSpec.rootAnchorSource = %v, want env:CADENCE_ROOT_ANCHOR", envSpec["rootAnchorSource"])
	}
}

func TestVerifyFailsWhenReservedSandboxEnvIsInjected(t *testing.T) {
	bin := buildBinary(t)
	repo := setupTestRepo(t)
	outDir := filepath.Join(repo, ".cadence", "out")

	cmd := exec.Command(bin, "verify", "--run-id", "reserved-env", "--out", outDir)
	cmd.Dir = repo
	cmd.Env = append(os.Environ(), "CADENCE_SANDBOX_PROFILE=poisoned")
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected verify to fail for reserved sandbox env injection\n%s", output)
	}
	if !containsSubstring(string(output), "runtime environment invalid") {
		t.Fatalf("unexpected verify failure output: %s", output)
	}
}

// Helpers.

func singleRunDir(t *testing.T, outDir string) string {
	t.Helper()
	entries, err := os.ReadDir(outDir)
	if err != nil {
		t.Fatalf("failed to read output dir %s: %v", outDir, err)
	}
	runDirs := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		runDirs = append(runDirs, filepath.Join(outDir, entry.Name()))
	}
	if len(runDirs) != 1 {
		t.Fatalf("expected exactly one run directory under %s, found %d", outDir, len(runDirs))
	}
	return runDirs[0]
}

func loadJSON(t *testing.T, path string, v any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read %s: %v", filepath.Base(path), err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		t.Fatalf("failed to parse %s: %v", filepath.Base(path), err)
	}
}

func requireField(t *testing.T, m map[string]any, key, context string) {
	t.Helper()
	if _, ok := m[key]; !ok {
		t.Errorf("%s: missing required field %q", context, key)
	}
}

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", h[:])
}

func hasJSONKey(v any, key string) bool {
	switch node := v.(type) {
	case map[string]any:
		if _, ok := node[key]; ok {
			return true
		}
		for _, child := range node {
			if hasJSONKey(child, key) {
				return true
			}
		}
	case []any:
		for _, child := range node {
			if hasJSONKey(child, key) {
				return true
			}
		}
	}
	return false
}

func containsSubstring(haystack string, needle string) bool {
	return strings.Contains(haystack, needle)
}
