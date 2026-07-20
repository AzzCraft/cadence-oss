package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, path string, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeJSON(t *testing.T, path string, payload any) {
	t.Helper()
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, path, string(data))
}

func writeValidCadenceArtifacts(t *testing.T, root string) {
	t.Helper()
	writeFile(t, filepath.Join(root, "runtime.json"), "{}")
	writeJSON(t, filepath.Join(root, "registry.json"), map[string]any{
		"schemaVersion": "1.0.0",
		"registryId":    "test-registry",
		"entries":       []map[string]any{},
	})
	writeFile(t, filepath.Join(root, "sandbox.json"), "{}")
	writeJSON(t, filepath.Join(root, "suite_lock.json"), map[string]any{
		"schemaVersion": "1.0.0",
	})
	writeJSON(t, filepath.Join(root, "suite_version_closure.json"), map[string]any{
		"schemaVersion":           "1.0.0",
		"standardVersion":         "1.4.0",
		"standardManifestVersion": "1.4.0",
		"suiteVersion":            "1.0.0",
		"factoryVersion":          "factory-1.0.0",
		"verifyRuntimeVersion":    "runtime-1.0.0",
		"closureUpdatedAt":        "2026-04-11T00:00:00Z",
		"suiteLockRef": map[string]any{
			"kind": "file", "uri": "./suite_lock.json", "pinType": "manifest", "pinValue": "suite_lock.json", "floating": false,
		},
		"lockRefs": map[string]any{
			"suiteToolingLock": map[string]any{
				"kind": "file", "uri": "./tooling_lock.json", "pinType": "manifest", "pinValue": "tooling_lock.json", "floating": false,
			},
		},
		"refs": map[string]any{
			"standard":      map[string]any{"kind": "git", "uri": "git@example.com:das-standard.git", "pinType": "commit", "pinValue": "1111111", "floating": false},
			"suite":         map[string]any{"kind": "git", "uri": "git@example.com:das-suite.git", "pinType": "commit", "pinValue": "2222222", "floating": false},
			"factory":       map[string]any{"kind": "git", "uri": "git@example.com:dasops.git", "pinType": "commit", "pinValue": "3333333", "floating": false},
			"verifyRuntime": map[string]any{"kind": "git", "uri": "git@example.com:cadence-oss.git", "pinType": "commit", "pinValue": "4444444", "floating": false},
		},
	})
	writeJSON(t, filepath.Join(root, "tooling_lock.json"), map[string]any{
		"schemaVersion":           "1.0.0",
		"standardManifestVersion": "1.4.0",
		"sourceOfTruth": map[string]any{
			"kind": "git", "uri": "git@example.com:example-product.git", "pinType": "commit", "pinValue": "aaaaaaa", "floating": false,
		},
		"verifyRuntime": map[string]any{
			"kind": "git", "uri": "git@example.com:cadence-oss.git", "pinType": "commit", "pinValue": "4444444", "floating": false,
		},
		"suiteVersionClosureRef": map[string]any{
			"kind": "file", "uri": "./suite_version_closure.json", "pinType": "manifest", "pinValue": "suite_version_closure.json", "floating": false,
		},
		"suiteLockRef": map[string]any{
			"kind": "file", "uri": "./suite_lock.json", "pinType": "manifest", "pinValue": "suite_lock.json", "floating": false,
		},
		"verifyRegistryRef": map[string]any{
			"kind": "file", "uri": "./registry.json", "pinType": "manifest", "pinValue": "registry.json", "floating": false,
		},
		"toolchain": []map[string]any{
			{"name": "go", "version": "1.22.x", "manager": "system"},
		},
	})
}

func TestLoadRequiresExplicitRefs(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "cadence.yaml"), "projectId: demo\nmode: strict_offline\npolicies:\n  - standard-ui-v140\n")

	_, err := Load(root)
	if err == nil || !(strings.Contains(err.Error(), "missing") || strings.Contains(err.Error(), "does not resolve")) {
		t.Fatalf("expected missing ref error, got %v", err)
	}
}

func TestLoadRejectsUnknownKeys(t *testing.T) {
	root := t.TempDir()
	writeValidCadenceArtifacts(t, root)
	writeFile(t, filepath.Join(root, "cadence.yaml"), ""+
		"projectId: demo\n"+
		"mode: strict_offline\n"+
		"closureRef: suite_version_closure.json\n"+
		"toolingLock: tooling_lock.json\n"+
		"runtimeRef: runtime.json\n"+
		"registryRef: registry.json\n"+
		"sandboxRef: sandbox.json\n"+
		"unexpectedKey: nope\n"+
		"policies:\n"+
		"  - standard-ui-v140\n")

	_, err := Load(root)
	if err == nil || !strings.Contains(err.Error(), "unknown top-level key") {
		t.Fatalf("expected unknown top-level key error, got %v", err)
	}
}

func TestLoadRejectsUnknownTopLevelField(t *testing.T) {
	root := t.TempDir()
	writeValidCadenceArtifacts(t, root)
	writeFile(t, filepath.Join(root, "cadence.yaml"), ""+
		"projectId: demo\n"+
		"mode: strict_offline\n"+
		"closureRef: suite_version_closure.json\n"+
		"toolingLock: tooling_lock.json\n"+
		"runtimeRef: runtime.json\n"+
		"registryRef: registry.json\n"+
		"sandboxRef: sandbox.json\n"+
		"futureField: nope\n"+
		"policies:\n"+
		"  - standard-ui-v140\n")

	_, err := Load(root)
	if err == nil || !strings.Contains(err.Error(), "unknown top-level key futureField") {
		t.Fatalf("expected schema-backed unknown field error, got %v", err)
	}
}

func TestLoadRejectsMissingRequiredPins(t *testing.T) {
	root := t.TempDir()
	writeValidCadenceArtifacts(t, root)
	writeFile(t, filepath.Join(root, "cadence.yaml"), ""+
		"projectId: demo\n"+
		"mode: strict_offline\n"+
		"closureRef: suite_version_closure.json\n"+
		"toolingLock: tooling_lock.json\n"+
		"registryRef: registry.json\n"+
		"sandboxRef: sandbox.json\n"+
		"policies:\n"+
		"  - standard-ui-v140\n")

	_, err := Load(root)
	if err == nil || !strings.Contains(err.Error(), "runtimeRef") {
		t.Fatalf("expected missing runtimeRef schema error, got %v", err)
	}
}

func TestLoadRejectsWrongTypeForPolicies(t *testing.T) {
	root := t.TempDir()
	writeValidCadenceArtifacts(t, root)
	writeFile(t, filepath.Join(root, "cadence.yaml"), ""+
		"projectId: demo\n"+
		"mode: strict_offline\n"+
		"closureRef: suite_version_closure.json\n"+
		"toolingLock: tooling_lock.json\n"+
		"runtimeRef: runtime.json\n"+
		"registryRef: registry.json\n"+
		"sandboxRef: sandbox.json\n"+
		"policies: standard-ui-v140\n")

	_, err := Load(root)
	if err == nil || !strings.Contains(err.Error(), "policies") {
		t.Fatalf("expected wrong policies type schema error, got %v", err)
	}
}

func TestConfigSchemaRequiredFieldsMatchLoader(t *testing.T) {
	payload, _, err := loadConfigSchemaData()
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Required []string `json:"required"`
	}
	if err := json.Unmarshal(payload, &schema); err != nil {
		t.Fatal(err)
	}
	required := map[string]bool{}
	for _, key := range schema.Required {
		required[key] = true
	}
	for _, key := range []string{"projectId", "closureRef", "toolingLock", "runtimeRef", "registryRef", "sandboxRef", "policies"} {
		if !required[key] {
			t.Fatalf("config.schema.json required set does not include %s", key)
		}
	}
}

func TestLoadAcceptsExplicitCadenceInputs(t *testing.T) {
	root := t.TempDir()
	writeValidCadenceArtifacts(t, root)
	writeFile(t, filepath.Join(root, "cadence.yaml"), ""+
		"projectId: demo\n"+
		"mode: strict_offline\n"+
		"closureRef: suite_version_closure.json\n"+
		"toolingLock: tooling_lock.json\n"+
		"runtimeRef: runtime.json\n"+
		"registryRef: registry.json\n"+
		"sandboxRef: sandbox.json\n"+
		"rootAnchor: hsm://tenant/root\n"+
		"policies:\n"+
		"  - standard-ui-v140\n"+
		"ui:\n"+
		"  enabled: true\n"+
		"  profile: pr\n")

	cfg, err := Load(root)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ToolingLock != "tooling_lock.json" || len(cfg.Policies) != 1 {
		t.Fatalf("unexpected config: %+v", cfg)
	}
	if cfg.RootAnchor != "hsm://tenant/root" {
		t.Fatalf("expected configured root anchor, got %+v", cfg)
	}
}

func TestConfigFixtures(t *testing.T) {
	fixtureRoot := filepath.Join("..", "..", "tests", "fixtures", "config")
	validDir := filepath.Join(fixtureRoot, "valid")
	invalidDir := filepath.Join(fixtureRoot, "invalid")

	validEntries, err := os.ReadDir(validDir)
	if err != nil {
		t.Fatalf("read valid fixture dir: %v", err)
	}
	if len(validEntries) == 0 {
		t.Fatal("valid fixture dir is empty")
	}
	for _, entry := range validEntries {
		if entry.IsDir() {
			continue
		}
		t.Run("valid_"+entry.Name(), func(t *testing.T) {
			root := t.TempDir()
			writeValidCadenceArtifacts(t, root)
			data, err := os.ReadFile(filepath.Join(validDir, entry.Name()))
			if err != nil {
				t.Fatal(err)
			}
			writeFile(t, filepath.Join(root, "cadence.yaml"), string(data))
			if _, err := Load(root); err != nil {
				t.Fatalf("valid fixture was rejected: %v", err)
			}
		})
	}

	invalidEntries, err := os.ReadDir(invalidDir)
	if err != nil {
		t.Fatalf("read invalid fixture dir: %v", err)
	}
	if len(invalidEntries) == 0 {
		t.Fatal("invalid fixture dir is empty")
	}
	for _, entry := range invalidEntries {
		if entry.IsDir() {
			continue
		}
		t.Run("invalid_"+entry.Name(), func(t *testing.T) {
			root := t.TempDir()
			writeValidCadenceArtifacts(t, root)
			data, err := os.ReadFile(filepath.Join(invalidDir, entry.Name()))
			if err != nil {
				t.Fatal(err)
			}
			writeFile(t, filepath.Join(root, "cadence.yaml"), string(data))
			if _, err := Load(root); err == nil {
				t.Fatal("invalid fixture was accepted")
			}
		})
	}
}

func TestLoadRejectsLegacyToolingLockShape(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "runtime.json"), "{}")
	writeJSON(t, filepath.Join(root, "registry.json"), map[string]any{
		"schemaVersion": "1.0.0",
		"registryId":    "test-registry",
		"entries":       []map[string]any{},
	})
	writeFile(t, filepath.Join(root, "sandbox.json"), "{}")
	writeJSON(t, filepath.Join(root, "suite_lock.json"), map[string]any{
		"schemaVersion": "1.0.0",
	})
	writeJSON(t, filepath.Join(root, "suite_version_closure.json"), map[string]any{
		"schemaVersion":           "1.0.0",
		"standardVersion":         "1.4.0",
		"standardManifestVersion": "1.4.0",
		"suiteVersion":            "1.0.0",
		"factoryVersion":          "factory-1.0.0",
		"verifyRuntimeVersion":    "runtime-1.0.0",
		"closureUpdatedAt":        "2026-04-11T00:00:00Z",
		"suiteLockRef": map[string]any{
			"kind": "file", "uri": "./suite_lock.json", "pinType": "manifest", "pinValue": "suite_lock.json", "floating": false,
		},
		"lockRefs": map[string]any{
			"suiteToolingLock": map[string]any{
				"kind": "file", "uri": "./tooling_lock.json", "pinType": "manifest", "pinValue": "tooling_lock.json", "floating": false,
			},
		},
		"refs": map[string]any{
			"standard":      map[string]any{"kind": "git", "uri": "git@example.com:das-standard.git", "pinType": "commit", "pinValue": "1111111", "floating": false},
			"suite":         map[string]any{"kind": "git", "uri": "git@example.com:das-suite.git", "pinType": "commit", "pinValue": "2222222", "floating": false},
			"factory":       map[string]any{"kind": "git", "uri": "git@example.com:dasops.git", "pinType": "commit", "pinValue": "3333333", "floating": false},
			"verifyRuntime": map[string]any{"kind": "git", "uri": "git@example.com:cadence-oss.git", "pinType": "commit", "pinValue": "4444444", "floating": false},
		},
	})
	writeJSON(t, filepath.Join(root, "tooling_lock.json"), map[string]any{
		"schemaVersion": "1.0.0",
		"locked":        true,
		"tools":         map[string]any{},
	})
	writeFile(t, filepath.Join(root, "cadence.yaml"), ""+
		"projectId: demo\n"+
		"mode: strict_offline\n"+
		"closureRef: suite_version_closure.json\n"+
		"toolingLock: tooling_lock.json\n"+
		"runtimeRef: runtime.json\n"+
		"registryRef: registry.json\n"+
		"sandboxRef: sandbox.json\n"+
		"policies:\n"+
		"  - standard-ui-v140\n")

	_, err := Load(root)
	errorText := ""
	if err != nil {
		errorText = err.Error()
	}
	if err == nil || !(strings.Contains(errorText, "unknown key locked") || strings.Contains(errorText, "unknown key tools") || strings.Contains(errorText, "standardManifestVersion")) {
		t.Fatalf("expected strict tooling lock validation error, got %v", err)
	}
}

func TestLoadRejectsClosureWithoutLockRefs(t *testing.T) {
	root := t.TempDir()
	writeValidCadenceArtifacts(t, root)
	writeJSON(t, filepath.Join(root, "suite_version_closure.json"), map[string]any{
		"schemaVersion":           "1.0.0",
		"standardVersion":         "1.4.0",
		"standardManifestVersion": "1.4.0",
		"suiteVersion":            "1.0.0",
		"factoryVersion":          "factory-1.0.0",
		"verifyRuntimeVersion":    "runtime-1.0.0",
		"closureUpdatedAt":        "2026-04-11T00:00:00Z",
		"suiteLockRef": map[string]any{
			"kind": "file", "uri": "./suite_lock.json", "pinType": "manifest", "pinValue": "suite_lock.json", "floating": false,
		},
		"refs": map[string]any{
			"standard":      map[string]any{"kind": "git", "uri": "git@example.com:das-standard.git", "pinType": "commit", "pinValue": "1111111", "floating": false},
			"suite":         map[string]any{"kind": "git", "uri": "git@example.com:das-suite.git", "pinType": "commit", "pinValue": "2222222", "floating": false},
			"factory":       map[string]any{"kind": "git", "uri": "git@example.com:dasops.git", "pinType": "commit", "pinValue": "3333333", "floating": false},
			"verifyRuntime": map[string]any{"kind": "git", "uri": "git@example.com:cadence-oss.git", "pinType": "commit", "pinValue": "4444444", "floating": false},
		},
	})
	writeFile(t, filepath.Join(root, "cadence.yaml"), ""+
		"projectId: demo\n"+
		"mode: strict_offline\n"+
		"closureRef: suite_version_closure.json\n"+
		"toolingLock: tooling_lock.json\n"+
		"runtimeRef: runtime.json\n"+
		"registryRef: registry.json\n"+
		"sandboxRef: sandbox.json\n"+
		"policies:\n"+
		"  - standard-ui-v140\n")

	_, err := Load(root)
	if err == nil || !strings.Contains(err.Error(), "missing lockRefs") {
		t.Fatalf("expected missing lockRefs error, got %v", err)
	}
}

func TestLoadRejectsToolingLockWrongRegistryRef(t *testing.T) {
	root := t.TempDir()
	writeValidCadenceArtifacts(t, root)
	writeJSON(t, filepath.Join(root, "tooling_lock.json"), map[string]any{
		"schemaVersion":           "1.0.0",
		"standardManifestVersion": "1.4.0",
		"sourceOfTruth": map[string]any{
			"kind": "git", "uri": "git@example.com:example-product.git", "pinType": "commit", "pinValue": "aaaaaaa", "floating": false,
		},
		"verifyRuntime": map[string]any{
			"kind": "git", "uri": "git@example.com:cadence-oss.git", "pinType": "commit", "pinValue": "4444444", "floating": false,
		},
		"suiteVersionClosureRef": map[string]any{
			"kind": "file", "uri": "./suite_version_closure.json", "pinType": "manifest", "pinValue": "suite_version_closure.json", "floating": false,
		},
		"suiteLockRef": map[string]any{
			"kind": "file", "uri": "./suite_lock.json", "pinType": "manifest", "pinValue": "suite_lock.json", "floating": false,
		},
		"verifyRegistryRef": map[string]any{
			"kind": "file", "uri": "./wrong-registry.json", "pinType": "manifest", "pinValue": "wrong-registry.json", "floating": false,
		},
		"toolchain": []map[string]any{
			{"name": "go", "version": "1.22.x", "manager": "system"},
		},
	})
	writeJSON(t, filepath.Join(root, "wrong-registry.json"), map[string]any{
		"schemaVersion": "1.0.0",
		"registryId":    "wrong-registry",
		"entries":       []map[string]any{},
	})
	writeFile(t, filepath.Join(root, "cadence.yaml"), ""+
		"projectId: demo\n"+
		"mode: strict_offline\n"+
		"closureRef: suite_version_closure.json\n"+
		"toolingLock: tooling_lock.json\n"+
		"runtimeRef: runtime.json\n"+
		"registryRef: registry.json\n"+
		"sandboxRef: sandbox.json\n"+
		"policies:\n"+
		"  - standard-ui-v140\n")

	_, err := Load(root)
	if err == nil || !strings.Contains(err.Error(), "verifyRegistryRef must point") {
		t.Fatalf("expected verifyRegistryRef alignment error, got %v", err)
	}
}

func TestLoadStrictExistsAndCallable(t *testing.T) {
	// LoadStrict delegates to Load, so we just verify it exists and is callable.
	// In a real setup, Load would fail because we have no cadence.yaml, so
	// we expect an error here.
	_, err := LoadStrict(t.TempDir())
	if err == nil {
		t.Fatal("expected error from LoadStrict on empty dir")
	}
}

func TestValidateProjectIDAccepts(t *testing.T) {
	for _, id := range []string{"my-project", "abc", "a1b2c3", "cadence-core-v1"} {
		if err := ValidateProjectID(id); err != nil {
			t.Fatalf("rejected valid id %q: %v", id, err)
		}
	}
}

func TestValidateProjectIDRejects(t *testing.T) {
	for _, id := range []string{"", "ab", "AB", "my_project", "-bad", "bad-", "a"} {
		if err := ValidateProjectID(id); err == nil {
			t.Fatalf("accepted invalid id %q", id)
		}
	}
}
