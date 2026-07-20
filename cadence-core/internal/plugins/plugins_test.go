package plugins

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func writePluginFile(t *testing.T, path string, body string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
}

func writePluginManifest(t *testing.T, dir string, payload map[string]any) string {
	t.Helper()
	path := filepath.Join(dir, "manifest.json")
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	writePluginFile(t, path, string(data), 0o644)
	return path
}

func TestLoadSupportsLegacyEntrypointKey(t *testing.T) {
	dir := t.TempDir()
	manifestPath := writePluginManifest(t, dir, map[string]any{
		"schemaVersion": "1.0.0",
		"pluginId":      "demo-plugin",
		"entrypoint":    "plugin.py",
		"runtime":       "python3",
		"protocol":      "1.0.0",
		"capabilities":  []string{"verify"},
	})

	manifest, err := Load(manifestPath)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if manifest.EntryPoint != "plugin.py" {
		t.Fatalf("expected normalized entry point, got %q", manifest.EntryPoint)
	}
}

func TestRunFailsClosedUntilAnIsolatedRunnerIsAvailable(t *testing.T) {
	dir := t.TempDir()
	pluginPath := filepath.Join(dir, "plugin.py")
	writePluginFile(t, pluginPath, `#!/usr/bin/env python3
import json
import os
import sys

req = json.loads(sys.stdin.read())
resp = {
  "pluginId": req["pluginId"],
  "protocolVersion": req["protocolVersion"],
  "status": "ok",
  "violations": [],
  "metrics": {
    "envKeys": sorted(k for k in os.environ if k.startswith("CADENCE_PLUGIN_"))
  },
  "diagnostics": {
    "workdir": os.environ.get("CADENCE_PLUGIN_WORKDIR"),
    "outputDir": os.environ.get("CADENCE_PLUGIN_OUTPUT_DIR")
  }
}
sys.stdout.write(json.dumps(resp))
`, 0o755)
	manifestPath := writePluginManifest(t, dir, map[string]any{
		"schemaVersion": "1.0.0",
		"pluginId":      "demo-plugin",
		"entrypoint":    "plugin.py",
		"runtime":       "python3",
		"protocol":      "1.0.0",
		"capabilities":  []string{"verify"},
	})

	manifest, err := Load(manifestPath)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	result, err := Run(manifest, RunRequest{
		PluginID:        "demo-plugin",
		ProtocolVersion: "1.0.0",
		RunID:           "run-1",
		InputHash:       "sha256:test",
		RepoRoot:        dir,
		WorkingDir:      dir,
		OutputDir:       filepath.Join(dir, "out"),
	})
	if err == nil || result != nil {
		t.Fatal("public runtime must refuse unsandboxed plugin execution")
	}
}

func TestRunRejectsProtocolMismatch(t *testing.T) {
	dir := t.TempDir()
	pluginPath := filepath.Join(dir, "plugin.py")
	writePluginFile(t, pluginPath, `#!/usr/bin/env python3
import json
import sys

req = json.loads(sys.stdin.read())
sys.stdout.write(json.dumps({
  "pluginId": req["pluginId"],
  "protocolVersion": "2.0.0",
  "status": "ok",
  "violations": []
}))
`, 0o755)
	manifestPath := writePluginManifest(t, dir, map[string]any{
		"schemaVersion": "1.0.0",
		"pluginId":      "demo-plugin",
		"entrypoint":    "plugin.py",
		"runtime":       "python3",
		"protocol":      "1.0.0",
		"compatWindow": map[string]any{
			"minProtocol": "1.0.0",
			"maxProtocol": "1.x",
		},
		"capabilities": []string{"verify"},
	})

	manifest, err := Load(manifestPath)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if _, err := Run(manifest, RunRequest{
		PluginID:        "demo-plugin",
		ProtocolVersion: "1.0.0",
		RunID:           "run-1",
		InputHash:       "sha256:test",
		RepoRoot:        dir,
		WorkingDir:      dir,
		OutputDir:       filepath.Join(dir, "out"),
	}); err == nil {
		t.Fatal("expected unsandboxed plugin execution to fail")
	}
}

func TestValidateManifestConsistencyRejectsLowTimeout(t *testing.T) {
	m := Manifest{PluginID: "test", Runtime: "go", TimeoutMs: 500}
	if err := ValidateManifestConsistency(m); err == nil {
		t.Fatal("expected error for low timeout")
	}
}

func TestValidateManifestConsistencyAcceptsValid(t *testing.T) {
	m := Manifest{PluginID: "test", Runtime: "go", TimeoutMs: 30000, Capabilities: []string{"scan", "lint"}}
	if err := ValidateManifestConsistency(m); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateManifestConsistencyRejectsDupCap(t *testing.T) {
	m := Manifest{PluginID: "test", Runtime: "go", TimeoutMs: 30000, Capabilities: []string{"scan", "scan"}}
	if err := ValidateManifestConsistency(m); err == nil {
		t.Fatal("expected error for duplicate capability")
	}
}

func TestCollectPluginResultsAggregates(t *testing.T) {
	runs := []RunResult{
		{PluginID: "a", ExitCode: 0, Response: Response{Violations: []Violation{{RuleID: "r1", Severity: "high", Message: "bad"}}}},
		{PluginID: "b", ExitCode: 1, Response: Response{Violations: []Violation{{RuleID: "r2", Severity: "low", Message: "warn"}}}},
	}
	agg := CollectPluginResults(runs)
	if agg.TotalViolations != 2 {
		t.Fatalf("expected 2 violations, got %d", agg.TotalViolations)
	}
	if agg.FailedPlugins != 1 {
		t.Fatalf("expected 1 failed plugin, got %d", agg.FailedPlugins)
	}
}
