package report

import (
	"path/filepath"
	"testing"
)

func TestGeneratePass(t *testing.T) {
	findings := []Finding{
		{RuleID: "UI-001", Severity: "info", Message: "optional check"},
	}
	r := Generate("run-1", "demo", findings)
	if r.Summary.Status != "pass" {
		t.Fatalf("expected pass, got %s", r.Summary.Status)
	}
	if r.Summary.Violations != 0 {
		t.Fatalf("expected 0 violations, got %d", r.Summary.Violations)
	}
}

func TestGenerateFail(t *testing.T) {
	findings := []Finding{
		{RuleID: "SEC-001", Severity: "error", Message: "critical failure"},
		{RuleID: "UI-002", Severity: "warning", Message: "minor issue"},
	}
	r := Generate("run-2", "demo", findings)
	if r.Summary.Status != "fail" {
		t.Fatalf("expected fail, got %s", r.Summary.Status)
	}
	if r.Summary.Violations != 1 {
		t.Fatalf("expected 1 violation, got %d", r.Summary.Violations)
	}
}

func TestSaveAndLoad(t *testing.T) {
	findings := []Finding{
		{RuleID: "CHK-001", Severity: "error", Message: "missing file", FilePath: "README.md"},
	}
	r := Generate("run-3", "test-proj", findings)

	path := filepath.Join(t.TempDir(), "report.json")
	if err := Save(path, r); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if loaded.RunID != "run-3" {
		t.Fatalf("expected run-3, got %s", loaded.RunID)
	}
	if loaded.Summary.Violations != 1 {
		t.Fatal("loaded report violations mismatch")
	}
	if len(loaded.Findings) != 1 || loaded.Findings[0].RuleID != "CHK-001" {
		t.Fatal("loaded findings mismatch")
	}
}

func TestWithMetricsAttaches(t *testing.T) {
	r := Generate("run-m", "proj-m", nil)
	r2 := WithMetrics(r, 100, 50, 250)
	if r2.Metrics == nil {
		t.Fatal("metrics should be attached")
	}
	if r2.Metrics.FilesScanned != 100 {
		t.Fatalf("expected 100, got %d", r2.Metrics.FilesScanned)
	}
}

func TestValidateRejectsEmptyRunID(t *testing.T) {
	r := Report{SchemaVersion: "1.0.0", Timestamp: "2025-01-01T00:00:00Z", Summary: Summary{Status: "pass"}}
	if err := Validate(r); err == nil {
		t.Fatal("expected error for empty runId")
	}
}

func TestValidateAcceptsValid(t *testing.T) {
	r := Generate("run-v", "proj-v", nil)
	if err := Validate(r); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
