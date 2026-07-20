package checks

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTestFile(t *testing.T, root, rel, content string) {
	t.Helper()
	path := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestRunAllDetectsAWSKey(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "config.py", "AWS_KEY = '"+"AKIA"+"IOSFODNN7EXAMPLE"+"'\n")
	violations, err := RunAll(root)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, v := range violations {
		if v.RuleID == "SEC_AWS_KEY" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected SEC_AWS_KEY violation")
	}
}

func TestRunAllDetectsGitHubToken(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "ci.sh", "TOKEN="+"ghp_"+"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"+"\n")
	violations, err := RunAll(root)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, v := range violations {
		if v.RuleID == "SEC_GITHUB_TOKEN" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected SEC_GITHUB_TOKEN violation")
	}
}

func TestRunAllDetectsPrivateKey(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "key.pem", "-----BEGIN "+"RSA PRIVATE KEY"+"-----\nfake\n-----END "+"RSA PRIVATE KEY"+"-----\n")
	violations, err := RunAll(root)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, v := range violations {
		if v.RuleID == "SEC_PRIVATE_KEY" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected SEC_PRIVATE_KEY violation")
	}
}

func TestRunAllCleanRepo(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "main.go", "package main\nfunc main() {}\n")
	violations, err := RunAll(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range violations {
		if v.RuleID[:4] == "SEC_" {
			t.Fatalf("unexpected secret violation in clean repo: %s", v.RuleID)
		}
	}
}

func TestFilterBySeverity(t *testing.T) {
	vs := []Violation{
		New("R1", SevP0, "crit", "a.go", 1),
		New("R2", SevP1, "warn", "b.go", 2),
		New("R3", SevP0, "crit2", "c.go", 3),
	}
	p0 := FilterBySeverity(vs, SevP0)
	if len(p0) != 2 {
		t.Fatalf("expected 2 P0 violations, got %d", len(p0))
	}
	p2 := FilterBySeverity(vs, SevP2)
	if len(p2) != 0 {
		t.Fatalf("expected 0 P2 violations, got %d", len(p2))
	}
}

func TestGroupByFile(t *testing.T) {
	vs := []Violation{
		New("R1", SevP0, "a", "file1.go", 1),
		New("R2", SevP0, "b", "file1.go", 2),
		New("R3", SevP1, "c", "file2.go", 3),
		New("R4", SevP1, "d", "", 0),
	}
	groups := GroupByFile(vs)
	if len(groups["file1.go"]) != 2 {
		t.Fatalf("expected 2 for file1.go, got %d", len(groups["file1.go"]))
	}
	if len(groups["file2.go"]) != 1 {
		t.Fatalf("expected 1 for file2.go, got %d", len(groups["file2.go"]))
	}
	if len(groups["(no file)"]) != 1 {
		t.Fatalf("expected 1 for (no file), got %d", len(groups["(no file)"]))
	}
}
