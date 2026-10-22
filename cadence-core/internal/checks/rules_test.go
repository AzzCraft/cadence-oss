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

func TestContractFixtureLayouts(t *testing.T) {
	for _, name := range []string{"payment.schema.json", "payment.json"} {
		for _, layout := range []string{"canonical", "legacy"} {
			root := t.TempDir()
			if err := os.MkdirAll(filepath.Join(root, "contracts/schemas"), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "contracts/schemas", name), []byte(`{"type":"object"}`), 0600); err != nil {
				t.Fatal(err)
			}
			dirs := []string{"contracts/fixtures/payment/valid", "contracts/fixtures/payment/invalid"}
			if layout == "legacy" {
				dirs = []string{"contracts/fixtures/payment"}
			}
			for _, dir := range dirs {
				os.MkdirAll(filepath.Join(root, dir), 0700)
				os.WriteFile(filepath.Join(root, dir, "case.json"), []byte(`{}`), 0600)
			}
			findings, err := checkContractCompleteness(root)
			if err != nil || len(findings) != 0 {
				t.Fatalf("%s %s: %v %v", name, layout, findings, err)
			}
			os.Remove(filepath.Join(root, dirs[0], "case.json"))
			findings, err = checkContractCompleteness(root)
			if err != nil || len(findings) != 1 {
				t.Fatalf("missing target fixture accepted: %v %v", findings, err)
			}
		}
	}
}

func TestPublicContractHubFixturesAndDefinitionLibrary(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join("..", "..", "..", "contracts-hub-template", "contracts")
	if err := os.CopyFS(filepath.Join(root, "contracts"), os.DirFS(source)); err != nil {
		t.Fatal(err)
	}
	findings, err := checkContractCompleteness(root)
	if err != nil || len(findings) != 0 {
		t.Fatalf("unchanged public contracts rejected: %v %v", findings, err)
	}
	// A real contract still needs its own fixtures; library detection must not
	// exempt an instance schema just because it also declares definitions.
	writeTestFile(t, root, "contracts/schemas/extra.schema.json", `{"$defs":{"name":{"type":"string"}},"type":"object","required":["name"]}`)
	findings, err = checkContractCompleteness(root)
	if err != nil || len(findings) != 1 || findings[0].RuleID != "CONTRACT_FIXTURE_MISSING" {
		t.Fatalf("missing instance fixtures not rejected: %v %v", findings, err)
	}
}

func TestRepeatedFindingsRetainActualLinesAndDistinctIdentity(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "source.env", "# start\nTEST_AUTH_TOKEN=synthetic-secret-token\n# middle\nTEST_AUTH_TOKEN=synthetic-secret-token\n")
	findings, err := RunAll(root)
	if err != nil {
		t.Fatal(err)
	}
	lines := map[int]bool{}
	identities := map[string]bool{}
	for _, v := range findings {
		if v.RuleID == "SEC_TEST_AUTH_TOKEN" {
			lines[v.Line] = true
			identities[v.Fingerprint] = true
		}
	}
	if len(lines) != 2 || !lines[2] || !lines[4] || len(identities) != 2 {
		t.Fatalf("locations collapsed: %+v", findings)
	}
}

func TestRootDirectoryNameNeverExemptsSource(t *testing.T) {
	for _, name := range []string{"ordinary", "build", "dist", "node_modules", ".cadence"} {
		t.Run(name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), name)
			if err := os.Mkdir(root, 0o755); err != nil {
				t.Fatal(err)
			}
			writeTestFile(t, root, "input.env", "TEST_AUTH_TOKEN=synthetic\n")
			found, err := RunAll(root)
			if err != nil || len(found) != 1 || found[0].RuleID != "SEC_TEST_AUTH_TOKEN" {
				t.Fatalf("root exempted: %v %v", found, err)
			}
		})
	}
}

func TestJSImportDeclarationBoundariesAndEscapes(t *testing.T) {
	for _, tc := range []struct {
		source string
		want   int
	}{
		{"const first = 1, second = 2\nexport { first }\nexport { second }\nimport value from 'pkg/internal/value'\n", 1},
		{`import value from 'pkg\u002finternal\u002fvalue';`, 1},
		{`export { value } from 'pkg\x2fsrc\x2fvalue';`, 1},
		{`import('pkg\u{2f}internal\/value');`, 1},
		{"import 'pkg/inte\\\nrnal/value';", 1},
		{`import value from 'pkg\\u002finternal/value';`, 0},
		{"const text = \"import value from 'pkg/internal/example'\";\n// import 'pkg/src/comment';", 0},
	} {
		root := t.TempDir()
		writeTestFile(t, root, "input.ts", tc.source)
		found, err := RunAll(root)
		if err != nil || len(found) != tc.want {
			t.Fatalf("%q: got %+v, %v; want %d", tc.source, found, err, tc.want)
		}
		if tc.want > 0 && found[0].Message != "Deep import detected: pkg/internal/value" && found[0].Message != "Deep import detected: pkg/src/value" {
			t.Fatalf("module literal not normalized: %+v", found)
		}
	}
}

func TestImportsAndSecretContentRetainDistinctFindings(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "input.ts", "import 'pkg/internal/side';\nimport {\n x\n} /* comment */ from 'pkg/src/multi';\nexport { x } from 'pkg/internal/export';\n// import 'pkg/internal/comment';\nconst text = \"import 'pkg/internal/string'\";\nimport { from as local } from 'pkg/internal/named';\nexport { from } from 'pkg/src/named-export';\n")
	found, executed, err := RunAllWithTrace(root)
	if err != nil || len(found) != 5 || len(executed) != 9 {
		t.Fatalf("imports/trace: %v %v %v", found, executed, err)
	}
	writeTestFile(t, root, "key.env", "token='synthetic-first-token'\n")
	a, _ := RunAll(root)
	writeTestFile(t, root, "key.env", "token='synthetic-other-token'\n")
	b, _ := RunAll(root)
	var first, second string
	for _, item := range a {
		if item.File == "key.env" {
			first = item.Fingerprint
		}
	}
	for _, item := range b {
		if item.File == "key.env" {
			second = item.Fingerprint
		}
	}
	if first == "" || second == "" || first == second {
		t.Fatal("new content reused old baseline identity")
	}
}
