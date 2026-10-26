package main

import (
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestReportDisplayQuotesUntrustedPathAndKeepsMultilineLogData(t *testing.T) {
	root := t.TempDir()
	name := filepath.Join(root, "report\n::warning::TEST-path\n\x1b[31m.json")
	value := map[string]any{"message": "legal first\nlegal second\n::set-output name=approval::true\n\x1b[2J<script>TEST()</script>", "approved": false}
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	original := os.Stdout
	defer func() { os.Stdout = original }()
	os.Stdout = writer
	reportCmd([]string{"--in", name})
	writer.Close()
	os.Stdout = original
	shown, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	text := string(shown)
	if strings.ContainsAny(text, "\x1b\r") || strings.Contains(text, "\n::") || strings.Contains(text, "<script>") {
		t.Fatalf("report display emitted raw control syntax: %q", shown)
	}
	parts := strings.SplitN(text, "\n\n", 2)
	if len(parts) != 2 || !strings.Contains(parts[0], `Input: "`) || !strings.Contains(parts[0], `\n::warning::TEST-path\n\x1b[31m`) {
		t.Fatalf("path is not a quoted single-line value: %q", shown)
	}
	var observed map[string]any
	if err := json.Unmarshal([]byte(parts[1]), &observed); err != nil || observed["message"] != value["message"] || observed["approved"] != false {
		t.Fatal("display lost literal log data or changed approval", observed, err)
	}
	unchanged, err := os.ReadFile(name)
	if err != nil || string(unchanged) != string(raw) {
		t.Fatal("display changed the raw input", err)
	}
}

func TestSafeOutputRootRejectsSymlinkAncestor(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink setup requires platform privileges on Windows")
	}
	root := t.TempDir()
	outside := t.TempDir()
	link := filepath.Join(root, "linked-output")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	if _, err := safeOutputRoot(root, filepath.Join(link, "runs")); err == nil {
		t.Fatal("expected a symlinked output ancestor to be rejected")
	}
}

func TestWriteStableAliasRejectsRunCollision(t *testing.T) {
	root := t.TempDir()
	run := filepath.Join(root, "same")
	if err := os.Mkdir(run, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := writeStableAlias(root, run, run, "same"); err == nil {
		t.Fatal("expected alias/run directory collision to be rejected")
	}
}

func TestOnlyConfiguredOutputsAreExcludedFromSourceIdentity(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "src")
	fake := filepath.Join(source, "run")
	if err := os.MkdirAll(fake, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"run-manifest.json", "pipeline-result.json", "job-envelope.json"} {
		if err := os.WriteFile(filepath.Join(fake, name), []byte("{}"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	file := filepath.Join(source, "app.py")
	if err := os.WriteFile(file, []byte("first"), 0600); err != nil {
		t.Fatal(err)
	}
	prefixes, err := prepareGovernedOutputRoots(root, filepath.Join(root, "custom-output"))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range prefixes {
		if p == "src" {
			t.Fatal("artifact names exempted source")
		}
	}
	_, before, err := computeSourceTreeIdentity(root, prefixes)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	_, after, err := computeSourceTreeIdentity(root, prefixes)
	if err != nil || before == after {
		t.Fatalf("source change not bound: %v", err)
	}
	out := filepath.Join(root, "custom-output")
	if err := os.Mkdir(out, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(out, "output.txt"), []byte("output"), 0600); err != nil {
		t.Fatal(err)
	}
	_, repeated, err := computeSourceTreeIdentity(root, prefixes)
	if err != nil || repeated != after {
		t.Fatalf("configured output changed identity: %v", err)
	}
}

func TestLegacyLockRejectsWrongNestingAndTypes(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	good := "cadence_cli:\n  version: '1.5.0-beta.1'\n  sha256: '" + digest + "'\nplugins: []\nrunners: []\n"
	if version, sha, err := parseLegacyLock([]byte(good)); err != nil || version != "1.5.0-beta.1" || sha != digest {
		t.Fatalf("valid lock: %s %s %v", version, sha, err)
	}
	for _, bad := range []string{
		"unrelated:\n  version: '1.5.0-beta.1'\n  sha256: '" + digest + "'\n",
		strings.Replace(good, "  version:", "  nested:\n    version:", 1),
		strings.Replace(good, "plugins: []", "plugins: invalid", 1),
		strings.Replace(good, "'1.5.0-beta.1'", "true", 1),
		strings.Replace(good, digest, "bad", 1),
		good + "---\n{}\n", good + "cadence_cli: {}\n",
	} {
		if _, _, err := parseLegacyLock([]byte(bad)); err == nil {
			t.Errorf("invalid legacy lock accepted: %s", bad)
		}
	}
}

func TestLockPositionalArgumentsCannotWrite(t *testing.T) {
	if os.Getenv("CADENCE_LOCK_ARGS_CHILD") == "1" {
		lockCmd([]string{"unexpected", "--check"})
		return
	}
	root := t.TempDir()
	path := filepath.Join(root, "cadence.lock")
	before := []byte("preserve this lock\n")
	os.WriteFile(path, before, 0600)
	cmd := exec.Command(os.Args[0], "-test.run=^TestLockPositionalArgumentsCannotWrite$")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "CADENCE_LOCK_ARGS_CHILD=1")
	output, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(output), "unexpected positional") {
		t.Fatal(string(output), err)
	}
	after, _ := os.ReadFile(path)
	if string(after) != string(before) {
		t.Fatal("lock changed")
	}
}

func TestDoctorProbesDirectoryAndRemovesProbe(t *testing.T) {
	root := t.TempDir()
	if err := probeWritableDirectory(root); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(root)
	if len(entries) != 0 {
		t.Fatal("probe leaked")
	}
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("read-only mode test requires non-root Unix")
	}
	os.Chmod(root, 0500)
	defer os.Chmod(root, 0700)
	if err := probeWritableDirectory(root); err == nil {
		t.Fatal("read-only directory accepted")
	}
}
