package main

import (
	"encoding/json"
	"io"
	"os"
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
