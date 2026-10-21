package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AzzCraft/cadence-oss/cadence-core/internal/replay"
)

func TestReplayCLIValidatesInputsAndRedactsTypedReports(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "replay")
	if out, err := exec.Command("go", "build", "-buildvcs=false", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, out)
	}
	makeBundle := func(content string) string {
		dir := t.TempDir()
		for _, name := range []string{"manifest.json", "result.json", "tester@example.invalid-secret-token-synthetic.txt"} {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0600); err != nil {
				t.Fatal(err)
			}
		}
		bundle, err := replay.Build("run", "manifest.json", "result.json", dir)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "bundle.json")
		if err := replay.Save(path, bundle); err != nil {
			t.Fatal(err)
		}
		return path
	}
	left, right := makeBundle("same"), makeBundle("same")
	run := func(actual string) ([]byte, error) {
		return exec.Command(bin, "--expected", left, "--actual", actual).CombinedOutput()
	}
	out, err := run(right)
	if err != nil || !strings.Contains(string(out), `"same":true`) {
		t.Fatalf("valid comparison: %v %s", err, out)
	}
	if strings.Contains(string(out), "tester@example.invalid") || strings.Contains(string(out), "secret-token-synthetic") || !strings.Contains(string(out), "<email>") {
		t.Fatalf("typed report was not redacted: %s", out)
	}
	for _, mutation := range []string{"empty", "duplicate-key", "duplicate-path", "metadata"} {
		raw, err := os.ReadFile(left)
		if err != nil {
			t.Fatal(err)
		}
		var bundle replay.Bundle
		if err = json.Unmarshal(raw, &bundle); err != nil {
			t.Fatal(err)
		}
		switch mutation {
		case "empty":
			raw = []byte(`{}`)
		case "duplicate-key":
			raw = append([]byte(`{"schemaVersion":"1.0.0",`), raw[1:]...)
		case "duplicate-path":
			bundle.Snapshots = append(bundle.Snapshots, bundle.Snapshots[0])
			raw, _ = json.Marshal(bundle)
		case "metadata":
			bundle.Snapshots[0].Size++
			raw, _ = json.Marshal(bundle)
		}
		path := filepath.Join(t.TempDir(), "mutated.json")
		os.WriteFile(path, raw, 0600)
		if output, err := run(path); err == nil {
			t.Fatalf("%s accepted: %s", mutation, output)
		}
	}
	alias := filepath.Join(t.TempDir(), "alias.json")
	if err := os.Link(left, alias); err != nil {
		t.Fatal(err)
	}
	if output, err := run(alias); err == nil {
		t.Fatalf("same inode accepted: %s", output)
	}
	different := makeBundle("changed")
	var previous string
	for i := 0; i < 12; i++ {
		output, err := run(different)
		if err == nil || !strings.Contains(string(output), `"same":false`) {
			t.Fatalf("difference accepted: %s", output)
		}
		if i > 0 && string(output) != previous {
			t.Fatal("nondeterministic comparison output")
		}
		previous = string(output)
	}
}
