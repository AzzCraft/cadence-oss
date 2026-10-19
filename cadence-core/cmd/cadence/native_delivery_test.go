package main

import (
	"encoding/json"
	"errors"
	"github.com/AzzCraft/cadence-oss/cadence-core/internal/evidence"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestAtomicAliasPreservesPreviousSuccessAndLegacyDirectory(t *testing.T) {
	root := t.TempDir()
	seed := func(name string) string {
		dir := filepath.Join(root, name)
		os.Mkdir(dir, 0700)
		for _, name := range append(append([]string{}, evidence.RequiredRunArtifacts...), "evidence-bundle.json", "replay-package.json", "replay-bundle.json") {
			os.WriteFile(filepath.Join(dir, name), []byte("fixture"), 0600)
		}
		return dir
	}
	first := seed("first")
	alias := filepath.Join(root, "latest")
	if err := writeStableAlias(root, alias, first, "first"); err != nil {
		t.Fatal(err)
	}
	old, _ := os.Readlink(alias)
	second := seed("second")
	os.Remove(filepath.Join(second, "evidence-bundle.json"))
	if err := writeStableAlias(root, alias, second, "second"); err == nil {
		t.Fatal("published incomplete run")
	}
	now, _ := os.Readlink(alias)
	if now != old {
		t.Fatal("lost prior success")
	}
	legacy := filepath.Join(root, "legacy")
	os.Mkdir(legacy, 0700)
	os.WriteFile(filepath.Join(legacy, "kept"), []byte("previous output"), 0600)
	if err := writeStableAlias(root, legacy, first, "first"); err == nil {
		t.Fatal("silently replaced legacy directory")
	}
	if data, err := os.ReadFile(filepath.Join(legacy, "kept")); err != nil || string(data) != "previous output" {
		t.Fatal("lost legacy output")
	}
}

func TestDeliveryFailureReportsNonzeroWithoutChangingScanOutcome(t *testing.T) {
	if dir := os.Getenv("CADENCE_TEST_DELIVERY_FAILURE_DIR"); dir != "" {
		deliveryFailure(dir, errors.New("synthetic required write failure"))
		return
	}
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "summary.json"), []byte(`{"decision":"pass","status":"ok"}`), 0600)
	command := exec.Command(os.Args[0], "-test.run=^TestDeliveryFailureReportsNonzeroWithoutChangingScanOutcome$")
	command.Env = append(os.Environ(), "CADENCE_TEST_DELIVERY_FAILURE_DIR="+dir)
	if out, err := command.CombinedOutput(); err == nil {
		t.Fatalf("required failure returned zero: %s", out)
	}
	data, err := os.ReadFile(filepath.Join(dir, "delivery-error.json"))
	if err != nil || len(data) == 0 {
		t.Fatal("missing structured delivery failure")
	}
	data, err = os.ReadFile(filepath.Join(dir, "summary.json"))
	if err != nil {
		t.Fatal(err)
	}
	var summary map[string]any
	if err = json.Unmarshal(data, &summary); err != nil || summary["decision"] != "pass" || summary["deliveryComplete"] != false {
		t.Fatalf("scan/delivery facts were conflated: %s", data)
	}
}
