package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestChainScalarTypesCannotBecomeZeroValues(t *testing.T) {
	dir := t.TempDir()
	fixture := "../../tests/fixtures/cad002/valid/"
	bundle, err := os.ReadFile(fixture + "evidence-bundle.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "evidence-bundle.json"), bundle, 0600); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(fixture + "step-hash-chain.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"stepIndex", "evidencePath"} {
		t.Run(field, func(t *testing.T) {
			var chain map[string]any
			if err := json.Unmarshal(data, &chain); err != nil {
				t.Fatal(err)
			}
			chain["steps"].([]any)[0].(map[string]any)[field] = nil
			bad, err := json.Marshal(chain)
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(filepath.Join(dir, "step-hash-chain.json"), bad, 0600); err != nil {
				t.Fatal(err)
			}
			if result, rc := verifyBundle(filepath.Join(dir, "evidence-bundle.json")); rc == 0 || result.OK {
				t.Fatalf("accepted null %s: %+v", field, result)
			}
		})
	}
}

func TestEvidenceProfilesRejectEmptyConflictingAndEscapingInputs(t *testing.T) {
	dir := t.TempDir()
	bundle := filepath.Join(dir, "evidence-bundle.json")
	for _, body := range []string{`{}`, `null`, `{"task":"CAD-002","schemaVersion":"1.0.0","chainRef":"../outside"}`, `{"task":"CAD-002","task":"CAD-002"}`, `{"x":"\ud800"}`} {
		if err := os.WriteFile(bundle, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		for _, profile := range []string{"cad002/v1", "cadence-run/v1", "cadence-run/v2", "unknown"} {
			result, rc := verifyProfile(bundle, profile)
			if rc == 0 || result.OK {
				t.Fatalf("accepted %s with %s", body, profile)
			}
		}
	}
}

func TestHistoricalCAD002AndNativeProfileAreNeverInterchanged(t *testing.T) {
	fixture := "../../tests/fixtures/cad002/valid/evidence-bundle.json"
	result, rc := verifyBundle(fixture)
	if rc != 0 || !result.OK {
		t.Fatalf("historical diagnostic rejected: %+v", result)
	}
	for _, profile := range []string{"cadence-run/v1", "cadence-run/v2"} {
		result, rc = verifyProfile(fixture, profile)
		if rc == 0 || result.OK {
			t.Fatal("accepted a different format")
		}
	}
}
