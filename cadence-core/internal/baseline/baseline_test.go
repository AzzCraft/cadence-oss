package baseline

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDiffDetectsAdded(t *testing.T) {
	b1 := Baseline{Fingerprints: []string{"a", "b"}}
	b2 := Baseline{Fingerprints: []string{"a", "b", "c"}}
	d := Diff(b1, b2)
	if len(d.Added) != 1 || d.Added[0] != "c" {
		t.Fatalf("expected added=[c], got %v", d.Added)
	}
	if len(d.Removed) != 0 {
		t.Fatalf("expected no removed, got %v", d.Removed)
	}
}

func TestDiffDetectsRemoved(t *testing.T) {
	b1 := Baseline{Fingerprints: []string{"a", "b", "c"}}
	b2 := Baseline{Fingerprints: []string{"a"}}
	d := Diff(b1, b2)
	if len(d.Removed) != 2 {
		t.Fatalf("expected 2 removed, got %v", d.Removed)
	}
}

func TestDiffIdentical(t *testing.T) {
	b := Baseline{Fingerprints: []string{"x", "y"}}
	d := Diff(b, b)
	if len(d.Added) != 0 || len(d.Removed) != 0 {
		t.Fatal("identical baselines should produce empty diff")
	}
}

func TestSnapshotBaseline(t *testing.T) {
	b := Baseline{Fingerprints: []string{"b", "a"}}
	snap := SnapshotBaseline(b, "v1.0.0")
	if snap.PolicyVersion != "v1.0.0" {
		t.Fatalf("expected v1.0.0, got %s", snap.PolicyVersion)
	}
	if len(snap.Fingerprints) != 2 || snap.Fingerprints[0] != "a" {
		t.Fatal("fingerprints should be sorted")
	}
}

func TestLoadRejectsMalformedBaselineAndRoundTripsSavedValues(t *testing.T) {
	path := filepath.Join(t.TempDir(), "baseline.json")
	for _, value := range []string{`{}`, `null`, `{"schemaVersion":"1.0.0","fingerprints":null}`, `{"schemaVersion":"1.0.0","fingerprints":[true]}`, `{"schemaVersion":"1.0.0","fingerprints":[],"fingerprints":["x"]}`, `{"schemaVersion":"1.0.0","fingerprints":[],"extra":true}`} {
		os.WriteFile(path, []byte(value), 0600)
		if _, err := Load(path); err == nil {
			t.Fatal("malformed baseline accepted", value)
		}
	}
	if err := Save(path, nil); err != nil {
		t.Fatal(err)
	}
	if got, err := Load(path); err != nil || len(got.Fingerprints) != 0 {
		t.Fatal(got, err)
	}
}
