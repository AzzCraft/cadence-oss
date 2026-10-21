package baseline

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/AzzCraft/cadence-oss/cadence-core/internal/exactjson"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/AzzCraft/cadence-oss/cadence-core/internal/checks"
)

type Baseline struct {
	SchemaVersion string   `json:"schemaVersion"`
	Fingerprints  []string `json:"fingerprints"`
}

func Load(path string) (Baseline, error) {
	b := Baseline{SchemaVersion: "1.0.0", Fingerprints: []string{}}
	data, err := os.ReadFile(path)
	if err != nil {
		return b, err
	}
	parsed, err := exactjson.Parse(data)
	if err != nil {
		return b, err
	}
	object, ok := parsed.(map[string]any)
	if !ok || object["schemaVersion"] != "1.0.0" || object["fingerprints"] == nil {
		return b, fmt.Errorf("invalid baseline object")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&b); err != nil {
		return b, err
	}
	return b, nil
}

func Save(path string, violations []checks.Violation) error {
	m := map[string]bool{}
	for _, v := range violations {
		m[v.Fingerprint] = true
	}
	fps := make([]string, 0, len(m))
	for fp := range m {
		fps = append(fps, fp)
	}
	b := Baseline{SchemaVersion: "1.0.0", Fingerprints: fps}
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func Contains(b Baseline, fp string) bool {
	for _, x := range b.Fingerprints {
		if x == fp {
			return true
		}
	}
	return false
}

// DiffResult holds the fingerprints that differ between two baselines.
type DiffResult struct {
	Added   []string `json:"added"`
	Removed []string `json:"removed"`
}

// Diff compares two baselines and returns fingerprints added in b2 but not b1,
// and fingerprints removed (in b1 but not b2).
func Diff(b1, b2 Baseline) DiffResult {
	set1 := map[string]bool{}
	for _, fp := range b1.Fingerprints {
		set1[fp] = true
	}
	set2 := map[string]bool{}
	for _, fp := range b2.Fingerprints {
		set2[fp] = true
	}
	var added, removed []string
	for fp := range set2 {
		if !set1[fp] {
			added = append(added, fp)
		}
	}
	for fp := range set1 {
		if !set2[fp] {
			removed = append(removed, fp)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return DiffResult{Added: added, Removed: removed}
}

// BaselineSnapshot captures a baseline at a point in time for auditing.
type BaselineSnapshot struct {
	SchemaVersion string   `json:"schemaVersion"`
	SnapshotID    string   `json:"snapshotId"`
	Timestamp     string   `json:"timestamp"`
	PolicyVersion string   `json:"policyVersion"`
	Fingerprints  []string `json:"fingerprints"`
}

// SnapshotBaseline creates a timestamped snapshot of the current baseline.
func SnapshotBaseline(b Baseline, policyVersion string) BaselineSnapshot {
	fps := make([]string, len(b.Fingerprints))
	copy(fps, b.Fingerprints)
	sort.Strings(fps)
	return BaselineSnapshot{
		SchemaVersion: "1.0.0",
		SnapshotID:    fmt.Sprintf("snap-%d", time.Now().UnixNano()),
		Timestamp:     time.Now().UTC().Format(time.RFC3339),
		PolicyVersion: policyVersion,
		Fingerprints:  fps,
	}
}
