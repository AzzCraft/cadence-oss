// Package runid — stable run identifiers.
//
// DAS-04-002: A run-id is the SHA-256 of a canonical descriptor of the
// run inputs (workspace hash, profile, attempt). Two invocations with
// identical inputs and the same attempt produce the same id; bumping the
// attempt counter produces a different id.
package runid

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"

	"github.com/AzzCraft/cadence-oss/cadence-core/internal/clock"
)

// Inputs describes a run.
type Inputs struct {
	WorkspaceHash string
	Profile       string
	Attempt       int
	Extra         map[string]string
}

// DeterministicRun is the CAD-001 stable pair emitted for replay evidence.
type DeterministicRun struct {
	RunID     string `json:"runId"`
	Timestamp string `json:"timestamp"`
}

// Diagnostic describes a deterministic run contract mismatch.
type Diagnostic struct {
	Task    string `json:"task"`
	Field   string `json:"field"`
	Message string `json:"message"`
}

// Make returns a stable hex-encoded SHA-256 of canonical Inputs.
func Make(in Inputs) string {
	h := sha256.New()
	// v2 length-delimits every arbitrary string, including invalid UTF-8 bytes.
	// This internal helper has no CLI/persisted-ID compatibility contract.
	h.Write([]byte("cadence-runid-v2\x00"))
	field := func(value string) {
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(value)))
		h.Write(size[:])
		h.Write([]byte(value))
	}
	field(in.WorkspaceHash)
	field(in.Profile)
	field(fmt.Sprint(in.Attempt))
	keys := make([]string, 0, len(in.Extra))
	for key := range in.Extra {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		field(key)
		field(in.Extra[key])
	}
	return hex.EncodeToString(h.Sum(nil))
}

// NewDeterministicRun returns the CAD-001 run-id/timestamp pair for inputs.
func NewDeterministicRun(in Inputs, clk clock.Clock) DeterministicRun {
	return DeterministicRun{
		RunID:     Make(in),
		Timestamp: clock.RFC3339(clk),
	}
}

// ValidateStablePair reports a CAD-001 diagnostic when a deterministic field drifts.
func ValidateStablePair(field string, expected string, actual string) *Diagnostic {
	if expected == actual {
		return nil
	}
	return &Diagnostic{
		Task:    "CAD-001",
		Field:   field,
		Message: fmt.Sprintf("CAD-001 deterministic run %s mismatch: expected %q, got %q", field, expected, actual),
	}
}
