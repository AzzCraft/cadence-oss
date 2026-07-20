// Package runid — stable run identifiers.
//
// DAS-04-002: A run-id is the SHA-256 of a canonical descriptor of the
// run inputs (workspace hash, profile, attempt). Two invocations with
// identical inputs and the same attempt produce the same id; bumping the
// attempt counter produces a different id.
package runid

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

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
	h.Write([]byte("workspaceHash="))
	h.Write([]byte(in.WorkspaceHash))
	h.Write([]byte("\nprofile="))
	h.Write([]byte(in.Profile))
	h.Write([]byte(fmt.Sprintf("\nattempt=%d\n", in.Attempt)))
	keys := make([]string, 0, len(in.Extra))
	for k := range in.Extra {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var sb strings.Builder
	for _, k := range keys {
		sb.WriteString(k)
		sb.WriteByte('=')
		sb.WriteString(in.Extra[k])
		sb.WriteByte('\n')
	}
	h.Write([]byte(sb.String()))
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
