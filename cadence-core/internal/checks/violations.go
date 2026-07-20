package checks

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

type Severity string

const (
	SevP0 Severity = "P0"
	SevP1 Severity = "P1"
	SevP2 Severity = "P2"
)

// Violation is a deterministic rule finding. It is intentionally small.
// Production implementations SHOULD include structured evidence pointers.
type Violation struct {
	RuleID      string   `json:"ruleId"`
	Severity    Severity `json:"severity"`
	Message     string   `json:"message"`
	File        string   `json:"file,omitempty"`
	Line        int      `json:"line,omitempty"`
	Fingerprint string   `json:"fingerprint"`
}

func New(ruleID string, severity Severity, message string, file string, line int) Violation {
	fp := fingerprint(ruleID, message, file, line)
	return Violation{
		RuleID:      ruleID,
		Severity:    severity,
		Message:     message,
		File:        file,
		Line:        line,
		Fingerprint: fp,
	}
}

func fingerprint(ruleID, message, file string, line int) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s\n%s\n%s\n%d", ruleID, message, file, line)))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// FilterBySeverity returns only violations matching the given severity.
func FilterBySeverity(violations []Violation, sev Severity) []Violation {
	var out []Violation
	for _, v := range violations {
		if v.Severity == sev {
			out = append(out, v)
		}
	}
	return out
}

// GroupByFile groups violations by their source file path.
func GroupByFile(violations []Violation) map[string][]Violation {
	groups := make(map[string][]Violation)
	for _, v := range violations {
		key := v.File
		if key == "" {
			key = "(no file)"
		}
		groups[key] = append(groups[key], v)
	}
	return groups
}
