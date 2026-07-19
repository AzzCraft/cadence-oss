package report

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Summary holds the top-level outcome of a cadence run.
type Summary struct {
	Status     string `json:"status"`
	Violations int    `json:"violations"`
}

// Finding represents a single policy or check violation/observation.
type Finding struct {
	RuleID   string `json:"ruleId"`
	Severity string `json:"severity"` // error, warning, info
	Message  string `json:"message"`
	FilePath string `json:"filePath,omitempty"`
}

// Report is the full structured report produced at the end of a cadence run.
type Report struct {
	SchemaVersion string    `json:"schemaVersion"`
	RunID         string    `json:"runId"`
	ProjectID     string    `json:"projectId"`
	Timestamp     string    `json:"timestamp"`
	Summary       Summary   `json:"summary"`
	Findings      []Finding `json:"findings"`
	Metrics       *Metrics  `json:"metrics,omitempty"`
}

// Metrics captures execution-level measurement data for the verify run.
type Metrics struct {
	FilesScanned   int `json:"filesScanned"`
	RulesEvaluated int `json:"rulesEvaluated"`
	DurationMs     int `json:"durationMs"`
}

func NewSummary(status string, violations int) Summary {
	return Summary{
		Status:     status,
		Violations: violations,
	}
}

// Generate builds a Report from a runID, projectID and a list of findings.
func Generate(runID, projectID string, findings []Finding) Report {
	violations := 0
	for _, f := range findings {
		if f.Severity == "error" {
			violations++
		}
	}
	status := "pass"
	if violations > 0 {
		status = "fail"
	}
	return Report{
		SchemaVersion: "1.0.0",
		RunID:         runID,
		ProjectID:     projectID,
		Timestamp:     time.Now().UTC().Format(time.RFC3339),
		Summary:       NewSummary(status, violations),
		Findings:      findings,
	}
}

// Save writes the report to disk as JSON.
func Save(path string, r Report) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Errorf("report: marshal: %w", err)
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

// Load reads a report from disk.
func Load(path string) (Report, error) {
	var r Report
	data, err := os.ReadFile(path)
	if err != nil {
		return r, err
	}
	err = json.Unmarshal(data, &r)
	return r, err
}

// WithMetrics attaches metrics to a report.
func WithMetrics(r Report, filesScanned, rulesEvaluated, durationMs int) Report {
	r.Metrics = &Metrics{
		FilesScanned:   filesScanned,
		RulesEvaluated: rulesEvaluated,
		DurationMs:     durationMs,
	}
	return r
}

// Validate checks that a report has all required fields and consistent status.
func Validate(r Report) error {
	if r.SchemaVersion == "" {
		return fmt.Errorf("report: schemaVersion is required")
	}
	if r.RunID == "" {
		return fmt.Errorf("report: runId is required")
	}
	if r.Timestamp == "" {
		return fmt.Errorf("report: timestamp is required")
	}
	if r.Summary.Status != "pass" && r.Summary.Status != "fail" && r.Summary.Status != "warn" {
		return fmt.Errorf("report: invalid status %q", r.Summary.Status)
	}
	return nil
}
