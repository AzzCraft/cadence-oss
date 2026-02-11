package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

const (
	SchemaVersionV1 = "1.0.0"
)

var (
	semverRe = regexp.MustCompile(`^\d+\.\d+\.\d+$`)
	shaRe    = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

type Correlation struct {
	RequestID string `json:"requestId,omitempty"`
	TraceID   string `json:"traceId,omitempty"`
}

type Pipeline struct {
	ID string `json:"id"`
}

type Algorithm struct {
	Version string `json:"version"`
	Build   string `json:"build,omitempty"`
}

type ConfigRef struct {
	ProfileID  string `json:"profileId"`
	ConfigID   string `json:"configId,omitempty"`
	ConfigHash string `json:"configHash,omitempty"`
}

type InputRef struct {
	RawInputID string `json:"rawInputId"`
	InputHash  string `json:"inputHash,omitempty"`
	SnapshotID string `json:"snapshotId,omitempty"`
}

type Determinism struct {
	Tier        string         `json:"tier"`
	Seed        int64          `json:"seed,omitempty"`
	Concurrency map[string]any `json:"concurrency,omitempty"`
}

type BudgetTermination struct {
	Code string `json:"code"`
}

type Budget struct {
	Scope       string             `json:"scope"`
	Allocated   map[string]float64 `json:"allocated"`
	Consumed    map[string]float64 `json:"consumed"`
	Remaining   map[string]float64 `json:"remaining"`
	Termination BudgetTermination  `json:"termination"`
	Children    []Budget           `json:"children"`
}

type Diagnostics struct {
	Codes    []string           `json:"codes"`
	KV       map[string]any     `json:"kv,omitempty"`
	Counters map[string]float64 `json:"counters,omitempty"`
	Notes    []string           `json:"notes,omitempty"`
}

type StageSummary struct {
	StageID string   `json:"stageId"`
	Status  string   `json:"status"`
	TimeMs  float64  `json:"timeMs"`
	Codes   []string `json:"codes"`
}

type ErrorEnvelope struct {
	Code        string         `json:"code"`
	Kind        string         `json:"kind"`
	Message     string         `json:"message"`
	Retryable   bool           `json:"retryable"`
	Details     map[string]any `json:"details,omitempty"`
	Correlation *Correlation   `json:"correlation,omitempty"`
}

type ManifestRef struct {
	RunID        string `json:"runId"`
	ManifestHash string `json:"manifestHash"`
}

type RunManifest struct {
	SchemaVersion   string            `json:"schemaVersion"`
	RunID           string            `json:"runId"`
	CreatedAt       string            `json:"createdAt"`
	Correlation     *Correlation      `json:"correlation,omitempty"`
	Pipeline        Pipeline          `json:"pipeline"`
	Algorithm       Algorithm         `json:"algorithm"`
	Contracts       map[string]string `json:"contracts"`
	Config          ConfigRef         `json:"config"`
	InputRef        InputRef          `json:"inputRef"`
	SideEffectsMode string            `json:"sideEffectsMode"`
	Determinism     Determinism       `json:"determinism"`
	Budget          Budget            `json:"budget"`
	StageSummaries  []StageSummary    `json:"stageSummaries,omitempty"`
	Diagnostics     *Diagnostics      `json:"diagnostics,omitempty"`
}

type PipelineResult struct {
	SchemaVersion  string         `json:"schemaVersion"`
	RunID          string         `json:"runId"`
	Pipeline       Pipeline       `json:"pipeline"`
	Status         string         `json:"status"`
	Output         map[string]any `json:"output,omitempty"`
	Warnings       []string       `json:"warnings,omitempty"`
	StageSummaries []StageSummary `json:"stageSummaries,omitempty"`
	Budget         Budget         `json:"budget"`
	Diagnostics    *Diagnostics   `json:"diagnostics,omitempty"`
	ManifestRef    ManifestRef    `json:"manifestRef"`
	Error          *ErrorEnvelope `json:"error,omitempty"`
	// Extensions (allowed): callers may add extra JSON fields by embedding them in Output/Diagnostics.
}

type JobEnvelope struct {
	SchemaVersion   string         `json:"schemaVersion"`
	JobID           string         `json:"jobId"`
	JobType         string         `json:"jobType"`
	Status          string         `json:"status"`
	CreatedAt       string         `json:"createdAt"`
	UpdatedAt       string         `json:"updatedAt"`
	StartedAt       string         `json:"startedAt,omitempty"`
	FinishedAt      string         `json:"finishedAt,omitempty"`
	Correlation     *Correlation   `json:"correlation,omitempty"`
	ProfileID       string         `json:"profileId"`
	ConfigID        string         `json:"configId,omitempty"`
	ConfigHash      string         `json:"configHash,omitempty"`
	SideEffectsMode string         `json:"sideEffectsMode"`
	InputRef        *InputRef      `json:"inputRef,omitempty"`
	Runs            []JobRun       `json:"runs"`
	Diagnostics     *Diagnostics   `json:"diagnostics,omitempty"`
	Error           *ErrorEnvelope `json:"error,omitempty"`
}

type JobRun struct {
	Attempt     int            `json:"attempt"`
	StartedAt   string         `json:"startedAt"`
	FinishedAt  string         `json:"finishedAt"`
	ManifestRef ManifestRef    `json:"manifestRef"`
	Result      PipelineResult `json:"result"`
}

func CanonicalJSON(v any) ([]byte, error) {
	// encoding/json provides deterministic ordering for map keys.
	return json.Marshal(v)
}

func Sha256Prefixed(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func WriteCanonicalJSON(path string, v any) (string, error) {
	b, err := CanonicalJSON(v)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", err
	}
	// Hash is computed on the exact canonical bytes we write to disk.
	if err := os.WriteFile(path, b, 0o644); err != nil {
		return "", err
	}
	return Sha256Prefixed(b), nil
}

func ValidateRunManifest(m RunManifest) error {
	if !semverRe.MatchString(m.SchemaVersion) {
		return fmt.Errorf("runManifest.schemaVersion must be semver, got %q", m.SchemaVersion)
	}
	if m.RunID == "" {
		return errors.New("runManifest.runId is required")
	}
	if _, err := time.Parse(time.RFC3339, m.CreatedAt); err != nil {
		return fmt.Errorf("runManifest.createdAt must be RFC3339, got %q", m.CreatedAt)
	}
	if m.Pipeline.ID == "" {
		return errors.New("runManifest.pipeline.id is required")
	}
	if m.Algorithm.Version == "" {
		return errors.New("runManifest.algorithm.version is required")
	}
	if m.Contracts == nil {
		return errors.New("runManifest.contracts is required")
	}
	if m.Config.ProfileID == "" {
		return errors.New("runManifest.config.profileId is required")
	}
	if m.Config.ConfigID == "" && m.Config.ConfigHash == "" {
		return errors.New("runManifest.config must include configId or configHash")
	}
	if m.Config.ConfigHash != "" && !shaRe.MatchString(m.Config.ConfigHash) {
		return fmt.Errorf("runManifest.config.configHash must be sha256:..., got %q", m.Config.ConfigHash)
	}
	if m.InputRef.RawInputID == "" {
		return errors.New("runManifest.inputRef.rawInputId is required")
	}
	if m.InputRef.InputHash == "" && m.InputRef.SnapshotID == "" {
		return errors.New("runManifest.inputRef must include inputHash or snapshotId")
	}
	if m.InputRef.InputHash != "" && !shaRe.MatchString(m.InputRef.InputHash) {
		return fmt.Errorf("runManifest.inputRef.inputHash must be sha256:..., got %q", m.InputRef.InputHash)
	}
	switch m.SideEffectsMode {
	case "dryRun", "sandbox", "live":
	default:
		return fmt.Errorf("runManifest.sideEffectsMode invalid: %q", m.SideEffectsMode)
	}
	switch m.Determinism.Tier {
	case "tier0", "tier1", "tier2":
	default:
		return fmt.Errorf("runManifest.determinism.tier invalid: %q", m.Determinism.Tier)
	}
	if err := validateBudget(m.Budget, "runManifest.budget"); err != nil {
		return err
	}
	return nil
}

func ValidatePipelineResult(r PipelineResult) error {
	if !semverRe.MatchString(r.SchemaVersion) {
		return fmt.Errorf("pipelineResult.schemaVersion must be semver, got %q", r.SchemaVersion)
	}
	if r.RunID == "" {
		return errors.New("pipelineResult.runId is required")
	}
	if r.Pipeline.ID == "" {
		return errors.New("pipelineResult.pipeline.id is required")
	}
	switch r.Status {
	case "ok", "degraded", "error", "cancelled":
	default:
		return fmt.Errorf("pipelineResult.status invalid: %q", r.Status)
	}
	if r.ManifestRef.RunID == "" || r.ManifestRef.ManifestHash == "" {
		return errors.New("pipelineResult.manifestRef.runId and manifestHash are required")
	}
	if !shaRe.MatchString(r.ManifestRef.ManifestHash) {
		return fmt.Errorf("pipelineResult.manifestRef.manifestHash must be sha256:..., got %q", r.ManifestRef.ManifestHash)
	}
	if err := validateBudget(r.Budget, "pipelineResult.budget"); err != nil {
		return err
	}
	return nil
}

func ValidateJobEnvelope(j JobEnvelope) error {
	if !semverRe.MatchString(j.SchemaVersion) {
		return fmt.Errorf("jobEnvelope.schemaVersion must be semver, got %q", j.SchemaVersion)
	}
	if j.JobID == "" {
		return errors.New("jobEnvelope.jobId is required")
	}
	if j.JobType == "" {
		return errors.New("jobEnvelope.jobType is required")
	}
	switch j.Status {
	case "queued", "running", "succeeded", "failed", "degraded", "cancelled":
	default:
		return fmt.Errorf("jobEnvelope.status invalid: %q", j.Status)
	}
	if _, err := time.Parse(time.RFC3339, j.CreatedAt); err != nil {
		return fmt.Errorf("jobEnvelope.createdAt must be RFC3339, got %q", j.CreatedAt)
	}
	if _, err := time.Parse(time.RFC3339, j.UpdatedAt); err != nil {
		return fmt.Errorf("jobEnvelope.updatedAt must be RFC3339, got %q", j.UpdatedAt)
	}
	if j.ProfileID == "" {
		return errors.New("jobEnvelope.profileId is required")
	}
	switch j.SideEffectsMode {
	case "dryRun", "sandbox", "live":
	default:
		return fmt.Errorf("jobEnvelope.sideEffectsMode invalid: %q", j.SideEffectsMode)
	}
	if len(j.Runs) == 0 {
		return errors.New("jobEnvelope.runs must not be empty")
	}
	for i, run := range j.Runs {
		if run.Attempt < 1 {
			return fmt.Errorf("jobEnvelope.runs[%d].attempt must be >= 1", i)
		}
		if _, err := time.Parse(time.RFC3339, run.StartedAt); err != nil {
			return fmt.Errorf("jobEnvelope.runs[%d].startedAt must be RFC3339", i)
		}
		if _, err := time.Parse(time.RFC3339, run.FinishedAt); err != nil {
			return fmt.Errorf("jobEnvelope.runs[%d].finishedAt must be RFC3339", i)
		}
		if run.ManifestRef.RunID == "" || run.ManifestRef.ManifestHash == "" {
			return fmt.Errorf("jobEnvelope.runs[%d].manifestRef is required", i)
		}
		if !shaRe.MatchString(run.ManifestRef.ManifestHash) {
			return fmt.Errorf("jobEnvelope.runs[%d].manifestRef.manifestHash must be sha256:...", i)
		}
		if err := ValidatePipelineResult(run.Result); err != nil {
			return fmt.Errorf("jobEnvelope.runs[%d].result invalid: %w", i, err)
		}
		// Strong consistency: run.manifestRef must match result.manifestRef.
		if run.Result.ManifestRef.ManifestHash != run.ManifestRef.ManifestHash || run.Result.ManifestRef.RunID != run.ManifestRef.RunID {
			return fmt.Errorf("jobEnvelope.runs[%d] manifestRef mismatch between run and result", i)
		}
	}
	return nil
}

func validateBudget(b Budget, path string) error {
	if b.Scope == "" {
		return fmt.Errorf("%s.scope is required", path)
	}
	if b.Allocated == nil || b.Consumed == nil || b.Remaining == nil {
		return fmt.Errorf("%s must include allocated, consumed, remaining objects", path)
	}
	if b.Termination.Code == "" {
		return fmt.Errorf("%s.termination.code is required", path)
	}
	switch b.Termination.Code {
	case "ok", "tokens_exhausted", "time_exhausted", "external_calls_exhausted", "cancelled":
	default:
		return fmt.Errorf("%s.termination.code invalid: %q", path, b.Termination.Code)
	}
	for i, c := range b.Children {
		if err := validateBudget(c, fmt.Sprintf("%s.children[%d]", path, i)); err != nil {
			return err
		}
	}
	return nil
}
