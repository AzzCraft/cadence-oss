package sandbox

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const TaskCAD004 = "CAD-004"

const (
	CodeNetworkDenied    = "sandbox.network.denied"
	CodeFilesystemDenied = "sandbox.filesystem.denied"
	CodeEnvDenied        = "sandbox.env.denied"
)

var allowedParentEnvKeys = []string{
	"PATH",
	"HOME",
	"LANG",
	"LC_ALL",
	"LC_CTYPE",
	"TMPDIR",
	"TMP",
	"TEMP",
	"SYSTEMROOT",
	"COMSPEC",
}

var reservedParentEnvPrefixes = []string{
	"CADENCE_SANDBOX_",
	"CADENCE_PLUGIN_",
}

var allowedReservedParentEnvKeys = map[string]bool{
	"CADENCE_SANDBOX_CONTAINER_ADAPTER": true,
	"CADENCE_SANDBOX_MICROVM_ADAPTER":   true,
}

type Profile struct {
	SchemaVersion      string   `json:"schemaVersion,omitempty"`
	ProfileID          string   `json:"profileId,omitempty"`
	SandboxID          string   `json:"sandboxId,omitempty"`
	Backend            string   `json:"backend,omitempty"`
	Description        string   `json:"description,omitempty"`
	Filesystem         string   `json:"filesystem,omitempty"`
	ImageRef           string   `json:"imageRef,omitempty"`
	NetworkAccess      bool     `json:"networkAccess,omitempty"`
	TimeSource         string   `json:"timeSource,omitempty"`
	DeterministicClock bool     `json:"deterministicClock,omitempty"`
	AllowedMounts      []string `json:"allowedMounts,omitempty"`
	AllowedEnv         []string `json:"allowedEnv,omitempty"`
	ResourceLimits     *Limits  `json:"resourceLimits,omitempty"`
	ReadOnlyInputs     bool     `json:"readOnlyInputs,omitempty"`
	WritableOutputDir  string   `json:"writableOutputDir,omitempty"`
}

type CapabilityPolicy struct {
	SandboxProfile  string   `json:"sandboxProfile"`
	Network         bool     `json:"network"`
	FilesystemWrite []string `json:"filesystemWrite,omitempty"`
	EnvRead         []string `json:"envRead,omitempty"`
}

type DeniedCapability struct {
	Task       string `json:"task"`
	Code       string `json:"code"`
	Capability string `json:"capability"`
	Message    string `json:"message"`
}

// DenyUndeclaredCapability returns a CAD-004 denial for a capability not granted by policy.
func DenyUndeclaredCapability(policy CapabilityPolicy, capability string) *DeniedCapability {
	switch {
	case strings.HasPrefix(capability, "network."):
		if !policy.Network {
			return denied(CodeNetworkDenied, capability)
		}
	case strings.HasPrefix(capability, "filesystem.write:"):
		target := strings.TrimPrefix(capability, "filesystem.write:")
		if !allowedByPrefix(policy.FilesystemWrite, target) {
			return denied(CodeFilesystemDenied, capability)
		}
	case strings.HasPrefix(capability, "env.read:"):
		key := strings.TrimPrefix(capability, "env.read:")
		if !stringIn(policy.EnvRead, key) {
			return denied(CodeEnvDenied, capability)
		}
	}
	return nil
}

func denied(code string, capability string) *DeniedCapability {
	return &DeniedCapability{
		Task:       TaskCAD004,
		Code:       code,
		Capability: capability,
		Message:    fmt.Sprintf("CAD-004 %s: undeclared capability %s", code, capability),
	}
}

func allowedByPrefix(patterns []string, target string) bool {
	for _, pattern := range patterns {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			continue
		}
		if strings.HasSuffix(pattern, "/**") && strings.HasPrefix(target, strings.TrimSuffix(pattern, "**")) {
			return true
		}
		if pattern == target {
			return true
		}
	}
	return false
}

func stringIn(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}

// Limits defines optional resource constraints for sandbox execution.
type Limits struct {
	MaxMemoryMB    int `json:"maxMemoryMb,omitempty"`
	MaxCPUMs       int `json:"maxCpuMs,omitempty"`
	MaxDiskMB      int `json:"maxDiskMb,omitempty"`
	CPULimit       int `json:"cpuLimit,omitempty"`
	MemoryLimitMB  int `json:"memoryLimitMB,omitempty"`
	PIDsLimit      int `json:"pidsLimit,omitempty"`
	TimeoutSeconds int `json:"timeoutSeconds,omitempty"`
}

// Enforcement captures the result of enforcing a sandbox profile.
type Enforcement struct {
	ProfileID      string   `json:"profileId"`
	Checks         []string `json:"checks"`
	Passed         bool     `json:"passed"`
	FailureReasons []string `json:"failureReasons,omitempty"`
}

type CommandRequest struct {
	Command []string          `json:"command"`
	WorkDir string            `json:"workDir"`
	Env     map[string]string `json:"env,omitempty"`
}

type RuntimeAdapterRequest struct {
	Backend                   string            `json:"backend"`
	Command                   []string          `json:"command"`
	WorkDir                   string            `json:"workDir"`
	Env                       map[string]string `json:"env,omitempty"`
	Filesystem                string            `json:"filesystem,omitempty"`
	ImageRef                  string            `json:"imageRef,omitempty"`
	NetworkAccess             bool              `json:"networkAccess"`
	ReadOnlyInputs            bool              `json:"readOnlyInputs,omitempty"`
	WritableOutputDir         string            `json:"writableOutputDir,omitempty"`
	AllowedMounts             []string          `json:"allowedMounts,omitempty"`
	AllowedEnv                []string          `json:"allowedEnv,omitempty"`
	ResourceLimits            *Limits           `json:"resourceLimits,omitempty"`
	RequiredChecks            []string          `json:"requiredChecks,omitempty"`
	RequiredParentEnvKeys     []string          `json:"requiredParentEnvKeys,omitempty"`
	ReservedParentEnvPrefixes []string          `json:"reservedParentEnvPrefixes,omitempty"`
}

type RuntimeAdapterResponse struct {
	ExitCode           int              `json:"exitCode"`
	Stdout             string           `json:"stdout,omitempty"`
	Stderr             string           `json:"stderr,omitempty"`
	ObservedChecks     []string         `json:"observedChecks,omitempty"`
	NamespaceProofHash string           `json:"namespaceProofHash,omitempty"`
	NamespaceProofs    []NamespaceProof `json:"namespaceProofs,omitempty"`
	BackendEvidence    map[string]any   `json:"backendEvidence,omitempty"`
	FailureReasons     []string         `json:"failureReasons,omitempty"`
}

type ExecutionResult struct {
	SchemaVersion      string         `json:"schemaVersion"`
	ProfileID          string         `json:"profileId"`
	Backend            string         `json:"backend"`
	Mode               string         `json:"mode"`
	IsolationLevel     string         `json:"isolationLevel"`
	Command            []string       `json:"command"`
	WorkDir            string         `json:"workDir"`
	Filesystem         string         `json:"filesystem,omitempty"`
	NetworkAccess      bool           `json:"networkAccess"`
	ReadOnlyInputs     bool           `json:"readOnlyInputs,omitempty"`
	WritableOutputDir  string         `json:"writableOutputDir,omitempty"`
	AllowedMounts      []string       `json:"allowedMounts,omitempty"`
	ResourceLimits     *Limits        `json:"resourceLimits,omitempty"`
	Checks             []string       `json:"checks"`
	BackendEvidence    map[string]any `json:"backendEvidence,omitempty"`
	IsolationProbeRef  string         `json:"isolationProbeRef,omitempty"`
	NamespaceProofHash string         `json:"namespaceProofHash,omitempty"`
	Passed             bool           `json:"passed"`
	Status             string         `json:"status"`
	ExitCode           int            `json:"exitCode,omitempty"`
	StdoutHash         string         `json:"stdoutHash,omitempty"`
	StderrHash         string         `json:"stderrHash,omitempty"`
	FailureReasons     []string       `json:"failureReasons,omitempty"`
}

type Execution struct {
	Result ExecutionResult
	Stdout []byte
	Stderr []byte
}

type BackendAttestation struct {
	Backend           string          `json:"backend"`
	AttestationStatus string          `json:"attestationStatus"`
	AttestationLevel  string          `json:"attestationLevel"`
	RequiredChecks    []string        `json:"requiredChecks,omitempty"`
	ObservedChecks    []string        `json:"observedChecks,omitempty"`
	FailureReasons    []string        `json:"failureReasons,omitempty"`
	SeccompProfile    *SeccompProfile `json:"seccompProfile,omitempty"`
}

type rawProfile struct {
	SchemaVersion      string          `json:"schemaVersion,omitempty"`
	ProfileID          string          `json:"profileId,omitempty"`
	SandboxID          string          `json:"sandboxId,omitempty"`
	Backend            string          `json:"backend,omitempty"`
	Description        string          `json:"description,omitempty"`
	Filesystem         json.RawMessage `json:"filesystem,omitempty"`
	ImageRef           string          `json:"imageRef,omitempty"`
	Network            json.RawMessage `json:"network,omitempty"`
	NetworkAccess      *bool           `json:"networkAccess,omitempty"`
	TimeSource         string          `json:"timeSource,omitempty"`
	DeterministicClock bool            `json:"deterministicClock,omitempty"`
	AllowedMounts      []string        `json:"allowedMounts,omitempty"`
	AllowedEnv         []string        `json:"allowedEnv,omitempty"`
	Resources          *rawResources   `json:"resources,omitempty"`
	ResourceLimits     *Limits         `json:"resourceLimits,omitempty"`
}

type rawFilesystem struct {
	Mode              string `json:"mode,omitempty"`
	ReadOnlyInputs    bool   `json:"readOnlyInputs,omitempty"`
	WritableOutputDir string `json:"writableOutputDir,omitempty"`
}

type rawNetwork struct {
	Access *bool `json:"access,omitempty"`
}

type rawResources struct {
	CPULimit       *int `json:"cpuLimit,omitempty"`
	MemoryLimitMB  *int `json:"memoryLimitMB,omitempty"`
	PIDsLimit      *int `json:"pidsLimit,omitempty"`
	TimeoutSeconds *int `json:"timeoutSeconds,omitempty"`
}

func Load(path string) (Profile, error) {
	var raw rawProfile
	var profile Profile
	data, err := os.ReadFile(path)
	if err != nil {
		return profile, err
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return profile, err
	}

	profile.SchemaVersion = raw.SchemaVersion
	profile.ProfileID = strings.TrimSpace(raw.ProfileID)
	profile.SandboxID = strings.TrimSpace(raw.SandboxID)
	profile.Backend = strings.TrimSpace(raw.Backend)
	if profile.ProfileID == "" {
		profile.ProfileID = profile.SandboxID
	}
	if profile.SandboxID == "" {
		profile.SandboxID = profile.ProfileID
	}
	profile.Description = raw.Description
	profile.ImageRef = strings.TrimSpace(raw.ImageRef)
	profile.TimeSource = strings.TrimSpace(raw.TimeSource)
	profile.DeterministicClock = raw.DeterministicClock
	profile.AllowedMounts = raw.AllowedMounts
	profile.AllowedEnv = append([]string{}, raw.AllowedEnv...)

	if len(raw.Filesystem) > 0 {
		var mode string
		if err := json.Unmarshal(raw.Filesystem, &mode); err == nil {
			profile.Filesystem = strings.TrimSpace(mode)
		} else {
			var fs rawFilesystem
			if err := json.Unmarshal(raw.Filesystem, &fs); err != nil {
				return profile, fmt.Errorf("sandbox: invalid filesystem payload: %w", err)
			}
			profile.Filesystem = strings.TrimSpace(fs.Mode)
			profile.ReadOnlyInputs = fs.ReadOnlyInputs
			profile.WritableOutputDir = strings.TrimSpace(fs.WritableOutputDir)
		}
	}

	if len(raw.Network) > 0 {
		var network rawNetwork
		if err := json.Unmarshal(raw.Network, &network); err != nil {
			return profile, fmt.Errorf("sandbox: invalid network payload: %w", err)
		}
		if network.Access != nil {
			profile.NetworkAccess = *network.Access
		}
	} else if raw.NetworkAccess != nil {
		profile.NetworkAccess = *raw.NetworkAccess
	}

	switch {
	case raw.Resources != nil:
		profile.ResourceLimits = &Limits{}
		if raw.Resources.CPULimit != nil {
			profile.ResourceLimits.CPULimit = *raw.Resources.CPULimit
		}
		if raw.Resources.MemoryLimitMB != nil {
			profile.ResourceLimits.MemoryLimitMB = *raw.Resources.MemoryLimitMB
		}
		if raw.Resources.PIDsLimit != nil {
			profile.ResourceLimits.PIDsLimit = *raw.Resources.PIDsLimit
		}
		if raw.Resources.TimeoutSeconds != nil {
			profile.ResourceLimits.TimeoutSeconds = *raw.Resources.TimeoutSeconds
		}
	case raw.ResourceLimits != nil:
		limits := *raw.ResourceLimits
		profile.ResourceLimits = &limits
	}
	if profile.Backend == "" {
		profile.Backend = inferBackend(profile.Filesystem)
	}

	return profile, nil
}

// Validate checks that a sandbox profile has consistent settings.
func Validate(p Profile) error {
	if profileID(p) == "" {
		return errors.New("sandbox: profileId or sandboxId is required")
	}
	validFS := map[string]bool{
		"read-only":          true,
		"copy-on-write":      true,
		"tmpfs":              true,
		"host":               true,
		"workspace-only":     true,
		"container-isolated": true,
		"microvm-isolated":   true,
	}
	if !validFS[p.Filesystem] {
		return fmt.Errorf("sandbox: invalid filesystem mode %q", p.Filesystem)
	}
	validTime := map[string]bool{"system": true, "epoch-frozen": true, "monotonic": true, "injected": true}
	if !validTime[p.TimeSource] {
		return fmt.Errorf("sandbox: invalid timeSource %q", p.TimeSource)
	}
	backend := selectedBackend(p)
	validBackend := map[string]bool{
		"host-local":        true,
		"container-runtime": true,
		"microvm-runtime":   true,
	}
	if !validBackend[backend] {
		return fmt.Errorf("sandbox: invalid backend %q", backend)
	}
	if p.Filesystem == "container-isolated" && backend != "container-runtime" {
		return errors.New("sandbox: container-isolated filesystem requires backend=container-runtime")
	}
	if p.Filesystem == "microvm-isolated" && backend != "microvm-runtime" {
		return errors.New("sandbox: microvm-isolated filesystem requires backend=microvm-runtime")
	}
	if p.Filesystem == "workspace-only" && backend == "microvm-runtime" {
		return errors.New("sandbox: workspace-only filesystem cannot use backend=microvm-runtime")
	}
	if p.DeterministicClock && p.TimeSource == "system" {
		return errors.New("sandbox: deterministicClock requires non-system timeSource")
	}
	if p.ReadOnlyInputs && p.WritableOutputDir == "" {
		return errors.New("sandbox: readOnlyInputs requires writableOutputDir")
	}
	if backend != "host-local" {
		if !p.ReadOnlyInputs {
			return fmt.Errorf("sandbox: backend %s requires readOnlyInputs=true", backend)
		}
		if p.WritableOutputDir == "" || filepath.Clean(p.WritableOutputDir) == "." {
			return fmt.Errorf("sandbox: backend %s requires a distinct writableOutputDir", backend)
		}
		if p.NetworkAccess {
			return fmt.Errorf("sandbox: backend %s requires networkAccess=false", backend)
		}
		if p.ResourceLimits == nil || p.ResourceLimits.TimeoutSeconds <= 0 {
			return fmt.Errorf("sandbox: backend %s requires bounded resource limits", backend)
		}
	}
	if p.ResourceLimits != nil {
		for label, value := range map[string]int{
			"maxMemoryMb":    p.ResourceLimits.MaxMemoryMB,
			"maxCpuMs":       p.ResourceLimits.MaxCPUMs,
			"maxDiskMb":      p.ResourceLimits.MaxDiskMB,
			"cpuLimit":       p.ResourceLimits.CPULimit,
			"memoryLimitMB":  p.ResourceLimits.MemoryLimitMB,
			"pidsLimit":      p.ResourceLimits.PIDsLimit,
			"timeoutSeconds": p.ResourceLimits.TimeoutSeconds,
		} {
			if value < 0 {
				return fmt.Errorf("sandbox: %s must be >= 0", label)
			}
		}
	}
	return nil
}

func AllowedParentEnvKeys() []string {
	return append([]string{}, allowedParentEnvKeys...)
}

func ReservedParentEnvPrefixes() []string {
	return append([]string{}, reservedParentEnvPrefixes...)
}

func ValidateParentEnvironment(env []string) error {
	for _, item := range env {
		parts := strings.SplitN(item, "=", 2)
		key := parts[0]
		if allowedReservedParentEnvKeys[key] {
			continue
		}
		for _, prefix := range reservedParentEnvPrefixes {
			if strings.HasPrefix(key, prefix) {
				return fmt.Errorf("sandbox: parent environment must not set reserved key %q", key)
			}
		}
	}
	return nil
}

// Enforce checks the current environment against the sandbox profile constraints
// and returns an enforcement result. This is a pre-flight check, not actual
// OS-level isolation (which requires container runtime or namespace setup).
func Enforce(p Profile, workDir string) Enforcement {
	enf := Enforcement{
		ProfileID: profileID(p),
		Passed:    true,
	}
	enf.Checks, enf.FailureReasons = collectChecks(p, workDir)
	enf.Passed = len(enf.FailureReasons) == 0
	return enf
}

// Execute launches a subprocess under the declared sandbox profile and returns
// a structured result contract plus captured stdout/stderr.
//
// `host-local` backends execute through the current launcher path.
// `container-runtime` and `microvm-runtime` backends execute through a
// configured runtime adapter and fail closed unless the adapter returns
// machine-checkable isolation proof.
func Execute(p Profile, req CommandRequest) Execution {
	enf := Enforce(p, req.WorkDir)
	result := newExecutionResult(p, req, enf)
	if len(result.Command) == 0 {
		result.Passed = false
		result.FailureReasons = append(result.FailureReasons, "sandbox command is required")
		return Execution{Result: result}
	}
	if !result.Passed {
		return Execution{Result: result}
	}

	if result.Backend != "host-local" {
		return executeRuntimeAdapter(p, req, result)
	}
	return executeHostLauncher(p, req, result)
}

func executeHostLauncher(p Profile, req CommandRequest, result ExecutionResult) Execution {
	timeout := 0 * time.Second
	if p.ResourceLimits != nil && p.ResourceLimits.TimeoutSeconds > 0 {
		timeout = time.Duration(p.ResourceLimits.TimeoutSeconds) * time.Second
	}

	ctx := context.Background()
	cancel := func() {}
	if timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, timeout)
	}
	defer cancel()

	cmd := exec.CommandContext(ctx, result.Command[0], result.Command[1:]...)
	if strings.TrimSpace(req.WorkDir) != "" {
		cmd.Dir = req.WorkDir
	}
	cmd.Env = buildCommandEnv(p, req.Env)

	var stdoutBuf bytes.Buffer
	var stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	err := cmd.Run()
	execution := Execution{
		Result: result,
		Stdout: stdoutBuf.Bytes(),
		Stderr: stderrBuf.Bytes(),
	}
	execution.Result.StdoutHash = hashBytes(execution.Stdout)
	execution.Result.StderrHash = hashBytes(execution.Stderr)

	if ctx.Err() == context.DeadlineExceeded {
		execution.Result.Passed = false
		execution.Result.Status = "timeout"
		execution.Result.FailureReasons = append(execution.Result.FailureReasons, "sandbox command timed out")
		return execution
	}
	if err != nil {
		execution.Result.Passed = false
		execution.Result.Status = "execution_error"
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			execution.Result.ExitCode = exitErr.ExitCode()
		} else {
			execution.Result.ExitCode = -1
		}
		execution.Result.FailureReasons = append(execution.Result.FailureReasons, err.Error())
		return execution
	}

	execution.Result.Status = "ok"
	execution.Result.ExitCode = 0
	return execution
}

func executeRuntimeAdapter(p Profile, req CommandRequest, result ExecutionResult) Execution {
	adapterEnvVarName := adapterEnvVar(result.Backend)
	adapterPath := strings.TrimSpace(os.Getenv(adapterEnvVarName))
	if adapterPath == "" {
		result.Passed = false
		result.Status = "denied"
		result.FailureReasons = append(
			result.FailureReasons,
			fmt.Sprintf("sandbox runtime adapter is required for backend %q; set %s", result.Backend, adapterEnvVarName),
		)
		return Execution{Result: result}
	}

	timeout := 0 * time.Second
	if p.ResourceLimits != nil && p.ResourceLimits.TimeoutSeconds > 0 {
		timeout = time.Duration(p.ResourceLimits.TimeoutSeconds) * time.Second
	}

	ctx := context.Background()
	cancel := func() {}
	if timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, timeout)
	}
	defer cancel()

	adapterEnv, adapterEnvErr := buildRuntimeAdapterEnv(p, req.Env)
	if adapterEnvErr != nil {
		result.Passed = false
		result.Status = "denied"
		result.FailureReasons = append(result.FailureReasons, adapterEnvErr.Error())
		return Execution{Result: result}
	}

	requestPayload := RuntimeAdapterRequest{
		Backend:                   result.Backend,
		Command:                   append([]string{}, req.Command...),
		WorkDir:                   req.WorkDir,
		Env:                       adapterEnv,
		Filesystem:                p.Filesystem,
		ImageRef:                  p.ImageRef,
		NetworkAccess:             p.NetworkAccess,
		ReadOnlyInputs:            p.ReadOnlyInputs,
		WritableOutputDir:         p.WritableOutputDir,
		AllowedMounts:             append([]string{}, p.AllowedMounts...),
		AllowedEnv:                append([]string{}, p.AllowedEnv...),
		ResourceLimits:            p.ResourceLimits,
		RequiredChecks:            requiredIsolationChecks(normalizedBackendType(result.Backend)),
		RequiredParentEnvKeys:     append([]string{}, allowedParentEnvKeys...),
		ReservedParentEnvPrefixes: append([]string{}, reservedParentEnvPrefixes...),
	}
	requestBytes, err := json.Marshal(requestPayload)
	if err != nil {
		result.Passed = false
		result.Status = "adapter_error"
		result.FailureReasons = append(result.FailureReasons, fmt.Sprintf("sandbox runtime adapter request marshal failed: %v", err))
		return Execution{Result: result}
	}

	cmd := exec.CommandContext(ctx, adapterPath)
	if strings.TrimSpace(req.WorkDir) != "" {
		cmd.Dir = req.WorkDir
	}
	cmd.Env = buildCommandEnv(p, nil)
	cmd.Stdin = bytes.NewReader(requestBytes)

	var stdoutBuf bytes.Buffer
	var stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	err = cmd.Run()
	execution := Execution{
		Result: result,
		Stdout: stdoutBuf.Bytes(),
		Stderr: stderrBuf.Bytes(),
	}
	if ctx.Err() == context.DeadlineExceeded {
		execution.Result.Passed = false
		execution.Result.Status = "timeout"
		execution.Result.FailureReasons = append(execution.Result.FailureReasons, "sandbox runtime adapter timed out")
		execution.Result.StdoutHash = hashBytes(execution.Stdout)
		execution.Result.StderrHash = hashBytes(execution.Stderr)
		return execution
	}
	if err != nil {
		execution.Result.Passed = false
		execution.Result.Status = "adapter_error"
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			execution.Result.ExitCode = exitErr.ExitCode()
		} else {
			execution.Result.ExitCode = -1
		}
		execution.Result.FailureReasons = append(
			execution.Result.FailureReasons,
			fmt.Sprintf("sandbox runtime adapter %q failed: %v", adapterPath, err),
		)
		execution.Result.StdoutHash = hashBytes(execution.Stdout)
		execution.Result.StderrHash = hashBytes(execution.Stderr)
		return execution
	}

	var adapterResp RuntimeAdapterResponse
	if err := json.Unmarshal(stdoutBuf.Bytes(), &adapterResp); err != nil {
		execution.Result.Passed = false
		execution.Result.Status = "adapter_error"
		execution.Result.ExitCode = -1
		execution.Result.FailureReasons = append(
			execution.Result.FailureReasons,
			fmt.Sprintf("sandbox runtime adapter returned invalid JSON: %v", err),
		)
		execution.Result.StdoutHash = hashBytes(execution.Stdout)
		execution.Result.StderrHash = hashBytes(execution.Stderr)
		return execution
	}

	execution.Stdout = []byte(adapterResp.Stdout)
	execution.Stderr = []byte(adapterResp.Stderr)
	execution.Result.StdoutHash = hashBytes(execution.Stdout)
	execution.Result.StderrHash = hashBytes(execution.Stderr)
	execution.Result.ExitCode = adapterResp.ExitCode
	execution.Result.Checks = appendUniqueStrings(execution.Result.Checks, "runtime-adapter-exec")
	if len(adapterResp.FailureReasons) > 0 {
		execution.Result.FailureReasons = append(execution.Result.FailureReasons, adapterResp.FailureReasons...)
	}
	applyAdapterEvidence(&execution.Result, p, adapterPath, adapterEnvVarName, adapterResp)
	if execution.Result.BackendEvidence["attestationStatus"] == "insufficient" {
		execution.Result.Passed = false
		execution.Result.Status = "denied"
		if len(execution.Result.FailureReasons) == 0 {
			execution.Result.FailureReasons = append(execution.Result.FailureReasons, "sandbox runtime attestation failed")
		}
		return execution
	}
	if execution.Result.ExitCode != 0 {
		execution.Result.Passed = false
		execution.Result.Status = "execution_error"
		if len(execution.Result.FailureReasons) == 0 {
			execution.Result.FailureReasons = append(
				execution.Result.FailureReasons,
				fmt.Sprintf("sandbox command exited with code %d under runtime adapter", execution.Result.ExitCode),
			)
		}
		return execution
	}

	execution.Result.Status = "ok"
	return execution
}

func DeniedExecution(p Profile, req CommandRequest, reasons ...string) Execution {
	enf := Enforce(p, req.WorkDir)
	result := newExecutionResult(p, req, enf)
	result.Passed = false
	result.Status = "denied"
	result.FailureReasons = append(result.FailureReasons, reasons...)
	return Execution{Result: result}
}

func newExecutionResult(p Profile, req CommandRequest, enf Enforcement) ExecutionResult {
	backend := selectedBackend(p)
	return ExecutionResult{
		SchemaVersion:     "1.0.0",
		ProfileID:         enf.ProfileID,
		Backend:           backend,
		Mode:              executionMode(backend),
		IsolationLevel:    isolationLevel(backend),
		Command:           append([]string{}, req.Command...),
		WorkDir:           req.WorkDir,
		Filesystem:        p.Filesystem,
		NetworkAccess:     p.NetworkAccess,
		ReadOnlyInputs:    p.ReadOnlyInputs,
		WritableOutputDir: p.WritableOutputDir,
		AllowedMounts:     append([]string{}, p.AllowedMounts...),
		ResourceLimits:    p.ResourceLimits,
		Checks:            append([]string{}, enf.Checks...),
		BackendEvidence:   buildBackendEvidence(p, req),
		Passed:            enf.Passed,
		Status:            "denied",
		FailureReasons:    append([]string{}, enf.FailureReasons...),
	}
}

func profileID(p Profile) string {
	if strings.TrimSpace(p.ProfileID) != "" {
		return strings.TrimSpace(p.ProfileID)
	}
	return strings.TrimSpace(p.SandboxID)
}

func collectChecks(p Profile, workDir string) ([]string, []string) {
	checks := []string{}
	failures := []string{}
	backend := selectedBackend(p)
	checks = append(checks, "backend:"+backend)

	// These are preflight contract checks. Non-host profiles still require a
	// successful runtime-adapter execution path before the sandbox run is valid.
	if p.Filesystem == "read-only" {
		testFile := filepath.Join(workDir, ".cadence_sandbox_probe")
		err := os.WriteFile(testFile, []byte("probe"), 0o644)
		if err == nil {
			_ = os.Remove(testFile)
			checks = append(checks, "filesystem-writable-warning")
		} else {
			checks = append(checks, "filesystem-readonly-ok")
		}
	} else if p.Filesystem != "" {
		checks = append(checks, "filesystem-mode-"+p.Filesystem)
	}
	if p.ReadOnlyInputs {
		checks = append(checks, "readonly-inputs-declared")
	}
	if p.WritableOutputDir != "" {
		checks = append(checks, "writable-output-dir:"+p.WritableOutputDir)
	}

	if !p.NetworkAccess {
		checks = append(checks, "network-disabled-declared")
	} else {
		checks = append(checks, "network-access-allowed")
	}

	for _, mount := range p.AllowedMounts {
		if !strings.HasPrefix(mount, "/") && !strings.HasPrefix(mount, "./") {
			failures = append(failures, fmt.Sprintf("mount %q is not an absolute or relative path", mount))
		} else {
			checks = append(checks, "mount-ok:"+mount)
		}
	}

	if p.DeterministicClock {
		checks = append(checks, "deterministic-clock-required")
	}
	if p.ResourceLimits != nil {
		checks = append(checks, "resource-limits-declared")
	}
	if backend != "host-local" {
		checks = append(checks, "backend-isolation-contract:"+backend)
		checks = append(checks, "runtime-adapter-required")
	}

	return checks, failures
}

func buildCommandEnv(p Profile, overlay map[string]string) []string {
	envMap := buildCommandEnvMap(p, overlay)
	keys := make([]string, 0, len(envMap))
	for key := range envMap {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	env := make([]string, 0, len(keys))
	for _, key := range keys {
		value := envMap[key]
		env = append(env, key+"="+value)
	}
	return env
}

func buildCommandEnvMap(p Profile, overlay map[string]string) map[string]string {
	envMap := map[string]string{}
	for _, key := range allowedParentEnvKeys {
		if value, ok := os.LookupEnv(key); ok {
			envMap[key] = value
		}
	}
	if !p.NetworkAccess {
		for _, key := range []string{
			"HTTP_PROXY",
			"HTTPS_PROXY",
			"ALL_PROXY",
			"http_proxy",
			"https_proxy",
			"all_proxy",
		} {
			delete(envMap, key)
		}
		envMap["CADENCE_SANDBOX_NETWORK"] = "off"
	}
	envMap["CADENCE_SANDBOX_PROFILE"] = profileID(p)
	envMap["CADENCE_SANDBOX_BACKEND"] = selectedBackend(p)
	envMap["CADENCE_SANDBOX_FILESYSTEM"] = p.Filesystem
	if p.ReadOnlyInputs {
		envMap["CADENCE_SANDBOX_READ_ONLY_INPUTS"] = "1"
	}
	if p.WritableOutputDir != "" {
		envMap["CADENCE_SANDBOX_WRITABLE_OUTPUT_DIR"] = p.WritableOutputDir
	}
	for key, value := range overlay {
		envMap[key] = value
	}
	return envMap
}

// buildRuntimeAdapterEnv deliberately does not forward the host launcher
// environment.  A non-host backend receives only Cadence's fixed runtime
// markers plus command environment names declared by the profile.  This keeps
// a request from smuggling credentials or proxy settings into an isolated
// image through CommandRequest.Env.
func buildRuntimeAdapterEnv(p Profile, overlay map[string]string) (map[string]string, error) {
	allowed := map[string]bool{}
	for _, key := range p.AllowedEnv {
		key = strings.TrimSpace(key)
		if !validEnvironmentKey(key) {
			return nil, fmt.Errorf("sandbox: invalid allowed environment key %q", key)
		}
		if strings.HasPrefix(key, "CADENCE_SANDBOX_") {
			return nil, fmt.Errorf("sandbox: profile may not override reserved environment key %q", key)
		}
		allowed[key] = true
	}
	env := map[string]string{
		"CADENCE_SANDBOX_PROFILE":    profileID(p),
		"CADENCE_SANDBOX_BACKEND":    selectedBackend(p),
		"CADENCE_SANDBOX_FILESYSTEM": p.Filesystem,
		"CADENCE_SANDBOX_NETWORK":    "off",
	}
	if p.ReadOnlyInputs {
		env["CADENCE_SANDBOX_READ_ONLY_INPUTS"] = "1"
	}
	if p.WritableOutputDir != "" {
		env["CADENCE_SANDBOX_WRITABLE_OUTPUT_DIR"] = p.WritableOutputDir
	}
	for key, value := range overlay {
		if !allowed[key] {
			return nil, fmt.Errorf("sandbox: environment key %q is not declared by profile", key)
		}
		env[key] = value
	}
	return env, nil
}

func validEnvironmentKey(key string) bool {
	if key == "" || key[0] < 'A' || key[0] > 'Z' {
		return false
	}
	for _, char := range key {
		if (char < 'A' || char > 'Z') && (char < '0' || char > '9') && char != '_' {
			return false
		}
	}
	return true
}

func selectedBackend(p Profile) string {
	if strings.TrimSpace(p.Backend) != "" {
		return strings.TrimSpace(p.Backend)
	}
	return inferBackend(p.Filesystem)
}

func inferBackend(filesystem string) string {
	switch strings.TrimSpace(filesystem) {
	case "container-isolated":
		return "container-runtime"
	case "microvm-isolated":
		return "microvm-runtime"
	default:
		return "host-local"
	}
}

func buildBackendEvidence(p Profile, req CommandRequest) map[string]any {
	backend := selectedBackend(p)
	writableOutput := strings.TrimSpace(p.WritableOutputDir)
	if writableOutput == "" {
		writableOutput = ".cadence/out"
	}
	contract := map[string]any{
		"backend":           backend,
		"filesystem":        p.Filesystem,
		"imageRef":          p.ImageRef,
		"networkAccess":     p.NetworkAccess,
		"readOnlyInputs":    p.ReadOnlyInputs,
		"writableOutputDir": writableOutput,
		"workDir":           req.WorkDir,
		"resourceLimits":    p.ResourceLimits,
		"allowedEnv":        append([]string{}, p.AllowedEnv...),
	}
	payload, _ := json.Marshal(contract)
	sum := sha256.Sum256(payload)
	contract["contractHash"] = "sha256:" + hex.EncodeToString(sum[:])
	contract["enforcement"] = executionMode(backend)
	contract["attestationType"] = "profile-contract"
	contract["requiredParentEnvKeys"] = append([]string{}, allowedParentEnvKeys...)
	contract["reservedParentEnvPrefixes"] = append([]string{}, reservedParentEnvPrefixes...)
	contract["escapeClassification"] = EscapeClassification(p)
	if backend == "host-local" {
		contract["attestationStatus"] = "launcher-only"
		contract["attestationLevel"] = "launcher-only"
	} else {
		contract["attestationStatus"] = "pending-runtime-proof"
		contract["attestationLevel"] = "profile-declared-only"
		contract["requiredChecks"] = requiredIsolationChecks(normalizedBackendType(backend))
		contract["adapterEnvVar"] = adapterEnvVar(backend)
	}
	return contract
}

func executionMode(backend string) string {
	if normalizedBackendType(backend) == "host-local" {
		return "host-launcher"
	}
	return "runtime-exec"
}

func isolationLevel(backend string) string {
	switch strings.TrimSpace(backend) {
	case "container-runtime":
		return "backend-container-runtime-enforced"
	case "microvm-runtime":
		return "backend-microvm-runtime-enforced"
	default:
		return "backend-host-local-launcher"
	}
}

func adapterEnvVar(backend string) string {
	switch strings.TrimSpace(backend) {
	case "container-runtime":
		return "CADENCE_SANDBOX_CONTAINER_ADAPTER"
	case "microvm-runtime":
		return "CADENCE_SANDBOX_MICROVM_ADAPTER"
	default:
		return ""
	}
}

func applyAdapterEvidence(result *ExecutionResult, p Profile, adapterPath string, adapterEnv string, response RuntimeAdapterResponse) {
	if result.BackendEvidence == nil {
		result.BackendEvidence = map[string]any{}
	}
	result.BackendEvidence["adapterExecutable"] = adapterPath
	result.BackendEvidence["adapterEnvVar"] = adapterEnv
	if response.BackendEvidence != nil {
		for key, value := range response.BackendEvidence {
			result.BackendEvidence[key] = value
		}
	}

	probe := probeFromAdapterResponse(response)
	attestation := DescribeBackendAttestation(p, probe)
	result.NamespaceProofHash = probe.NamespaceProofHash
	result.BackendEvidence["attestationStatus"] = attestation.AttestationStatus
	result.BackendEvidence["attestationLevel"] = attestation.AttestationLevel
	result.BackendEvidence["requiredChecks"] = attestation.RequiredChecks
	result.BackendEvidence["observedChecks"] = attestation.ObservedChecks
	if attestation.SeccompProfile != nil {
		result.BackendEvidence["seccompProfile"] = attestation.SeccompProfile
	}
	if len(attestation.FailureReasons) > 0 {
		result.FailureReasons = append(result.FailureReasons, attestation.FailureReasons...)
		result.BackendEvidence["attestationFailures"] = attestation.FailureReasons
	} else {
		delete(result.BackendEvidence, "attestationFailures")
	}
	if probe.NamespaceProofHash != "" {
		result.BackendEvidence["namespaceProofHash"] = probe.NamespaceProofHash
	}
	if len(probe.NamespaceProofs) > 0 {
		result.BackendEvidence["namespaceProofs"] = probe.NamespaceProofs
	}
}

func probeFromAdapterResponse(response RuntimeAdapterResponse) IsolationProbe {
	probe := IsolationProbe{
		NamespaceProofs: append([]NamespaceProof{}, response.NamespaceProofs...),
	}
	if response.BackendEvidence != nil {
		if version, ok := response.BackendEvidence["cgroupVersion"].(string); ok {
			probe.CgroupVersion = version
		}
	}
	observed := stringSlice(response.ObservedChecks)
	probe.PIDNamespaced = containsString(observed, "pid-namespace")
	probe.MountNamespaced = containsString(observed, "mount-namespace")
	probe.NetNamespaced = containsString(observed, "network-namespace")
	probe.SeccompActive = containsString(observed, "seccomp-active")
	probe.CgroupFenced = containsString(observed, "cgroup-fenced")
	probe.ReadonlyRoot = containsString(observed, "readonly-root")
	probe.NamespaceProofHash = strings.TrimSpace(response.NamespaceProofHash)
	if probe.NamespaceProofHash == "" && len(probe.NamespaceProofs) > 0 {
		probe.NamespaceProofHash = hashNamespaceProofs(probe.NamespaceProofs)
	}
	return probe
}

func ExecutionIsolationProbe(result ExecutionResult) IsolationProbe {
	evidence := result.BackendEvidence
	if len(evidence) == 0 {
		return IsolationProbe{}
	}
	probe := IsolationProbe{}
	observed := stringSlice(evidence["observedChecks"])
	probe.PIDNamespaced = containsString(observed, "pid-namespace")
	probe.MountNamespaced = containsString(observed, "mount-namespace")
	probe.NetNamespaced = containsString(observed, "network-namespace")
	probe.SeccompActive = containsString(observed, "seccomp-active")
	probe.CgroupFenced = containsString(observed, "cgroup-fenced")
	probe.ReadonlyRoot = containsString(observed, "readonly-root")
	if version, ok := evidence["cgroupVersion"].(string); ok {
		probe.CgroupVersion = version
	}
	switch rawProofs := evidence["namespaceProofs"].(type) {
	case []NamespaceProof:
		probe.NamespaceProofs = append([]NamespaceProof{}, rawProofs...)
	case []any:
		for _, raw := range rawProofs {
			payload, err := json.Marshal(raw)
			if err != nil {
				continue
			}
			var proof NamespaceProof
			if err := json.Unmarshal(payload, &proof); err == nil {
				probe.NamespaceProofs = append(probe.NamespaceProofs, proof)
			}
		}
	}
	if hash, ok := evidence["namespaceProofHash"].(string); ok {
		probe.NamespaceProofHash = strings.TrimSpace(hash)
	}
	if probe.NamespaceProofHash == "" {
		probe.NamespaceProofHash = result.NamespaceProofHash
	}
	if probe.NamespaceProofHash == "" && len(probe.NamespaceProofs) > 0 {
		probe.NamespaceProofHash = hashNamespaceProofs(probe.NamespaceProofs)
	}
	return probe
}

func appendUniqueStrings(values []string, extras ...string) []string {
	seen := make(map[string]bool, len(values)+len(extras))
	result := make([]string, 0, len(values)+len(extras))
	for _, value := range values {
		if seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	for _, value := range extras {
		if seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	return result
}

func stringSlice(raw any) []string {
	switch typed := raw.(type) {
	case nil:
		return nil
	case []string:
		return append([]string{}, typed...)
	case []any:
		values := make([]string, 0, len(typed))
		for _, item := range typed {
			if text, ok := item.(string); ok && strings.TrimSpace(text) != "" {
				values = append(values, strings.TrimSpace(text))
			}
		}
		return values
	default:
		return nil
	}
}

func containsString(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}

func hashBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// EscapeClassification returns a structured escape-risk assessment for the
// given sandbox profile. The classification level indicates the theoretical
// escape surface area: "minimal" (non-host isolated), "bounded" (host-local
// with restrictions), or "permissive" (host-local without restrictions).
func EscapeClassification(p Profile) map[string]any {
	backend := selectedBackend(p)
	classification := map[string]any{
		"profileId": profileID(p),
		"backend":   backend,
	}

	switch backend {
	case "microvm-runtime":
		classification["level"] = "minimal"
		classification["escapeSurface"] = "vm-boundary"
		classification["isolation"] = []string{"kernel", "filesystem", "network", "pid", "resource"}
	case "container-runtime":
		classification["level"] = "minimal"
		classification["escapeSurface"] = "container-boundary"
		classification["isolation"] = []string{"namespace", "filesystem", "network", "pid", "resource"}
	default:
		restrictions := []string{}
		if p.ReadOnlyInputs {
			restrictions = append(restrictions, "read-only-inputs")
		}
		if !p.NetworkAccess {
			restrictions = append(restrictions, "network-disabled")
		}
		if p.ResourceLimits != nil && p.ResourceLimits.TimeoutSeconds > 0 {
			restrictions = append(restrictions, "timeout-bounded")
		}
		if p.DeterministicClock {
			restrictions = append(restrictions, "deterministic-clock")
		}
		if len(restrictions) >= 2 {
			classification["level"] = "bounded"
			classification["escapeSurface"] = "host-restricted"
		} else {
			classification["level"] = "permissive"
			classification["escapeSurface"] = "host-unrestricted"
		}
		classification["isolation"] = restrictions
	}
	return classification
}

// NamespaceProof captures concrete namespace descriptors observed at runtime.
type NamespaceProof struct {
	Namespace      string `json:"namespace"`
	SelfDescriptor string `json:"selfDescriptor,omitempty"`
	InitDescriptor string `json:"initDescriptor,omitempty"`
	MatchesInit    bool   `json:"matchesInit"`
}

// IsolationProbe holds evidence of actual runtime isolation fences detected on
// the current execution environment. This is distinct from the declared profile
// contract — it reports what the OS kernel actually enforces.
type IsolationProbe struct {
	PIDNamespaced      bool             `json:"pidNamespaced"`
	MountNamespaced    bool             `json:"mountNamespaced"`
	NetNamespaced      bool             `json:"netNamespaced"`
	SeccompActive      bool             `json:"seccompActive"`
	CgroupFenced       bool             `json:"cgroupFenced"`
	CgroupVersion      string           `json:"cgroupVersion"`
	ReadonlyRoot       bool             `json:"readonlyRoot"`
	NamespaceProofs    []NamespaceProof `json:"namespaceProofs,omitempty"`
	NamespaceProofHash string           `json:"namespaceProofHash,omitempty"`
}

func probeNamespace(name string) NamespaceProof {
	proof := NamespaceProof{Namespace: name}
	selfPath := filepath.Join("/proc/self/ns", name)
	initPath := filepath.Join("/proc/1/ns", name)
	if descriptor, err := os.Readlink(selfPath); err == nil {
		proof.SelfDescriptor = descriptor
	}
	if descriptor, err := os.Readlink(initPath); err == nil {
		proof.InitDescriptor = descriptor
	}
	if proof.SelfDescriptor != "" && proof.InitDescriptor != "" {
		proof.MatchesInit = proof.SelfDescriptor == proof.InitDescriptor
	}
	return proof
}

func hashNamespaceProofs(proofs []NamespaceProof) string {
	if len(proofs) == 0 {
		return ""
	}
	payload, err := json.Marshal(proofs)
	if err != nil {
		return ""
	}
	return hashBytes(payload)
}

// ProbeRuntimeIsolation inspects the current Linux process for evidence of
// kernel-level isolation fences. On non-Linux systems it returns an empty probe
// with all fields false.
func ProbeRuntimeIsolation() IsolationProbe {
	probe := IsolationProbe{}
	pidProof := probeNamespace("pid")
	mountProof := probeNamespace("mnt")
	netProof := probeNamespace("net")
	for _, proof := range []NamespaceProof{pidProof, mountProof, netProof} {
		if proof.SelfDescriptor != "" || proof.InitDescriptor != "" {
			probe.NamespaceProofs = append(probe.NamespaceProofs, proof)
		}
	}
	probe.NamespaceProofHash = hashNamespaceProofs(probe.NamespaceProofs)
	probe.PIDNamespaced = pidProof.SelfDescriptor != "" && pidProof.InitDescriptor != "" && !pidProof.MatchesInit
	probe.MountNamespaced = mountProof.SelfDescriptor != "" && mountProof.InitDescriptor != "" && !mountProof.MatchesInit
	probe.NetNamespaced = netProof.SelfDescriptor != "" && netProof.InitDescriptor != "" && !netProof.MatchesInit

	// PID namespace: if /proc/1/cmdline is NOT the host init, we're namespaced.
	if data, err := os.ReadFile("/proc/1/cmdline"); err == nil {
		cmd := strings.TrimRight(string(data), "\x00")
		probe.PIDNamespaced = probe.PIDNamespaced || (!strings.Contains(cmd, "init") && !strings.Contains(cmd, "systemd"))
	}

	// Mount namespace: check /proc/self/mountinfo for overlay or tmpfs root.
	if data, err := os.ReadFile("/proc/self/mountinfo"); err == nil {
		content := string(data)
		probe.MountNamespaced = probe.MountNamespaced || strings.Contains(content, "overlay") || strings.Contains(content, "aufs")
	}

	// Network namespace: if /proc/sys/net/ipv4/ip_forward is unreadable or
	// /sys/class/net has only lo, we're likely net-namespaced.
	if entries, err := os.ReadDir("/sys/class/net"); err == nil {
		nonLoCount := 0
		for _, e := range entries {
			if e.Name() != "lo" {
				nonLoCount++
			}
		}
		probe.NetNamespaced = probe.NetNamespaced || nonLoCount == 0
	}

	// Seccomp: /proc/self/status Seccomp field.
	if data, err := os.ReadFile("/proc/self/status"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "Seccomp:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 && fields[1] != "0" {
					probe.SeccompActive = true
				}
			}
		}
	}

	// Cgroup: detect version and fencing.
	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err == nil {
		probe.CgroupVersion = "v2"
		probe.CgroupFenced = true
	} else if _, err := os.Stat("/sys/fs/cgroup"); err == nil {
		probe.CgroupVersion = "v1"
		probe.CgroupFenced = true
	}

	// Readonly root: attempt to create a temp file at /.
	tmpPath := "/.cadence_probe_ro_test"
	f, err := os.Create(tmpPath)
	if err != nil {
		probe.ReadonlyRoot = true
	} else {
		f.Close()
		os.Remove(tmpPath)
	}

	return probe
}

// SeccompProfile describes a required seccomp posture for a sandbox backend.
type SeccompProfile struct {
	BackendType     string   `json:"backendType"`
	RequiredMode    int      `json:"requiredMode"`    // 1=strict, 2=filter
	AllowedSyscalls []string `json:"allowedSyscalls"` // whitelist for audit
}

// DefaultSeccompProfiles returns the built-in seccomp expectations per backend.
func DefaultSeccompProfiles() []SeccompProfile {
	return []SeccompProfile{
		{BackendType: "microvm", RequiredMode: 2, AllowedSyscalls: []string{"read", "write", "exit_group", "futex"}},
		{BackendType: "container", RequiredMode: 2, AllowedSyscalls: []string{"read", "write", "exit_group", "futex", "mmap", "mprotect"}},
		{BackendType: "host-local", RequiredMode: 0, AllowedSyscalls: nil},
	}
}

func normalizedBackendType(backend string) string {
	switch strings.TrimSpace(backend) {
	case "container-runtime", "container":
		return "container"
	case "microvm-runtime", "microvm":
		return "microvm"
	default:
		return "host-local"
	}
}

// MatchSeccompProfile returns the SeccompProfile matching the given backend, or
// nil if no profile applies (e.g. host-local with no requirement).
func MatchSeccompProfile(backend string) *SeccompProfile {
	normalized := normalizedBackendType(backend)
	for _, p := range DefaultSeccompProfiles() {
		if p.BackendType == normalized {
			return &p
		}
	}
	return nil
}

// ValidateSeccompPosture checks whether the runtime isolation probe meets the
// seccomp requirements for the given backend.
func ValidateSeccompPosture(probe IsolationProbe, backend string) error {
	profile := MatchSeccompProfile(backend)
	if profile == nil || profile.RequiredMode == 0 {
		return nil // no seccomp requirement
	}
	if !probe.SeccompActive {
		return fmt.Errorf("sandbox: backend %q requires seccomp mode >= %d but seccomp is inactive", backend, profile.RequiredMode)
	}
	return nil
}

func DescribeBackendAttestation(p Profile, probe IsolationProbe) BackendAttestation {
	backend := selectedBackend(p)
	normalized := normalizedBackendType(backend)
	observed := observedIsolationChecks(probe)
	required := requiredIsolationChecks(normalized)
	attestation := BackendAttestation{
		Backend:           backend,
		RequiredChecks:    required,
		ObservedChecks:    observed,
		AttestationStatus: "launcher-only",
		AttestationLevel:  "launcher-only",
		SeccompProfile:    MatchSeccompProfile(backend),
	}
	if normalized == "host-local" {
		return attestation
	}
	attestation.AttestationStatus = "verified"
	switch normalized {
	case "container":
		attestation.AttestationLevel = "namespace-verified"
	case "microvm":
		attestation.AttestationLevel = "vm-verified"
	default:
		attestation.AttestationLevel = "backend-verified"
	}
	observedSet := make(map[string]bool, len(observed))
	for _, check := range observed {
		observedSet[check] = true
	}
	for _, check := range required {
		if !observedSet[check] {
			attestation.FailureReasons = append(attestation.FailureReasons, fmt.Sprintf("missing %s proof", check))
		}
	}
	if err := ValidateSeccompPosture(probe, backend); err != nil {
		attestation.FailureReasons = append(attestation.FailureReasons, err.Error())
	}
	if len(attestation.FailureReasons) > 0 {
		attestation.AttestationStatus = "insufficient"
		attestation.AttestationLevel = "profile-declared-only"
	}
	return attestation
}

func ValidateBackendAttestation(p Profile, probe IsolationProbe) error {
	attestation := DescribeBackendAttestation(p, probe)
	if len(attestation.FailureReasons) == 0 {
		return nil
	}
	return fmt.Errorf(
		"sandbox: backend %q attestation failed: %s",
		selectedBackend(p),
		strings.Join(attestation.FailureReasons, "; "),
	)
}

func observedIsolationChecks(probe IsolationProbe) []string {
	checks := []string{}
	if probe.PIDNamespaced {
		checks = append(checks, "pid-namespace")
	}
	if probe.MountNamespaced {
		checks = append(checks, "mount-namespace")
	}
	if probe.NetNamespaced {
		checks = append(checks, "network-namespace")
	}
	if probe.SeccompActive {
		checks = append(checks, "seccomp-active")
	}
	if probe.CgroupFenced {
		checks = append(checks, "cgroup-fenced")
	}
	if probe.NamespaceProofHash != "" {
		checks = append(checks, "namespace-proof-hash")
	}
	if probe.ReadonlyRoot {
		checks = append(checks, "readonly-root")
	}
	sort.Strings(checks)
	return checks
}

func requiredIsolationChecks(normalizedBackend string) []string {
	switch normalizedBackend {
	case "container", "microvm":
		return []string{
			"cgroup-fenced",
			"mount-namespace",
			"namespace-proof-hash",
			"network-namespace",
			"pid-namespace",
			"seccomp-active",
		}
	default:
		return nil
	}
}
