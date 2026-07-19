package plugins

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/AzzCraft/cadence-oss/cadence-core/internal/sandbox"
)

const ProtocolVersion = "1.0.0"
const TaskCAD004 = "CAD-004"

type CompatWindow struct {
	MinProtocol string `json:"minProtocol,omitempty"`
	MaxProtocol string `json:"maxProtocol,omitempty"`
}

type Manifest struct {
	SchemaVersion  string       `json:"schemaVersion"`
	PluginID       string       `json:"pluginId"`
	DisplayName    string       `json:"displayName,omitempty"`
	Version        string       `json:"version,omitempty"`
	Kind           string       `json:"kind,omitempty"`
	Language       string       `json:"language,omitempty"`
	Protocol       string       `json:"protocol,omitempty"`
	EntryPoint     string       `json:"entryPoint,omitempty"`
	Entrypoint     string       `json:"entrypoint,omitempty"`
	Runtime        string       `json:"runtime,omitempty"`
	Capabilities   []string     `json:"capabilities"`
	TimeoutMs      int          `json:"timeoutMs,omitempty"`
	CompatWindow   CompatWindow `json:"compatWindow,omitempty"`
	EnvAllowlist   []string     `json:"envAllowlist,omitempty"`
	SandboxProfile string       `json:"sandboxProfile,omitempty"`
	Permissions    Permissions  `json:"permissions,omitempty"`

	manifestPath string
}

type Permissions struct {
	Network    bool                  `json:"network"`
	Filesystem FilesystemPermissions `json:"filesystem,omitempty"`
	EnvRead    []string              `json:"envRead,omitempty"`
}

type FilesystemPermissions struct {
	Read  []string `json:"read,omitempty"`
	Write []string `json:"write,omitempty"`
}

type RunRequest struct {
	PluginID        string            `json:"pluginId"`
	ProtocolVersion string            `json:"protocolVersion"`
	RunID           string            `json:"runId"`
	InputHash       string            `json:"inputHash"`
	RepoRoot        string            `json:"repoRoot"`
	WorkingDir      string            `json:"workingDir"`
	OutputDir       string            `json:"outputDir"`
	Files           []string          `json:"files,omitempty"`
	Parameters      map[string]string `json:"parameters,omitempty"`
	Environment     map[string]string `json:"environment,omitempty"`
}

type Violation struct {
	RuleID   string `json:"ruleId"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
	File     string `json:"file,omitempty"`
	Line     int    `json:"line,omitempty"`
}

type Response struct {
	PluginID        string         `json:"pluginId,omitempty"`
	ProtocolVersion string         `json:"protocolVersion,omitempty"`
	Status          string         `json:"status,omitempty"`
	Violations      []Violation    `json:"violations,omitempty"`
	Diagnostics     map[string]any `json:"diagnostics,omitempty"`
	Metrics         map[string]any `json:"metrics,omitempty"`
	IR              map[string]any `json:"ir,omitempty"`
}

type RunResult struct {
	PluginID        string         `json:"pluginId"`
	ManifestPath    string         `json:"manifestPath"`
	ResolvedCommand []string       `json:"resolvedCommand"`
	WorkingDir      string         `json:"workingDir"`
	OutputDir       string         `json:"outputDir"`
	EnvKeys         []string       `json:"envKeys"`
	StdoutHash      string         `json:"stdoutHash"`
	StderrHash      string         `json:"stderrHash"`
	ExitCode        int            `json:"exitCode"`
	Response        Response       `json:"response"`
	Diagnostics     map[string]any `json:"diagnostics,omitempty"`
}

func Load(path string) (Manifest, error) {
	var manifest Manifest
	data, err := os.ReadFile(path)
	if err != nil {
		return manifest, err
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		return manifest, err
	}
	manifest.manifestPath = path
	if manifest.EntryPoint == "" {
		manifest.EntryPoint = manifest.Entrypoint
	}
	if manifest.Protocol == "" {
		manifest.Protocol = ProtocolVersion
	}
	if manifest.TimeoutMs <= 0 {
		manifest.TimeoutMs = 60000
	}
	if len(manifest.EnvAllowlist) == 0 {
		manifest.EnvAllowlist = []string{"PATH", "HOME", "TMPDIR", "TMP", "TEMP"}
	}
	if manifest.SandboxProfile == "" {
		manifest.SandboxProfile = "readonly-no-network"
	}
	if strings.TrimSpace(manifest.PluginID) == "" {
		return manifest, fmt.Errorf("plugin manifest %s: pluginId is required", path)
	}
	if strings.TrimSpace(manifest.EntryPoint) == "" {
		return manifest, fmt.Errorf("plugin manifest %s: entryPoint is required", path)
	}
	if strings.TrimSpace(manifest.Runtime) == "" {
		return manifest, fmt.Errorf("plugin manifest %s: runtime is required", path)
	}
	return manifest, nil
}

// BindPluginProfile returns the CAD-004 sandbox policy bound to a plugin manifest.
func BindPluginProfile(manifest Manifest, profileID string) (sandbox.CapabilityPolicy, error) {
	if profileID == "" {
		profileID = manifest.SandboxProfile
	}
	if profileID == "" {
		return sandbox.CapabilityPolicy{}, fmt.Errorf("CAD-004 plugin %q requires sandboxProfile", manifest.PluginID)
	}
	if manifest.SandboxProfile != "" && manifest.SandboxProfile != profileID {
		return sandbox.CapabilityPolicy{}, fmt.Errorf("CAD-004 plugin %q sandboxProfile mismatch: manifest=%s requested=%s", manifest.PluginID, manifest.SandboxProfile, profileID)
	}
	return sandbox.CapabilityPolicy{
		SandboxProfile:  profileID,
		Network:         manifest.Permissions.Network,
		FilesystemWrite: manifest.Permissions.Filesystem.Write,
		EnvRead:         manifest.Permissions.EnvRead,
	}, nil
}

func Run(manifest Manifest, req RunRequest) (*RunResult, error) {
	// A capability declaration is not a sandbox.  The historical runner invoked
	// arbitrary entry points directly on the host while merely recording a
	// profile.  Do not execute third-party plugin code until an isolated runner
	// enforces BindPluginProfile's policy on every supported platform.
	return nil, fmt.Errorf("CAD-004 plugin execution is disabled in the public v1.0 runtime until an enforcing isolated runner is available")
	/*
		if req.ProtocolVersion == "" {
			req.ProtocolVersion = ProtocolVersion
		}
		if req.PluginID == "" {
			req.PluginID = manifest.PluginID
		}
		if req.PluginID != manifest.PluginID {
			return nil, fmt.Errorf("plugin request id %q does not match manifest %q", req.PluginID, manifest.PluginID)
		}

		timeout := time.Duration(manifest.TimeoutMs) * time.Millisecond
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		command, err := resolvedCommand(manifest)
		if err != nil {
			return nil, err
		}

		cmd := exec.CommandContext(ctx, command[0], command[1:]...)
		if strings.TrimSpace(req.WorkingDir) != "" {
			cmd.Dir = req.WorkingDir
		}

		env, envKeys := buildEnv(manifest, req)
		cmd.Env = env

		inputJSON, err := json.Marshal(req)
		if err != nil {
			return nil, fmt.Errorf("marshal request: %w", err)
		}

		stdinPipe, err := cmd.StdinPipe()
		if err != nil {
			return nil, fmt.Errorf("stdin pipe: %w", err)
		}
		outPipe, err := cmd.StdoutPipe()
		if err != nil {
			return nil, fmt.Errorf("stdout pipe: %w", err)
		}
		errPipe, err := cmd.StderrPipe()
		if err != nil {
			return nil, fmt.Errorf("stderr pipe: %w", err)
		}

		if err := cmd.Start(); err != nil {
			return nil, fmt.Errorf("start plugin %q: %w", manifest.PluginID, err)
		}
		if _, err := stdinPipe.Write(inputJSON); err != nil {
			return nil, fmt.Errorf("write stdin: %w", err)
		}
		_ = stdinPipe.Close()

		stdout, err := readAll(outPipe)
		if err != nil {
			return nil, fmt.Errorf("read stdout: %w", err)
		}
		stderr, err := readAll(errPipe)
		if err != nil {
			return nil, fmt.Errorf("read stderr: %w", err)
		}

		runResult := &RunResult{
			PluginID:        manifest.PluginID,
			ManifestPath:    manifest.manifestPath,
			ResolvedCommand: command,
			WorkingDir:      req.WorkingDir,
			OutputDir:       req.OutputDir,
			EnvKeys:         envKeys,
			StdoutHash:      hashBytes(stdout),
			StderrHash:      hashBytes(stderr),
			Diagnostics: map[string]any{
				"stderr": string(stderr),
			},
		}

		if err := cmd.Wait(); err != nil {
			runResult.ExitCode = -1
			if exitErr, ok := err.(*exec.ExitError); ok {
				runResult.ExitCode = exitErr.ExitCode()
			}
			return nil, fmt.Errorf("plugin %q exited with error: %w", manifest.PluginID, err)
		}
		runResult.ExitCode = 0

		var response Response
		if err := json.Unmarshal(stdout, &response); err != nil {
			return nil, fmt.Errorf("parse plugin output: %w", err)
		}
		if response.PluginID == "" {
			response.PluginID = manifest.PluginID
		}
		if response.PluginID != manifest.PluginID {
			return nil, fmt.Errorf("plugin %q returned mismatched pluginId %q", manifest.PluginID, response.PluginID)
		}
		if response.ProtocolVersion == "" {
			response.ProtocolVersion = manifest.Protocol
		}
		if !protocolCompatible(response.ProtocolVersion, manifest) {
			return nil, fmt.Errorf(
				"plugin %q returned incompatible protocol %q",
				manifest.PluginID,
				response.ProtocolVersion,
			)
		}
		if response.Status == "" {
			if len(response.Violations) == 0 {
				response.Status = "ok"
			} else {
				response.Status = "violations"
			}
		}
		runResult.Response = response
		return runResult, nil
	*/
}

func resolvedCommand(manifest Manifest) ([]string, error) {
	entry := manifest.EntryPoint
	if !filepath.IsAbs(entry) {
		entry = filepath.Clean(filepath.Join(filepath.Dir(manifest.manifestPath), entry))
	}
	switch manifest.Runtime {
	case "python3", "node":
		return []string{manifest.Runtime, entry}, nil
	case "direct":
		return []string{entry}, nil
	default:
		return nil, fmt.Errorf("plugin manifest %s: unsupported runtime %q", manifest.manifestPath, manifest.Runtime)
	}
}

func ResolvedCommand(manifest Manifest) ([]string, error) {
	return resolvedCommand(manifest)
}

func protocolCompatible(version string, manifest Manifest) bool {
	if version == "" {
		return false
	}
	minProtocol := manifest.CompatWindow.MinProtocol
	if minProtocol == "" {
		minProtocol = manifest.Protocol
	}
	if minProtocol != "" && version < minProtocol {
		return false
	}
	maxProtocol := manifest.CompatWindow.MaxProtocol
	if strings.HasSuffix(maxProtocol, ".x") {
		return strings.HasPrefix(version, strings.TrimSuffix(maxProtocol, ".x")+".")
	}
	if maxProtocol != "" && version > maxProtocol {
		return false
	}
	return true
}

func buildEnv(manifest Manifest, req RunRequest) ([]string, []string) {
	envMap := map[string]string{
		"CADENCE_PLUGIN_ID":         manifest.PluginID,
		"CADENCE_PLUGIN_PROTOCOL":   req.ProtocolVersion,
		"CADENCE_PLUGIN_WORKDIR":    req.WorkingDir,
		"CADENCE_PLUGIN_OUTPUT_DIR": req.OutputDir,
	}
	for _, key := range manifest.EnvAllowlist {
		value, ok := os.LookupEnv(key)
		if ok {
			envMap[key] = value
		}
	}
	for key, value := range req.Environment {
		envMap[key] = value
	}
	keys := make([]string, 0, len(envMap))
	for key := range envMap {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	env := make([]string, 0, len(keys))
	for _, key := range keys {
		env = append(env, key+"="+envMap[key])
	}
	return env, keys
}

func readAll(r interface{ Read([]byte) (int, error) }) ([]byte, error) {
	var buf []byte
	tmp := make([]byte, 4096)
	for {
		n, err := r.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if err != nil {
			if err.Error() == "EOF" {
				break
			}
			return buf, err
		}
	}
	return buf, nil
}

func hashBytes(data []byte) string {
	sum := sha256Sum(data)
	return "sha256:" + sum
}

func sha256Sum(data []byte) string {
	h := sha256.New()
	h.Write(data)
	return fmt.Sprintf("%x", h.Sum(nil))
}

// ValidateManifestConsistency checks that a plugin manifest is semantically
// consistent: pluginId format, version format, timeout within bounds, and
// capabilities contain no duplicates.
func ValidateManifestConsistency(m Manifest) error {
	if m.PluginID == "" {
		return errors.New("pluginId is required")
	}
	if m.Runtime == "" {
		return errors.New("runtime is required")
	}
	if m.TimeoutMs < 1000 || m.TimeoutMs > 600000 {
		return fmt.Errorf("timeoutMs %d outside allowed range [1000, 600000]", m.TimeoutMs)
	}
	seen := map[string]bool{}
	for _, cap := range m.Capabilities {
		if seen[cap] {
			return fmt.Errorf("duplicate capability: %s", cap)
		}
		seen[cap] = true
	}
	return nil
}

// AggregatedResults consolidates violations and diagnostics across plugin runs.
type AggregatedResults struct {
	TotalViolations int            `json:"totalViolations"`
	TotalPlugins    int            `json:"totalPlugins"`
	FailedPlugins   int            `json:"failedPlugins"`
	Violations      []Violation    `json:"violations"`
	Diagnostics     map[string]any `json:"diagnostics,omitempty"`
}

// CollectPluginResults aggregates results from multiple plugin runs into a
// single summary with merged violations and diagnostics.
func CollectPluginResults(runs []RunResult) AggregatedResults {
	agg := AggregatedResults{
		TotalPlugins: len(runs),
		Diagnostics:  map[string]any{},
	}
	for _, run := range runs {
		if run.ExitCode != 0 {
			agg.FailedPlugins++
		}
		agg.Violations = append(agg.Violations, run.Response.Violations...)
		for k, v := range run.Response.Diagnostics {
			agg.Diagnostics[run.PluginID+"."+k] = v
		}
	}
	agg.TotalViolations = len(agg.Violations)
	return agg
}
