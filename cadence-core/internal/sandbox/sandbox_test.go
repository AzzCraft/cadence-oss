package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeAdapterScript(t *testing.T, dir string, response string) string {
	t.Helper()
	path := filepath.Join(dir, "runtime-adapter.sh")
	body := "#!/bin/sh\ncat <<'EOF'\n" + response + "\nEOF\n"
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatalf("write adapter script: %v", err)
	}
	return path
}

func TestValidateGoodProfile(t *testing.T) {
	p := Profile{
		SandboxID:          "test-sandbox",
		Filesystem:         "read-only",
		TimeSource:         "epoch-frozen",
		DeterministicClock: true,
	}
	if err := Validate(p); err != nil {
		t.Fatalf("expected valid profile: %v", err)
	}
}

func TestValidateRejectsMissingSandboxID(t *testing.T) {
	p := Profile{Filesystem: "read-only", TimeSource: "system"}
	if err := Validate(p); err == nil {
		t.Fatal("expected error for missing sandboxId")
	}
}

func TestValidateRejectsInvalidFilesystem(t *testing.T) {
	p := Profile{SandboxID: "test", Filesystem: "potato", TimeSource: "system"}
	if err := Validate(p); err == nil {
		t.Fatal("expected error for invalid filesystem")
	}
}

func TestValidateRejectsDeterministicClockWithSystemTime(t *testing.T) {
	p := Profile{
		SandboxID:          "test",
		Filesystem:         "read-only",
		TimeSource:         "system",
		DeterministicClock: true,
	}
	if err := Validate(p); err == nil {
		t.Fatal("expected error for deterministicClock with system timeSource")
	}
}

func TestEnforceBasicProfile(t *testing.T) {
	p := Profile{
		SandboxID:     "dev",
		Filesystem:    "host",
		NetworkAccess: true,
		TimeSource:    "system",
		AllowedMounts: []string{"/tmp", "./data"},
	}
	enf := Enforce(p, t.TempDir())
	if !enf.Passed {
		t.Fatalf("expected enforcement to pass, failures: %v", enf.FailureReasons)
	}
	if len(enf.Checks) == 0 {
		t.Fatal("expected at least one check")
	}
}

func TestEnforceRejectsInvalidMount(t *testing.T) {
	p := Profile{
		SandboxID:     "strict",
		Filesystem:    "read-only",
		NetworkAccess: false,
		TimeSource:    "epoch-frozen",
		AllowedMounts: []string{"relative-no-prefix"},
	}
	enf := Enforce(p, t.TempDir())
	if enf.Passed {
		t.Fatal("expected enforcement to fail for invalid mount path")
	}
}

func TestLoadStructuredProfile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "profile.json")
	payload := `{
  "schemaVersion": "1.0.0",
  "profileId": "rootless-dev",
  "filesystem": {
    "mode": "workspace-only",
    "readOnlyInputs": true,
    "writableOutputDir": ".cadence/out"
  },
  "network": {
    "access": false
  },
  "resources": {
    "timeoutSeconds": 300
  },
  "timeSource": "injected"
}`
	if err := os.WriteFile(path, []byte(payload), 0o644); err != nil {
		t.Fatalf("write profile: %v", err)
	}

	profile, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if profile.ProfileID != "rootless-dev" {
		t.Fatalf("ProfileID = %q, want rootless-dev", profile.ProfileID)
	}
	if profile.Filesystem != "workspace-only" {
		t.Fatalf("Filesystem = %q, want workspace-only", profile.Filesystem)
	}
	if profile.Backend != "host-local" {
		t.Fatalf("Backend = %q, want host-local", profile.Backend)
	}
	if !profile.ReadOnlyInputs {
		t.Fatal("expected ReadOnlyInputs=true")
	}
	if profile.WritableOutputDir != ".cadence/out" {
		t.Fatalf("WritableOutputDir = %q", profile.WritableOutputDir)
	}
	if profile.NetworkAccess {
		t.Fatal("expected NetworkAccess=false")
	}
	if profile.ResourceLimits == nil || profile.ResourceLimits.TimeoutSeconds != 300 {
		t.Fatalf("unexpected resource limits: %+v", profile.ResourceLimits)
	}
}

func TestValidateRejectsNegativeStructuredLimit(t *testing.T) {
	p := Profile{
		ProfileID:         "rootless-dev",
		Backend:           "host-local",
		Filesystem:        "workspace-only",
		TimeSource:        "injected",
		ReadOnlyInputs:    true,
		WritableOutputDir: ".cadence/out",
		ResourceLimits:    &Limits{TimeoutSeconds: -1},
	}
	if err := Validate(p); err == nil {
		t.Fatal("expected error for negative timeoutSeconds")
	}
}

func TestValidateRejectsBackendFilesystemMismatch(t *testing.T) {
	p := Profile{
		ProfileID:     "ci-container",
		Backend:       "host-local",
		Filesystem:    "container-isolated",
		TimeSource:    "injected",
		NetworkAccess: false,
	}
	if err := Validate(p); err == nil {
		t.Fatal("expected backend/filesystem mismatch to fail")
	}
}

func TestValidateRejectsNonHostBackendWithoutReadOnlyInputs(t *testing.T) {
	p := Profile{
		ProfileID:      "ci-container",
		Backend:        "container-runtime",
		Filesystem:     "container-isolated",
		TimeSource:     "injected",
		NetworkAccess:  false,
		ResourceLimits: &Limits{TimeoutSeconds: 30},
	}
	if err := Validate(p); err == nil {
		t.Fatal("expected non-host backend without readOnlyInputs to fail")
	}
}

func TestValidateParentEnvironmentRejectsReservedKeys(t *testing.T) {
	err := ValidateParentEnvironment([]string{
		"PATH=/usr/bin",
		"CADENCE_SANDBOX_PROFILE=host-local",
	})
	if err == nil || !strings.Contains(err.Error(), "reserved key") {
		t.Fatalf("expected reserved-key error, got %v", err)
	}
}

func TestValidateParentEnvironmentAllowsRuntimeAdapterDiscoveryKeys(t *testing.T) {
	err := ValidateParentEnvironment([]string{
		"PATH=/usr/bin",
		"CADENCE_SANDBOX_CONTAINER_ADAPTER=/tmp/container-adapter",
		"CADENCE_SANDBOX_MICROVM_ADAPTER=/tmp/microvm-adapter",
	})
	if err != nil {
		t.Fatalf("expected adapter discovery env vars to be allowed, got %v", err)
	}
}

func TestBuildCommandEnvUsesAllowlistOnly(t *testing.T) {
	t.Setenv("PATH", "/usr/bin")
	t.Setenv("HOME", "/tmp/home")
	t.Setenv("SECRET_TOKEN", "should-not-leak")
	t.Setenv("HTTP_PROXY", "http://proxy.internal")

	env := buildCommandEnv(Profile{
		ProfileID:      "launcher-dev",
		Backend:        "host-local",
		Filesystem:     "workspace-only",
		NetworkAccess:  false,
		TimeSource:     "injected",
		ReadOnlyInputs: true,
	}, map[string]string{
		"PYTHONDONTWRITEBYTECODE": "1",
	})

	joined := strings.Join(env, "\n")
	if !strings.Contains(joined, "PATH=/usr/bin") {
		t.Fatalf("expected PATH in command env, got %v", env)
	}
	if strings.Contains(joined, "SECRET_TOKEN=") {
		t.Fatalf("unexpected leaked secret env: %v", env)
	}
	if strings.Contains(joined, "HTTP_PROXY=") {
		t.Fatalf("expected proxy vars to be stripped when network disabled: %v", env)
	}
	if !strings.Contains(joined, "CADENCE_SANDBOX_NETWORK=off") {
		t.Fatalf("expected sandbox network marker, got %v", env)
	}
}

func TestExecuteLaunchesCommand(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "echo-ok.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\necho ok\n"), 0o755); err != nil {
		t.Fatalf("write script: %v", err)
	}

	execution := Execute(Profile{
		ProfileID:      "launcher-dev",
		Backend:        "host-local",
		Filesystem:     "workspace-only",
		NetworkAccess:  false,
		TimeSource:     "injected",
		ReadOnlyInputs: true,
		ResourceLimits: &Limits{TimeoutSeconds: 5},
	}, CommandRequest{
		Command: []string{script},
		WorkDir: dir,
	})

	if !execution.Result.Passed {
		t.Fatalf("expected launcher execution to pass, failures: %v", execution.Result.FailureReasons)
	}
	if execution.Result.Status != "ok" {
		t.Fatalf("unexpected status: %s", execution.Result.Status)
	}
	if execution.Result.Backend != "host-local" {
		t.Fatalf("unexpected backend: %s", execution.Result.Backend)
	}
	if execution.Result.BackendEvidence["backend"] != "host-local" {
		t.Fatalf("expected backend evidence to record host-local backend: %+v", execution.Result.BackendEvidence)
	}
	if execution.Result.ExitCode != 0 {
		t.Fatalf("unexpected exit code: %d", execution.Result.ExitCode)
	}
	if execution.Result.StdoutHash == "" || execution.Result.StderrHash == "" {
		t.Fatal("expected stdout/stderr hashes to be populated")
	}
}

func TestExecuteEmitsBackendEvidenceForNonHostBackends(t *testing.T) {
	dir := t.TempDir()
	adapter := writeAdapterScript(t, dir, `{"exitCode":0,"stdout":"backend\n","stderr":"","observedChecks":["cgroup-fenced","mount-namespace","namespace-proof-hash","network-namespace","pid-namespace","seccomp-active"],"namespaceProofHash":"sha256:test","namespaceProofs":[{"namespace":"pid","selfDescriptor":"pid:[2]","initDescriptor":"pid:[1]","matchesInit":false}]}`)
	t.Setenv("CADENCE_SANDBOX_CONTAINER_ADAPTER", adapter)

	execution := Execute(Profile{
		ProfileID:      "ci-container",
		Backend:        "container-runtime",
		Filesystem:     "container-isolated",
		NetworkAccess:  false,
		TimeSource:     "injected",
		ReadOnlyInputs: true,
		ResourceLimits: &Limits{TimeoutSeconds: 5},
	}, CommandRequest{
		Command: []string{filepath.Join(dir, "missing-local-command")},
		WorkDir: dir,
	})

	if !execution.Result.Passed {
		t.Fatalf("expected execution to pass, failures: %v", execution.Result.FailureReasons)
	}
	if execution.Result.Backend != "container-runtime" {
		t.Fatalf("unexpected backend: %s", execution.Result.Backend)
	}
	if execution.Result.Mode != "runtime-exec" {
		t.Fatalf("unexpected mode: %s", execution.Result.Mode)
	}
	if execution.Result.IsolationLevel != "backend-container-runtime-enforced" {
		t.Fatalf("unexpected isolation level: %s", execution.Result.IsolationLevel)
	}
	if execution.Result.BackendEvidence["backend"] != "container-runtime" {
		t.Fatalf("unexpected backend evidence: %+v", execution.Result.BackendEvidence)
	}
	if _, ok := execution.Result.BackendEvidence["contractHash"]; !ok {
		t.Fatalf("expected backend evidence contract hash, got: %+v", execution.Result.BackendEvidence)
	}
	if execution.Result.BackendEvidence["attestationStatus"] != "verified" {
		t.Fatalf("expected verified attestation status, got %+v", execution.Result.BackendEvidence)
	}
	if execution.Result.BackendEvidence["adapterEnvVar"] != "CADENCE_SANDBOX_CONTAINER_ADAPTER" {
		t.Fatalf("expected adapter env var to be recorded, got %+v", execution.Result.BackendEvidence)
	}
	if execution.Result.ExitCode != 0 {
		t.Fatalf("unexpected exit code: %d", execution.Result.ExitCode)
	}
	if string(execution.Stdout) != "backend\n" {
		t.Fatalf("unexpected stdout: %q", execution.Stdout)
	}
}

func TestExecuteFailsClosedWhenRuntimeAdapterMissing(t *testing.T) {
	dir := t.TempDir()
	execution := Execute(Profile{
		ProfileID:      "ci-container",
		Backend:        "container-runtime",
		Filesystem:     "container-isolated",
		NetworkAccess:  false,
		TimeSource:     "injected",
		ReadOnlyInputs: true,
		ResourceLimits: &Limits{TimeoutSeconds: 5},
	}, CommandRequest{
		Command: []string{filepath.Join(dir, "missing-local-command")},
		WorkDir: dir,
	})

	if execution.Result.Passed {
		t.Fatal("expected execution to fail when runtime adapter is missing")
	}
	if execution.Result.Status != "denied" {
		t.Fatalf("unexpected status: %s", execution.Result.Status)
	}
	if !strings.Contains(strings.Join(execution.Result.FailureReasons, "\n"), "CADENCE_SANDBOX_CONTAINER_ADAPTER") {
		t.Fatalf("expected missing adapter env var failure, got %v", execution.Result.FailureReasons)
	}
}

func TestExecuteFailsClosedWhenRuntimeProofIsInsufficient(t *testing.T) {
	dir := t.TempDir()
	adapter := writeAdapterScript(t, dir, `{"exitCode":0,"stdout":"[]\n","stderr":"","observedChecks":["cgroup-fenced"],"failureReasons":["adapter observed partial fences only"]}`)
	t.Setenv("CADENCE_SANDBOX_CONTAINER_ADAPTER", adapter)

	execution := Execute(Profile{
		ProfileID:      "ci-container",
		Backend:        "container-runtime",
		Filesystem:     "container-isolated",
		NetworkAccess:  false,
		TimeSource:     "injected",
		ReadOnlyInputs: true,
		ResourceLimits: &Limits{TimeoutSeconds: 5},
	}, CommandRequest{
		Command: []string{filepath.Join(dir, "missing-local-command")},
		WorkDir: dir,
	})

	if execution.Result.Passed {
		t.Fatal("expected insufficient runtime proof to fail closed")
	}
	if execution.Result.Status != "denied" {
		t.Fatalf("unexpected status: %s", execution.Result.Status)
	}
	if execution.Result.BackendEvidence["attestationStatus"] != "insufficient" {
		t.Fatalf("expected insufficient attestation status, got %+v", execution.Result.BackendEvidence)
	}
}

func TestExecuteFailsClosedOnInvalidMount(t *testing.T) {
	execution := Execute(Profile{
		ProfileID:     "launcher-strict",
		Backend:       "host-local",
		Filesystem:    "workspace-only",
		NetworkAccess: false,
		TimeSource:    "injected",
		AllowedMounts: []string{"relative-no-prefix"},
	}, CommandRequest{
		Command: []string{"echo", "ignored"},
		WorkDir: t.TempDir(),
	})

	if execution.Result.Passed {
		t.Fatal("expected invalid mount to fail closed")
	}
	if execution.Result.Status != "denied" {
		t.Fatalf("expected denied status, got %s", execution.Result.Status)
	}
}

func TestExecuteTimesOut(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "sleep.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nsleep 2\n"), 0o755); err != nil {
		t.Fatalf("write script: %v", err)
	}

	execution := Execute(Profile{
		ProfileID:      "launcher-timeout",
		Backend:        "host-local",
		Filesystem:     "workspace-only",
		NetworkAccess:  false,
		TimeSource:     "injected",
		ResourceLimits: &Limits{TimeoutSeconds: 1},
	}, CommandRequest{
		Command: []string{script},
		WorkDir: dir,
	})

	if execution.Result.Passed {
		t.Fatal("expected timeout to fail")
	}
	if execution.Result.Status != "timeout" {
		t.Fatalf("expected timeout status, got %s", execution.Result.Status)
	}
}

func TestEscapeClassificationMinimalMicroVM(t *testing.T) {
	p := Profile{
		ProfileID:         "microvm-test",
		Backend:           "microvm-runtime",
		Filesystem:        "microvm-isolated",
		NetworkAccess:     false,
		TimeSource:        "epoch-frozen",
		ReadOnlyInputs:    true,
		WritableOutputDir: "/out",
		ResourceLimits:    &Limits{TimeoutSeconds: 30},
	}
	ec := EscapeClassification(p)
	if ec["level"] != "minimal" {
		t.Fatalf("expected minimal escape level for microvm, got %v", ec["level"])
	}
	if ec["escapeSurface"] != "vm-boundary" {
		t.Fatalf("expected vm-boundary surface, got %v", ec["escapeSurface"])
	}
}

func TestEscapeClassificationMinimalContainer(t *testing.T) {
	p := Profile{
		ProfileID:         "container-test",
		Backend:           "container-runtime",
		Filesystem:        "container-isolated",
		NetworkAccess:     false,
		TimeSource:        "epoch-frozen",
		ReadOnlyInputs:    true,
		WritableOutputDir: "/out",
		ResourceLimits:    &Limits{TimeoutSeconds: 30},
	}
	ec := EscapeClassification(p)
	if ec["level"] != "minimal" {
		t.Fatalf("expected minimal escape level for container, got %v", ec["level"])
	}
	if ec["escapeSurface"] != "container-boundary" {
		t.Fatalf("expected container-boundary surface, got %v", ec["escapeSurface"])
	}
}

func TestEscapeClassificationBoundedHostLocal(t *testing.T) {
	p := Profile{
		ProfileID:         "bounded-host",
		Backend:           "host-local",
		Filesystem:        "workspace-only",
		NetworkAccess:     false,
		TimeSource:        "injected",
		ReadOnlyInputs:    true,
		WritableOutputDir: "/out",
		ResourceLimits:    &Limits{TimeoutSeconds: 30},
	}
	ec := EscapeClassification(p)
	if ec["level"] != "bounded" {
		t.Fatalf("expected bounded escape level for restricted host-local, got %v", ec["level"])
	}
}

func TestEscapeClassificationPermissiveHostLocal(t *testing.T) {
	p := Profile{
		ProfileID:     "permissive-host",
		Backend:       "host-local",
		Filesystem:    "host",
		NetworkAccess: true,
		TimeSource:    "system",
	}
	ec := EscapeClassification(p)
	if ec["level"] != "permissive" {
		t.Fatalf("expected permissive escape level for unrestricted host-local, got %v", ec["level"])
	}
}

func TestProbeRuntimeIsolationReturnsStruct(t *testing.T) {
	probe := ProbeRuntimeIsolation()
	// On a normal dev machine (not in a container), we expect most fields false.
	// The key assertion is that the function runs without panic and returns a
	// valid struct.
	if probe.CgroupVersion == "" {
		// CgroupVersion should be "v1", "v2", or "" (non-linux)
		// Just ensure we get a string back
		t.Log("cgroup version is empty (likely non-linux)")
	}
	// Smoke: PIDNamespaced should be false on a bare metal/VM host
	if probe.PIDNamespaced {
		t.Log("running inside a PID namespace")
	}
	if len(probe.NamespaceProofs) > 0 {
		if probe.NamespaceProofHash == "" {
			t.Fatal("expected namespace proof hash when namespace proofs exist")
		}
		for _, proof := range probe.NamespaceProofs {
			if proof.Namespace == "" {
				t.Fatal("expected namespace proof name")
			}
		}
	}
}

func TestHashNamespaceProofsStable(t *testing.T) {
	proofs := []NamespaceProof{
		{Namespace: "pid", SelfDescriptor: "pid:[1]", InitDescriptor: "pid:[2]", MatchesInit: false},
		{Namespace: "mnt", SelfDescriptor: "mnt:[3]", InitDescriptor: "mnt:[3]", MatchesInit: true},
	}
	left := hashNamespaceProofs(proofs)
	right := hashNamespaceProofs(proofs)
	if left == "" {
		t.Fatal("expected non-empty hash")
	}
	if left != right {
		t.Fatalf("expected stable hash, got %s vs %s", left, right)
	}
}

func TestMatchSeccompProfileMicrovm(t *testing.T) {
	p := MatchSeccompProfile("microvm-runtime")
	if p == nil {
		t.Fatal("expected profile for microvm")
	}
	if p.RequiredMode != 2 {
		t.Fatalf("expected mode 2, got %d", p.RequiredMode)
	}
}

func TestMatchSeccompProfileHostLocal(t *testing.T) {
	p := MatchSeccompProfile("host-local")
	if p == nil {
		t.Fatal("expected profile for host-local")
	}
	if p.RequiredMode != 0 {
		t.Fatalf("expected mode 0, got %d", p.RequiredMode)
	}
}

func TestValidateSeccompPosturePassesHostLocal(t *testing.T) {
	probe := IsolationProbe{SeccompActive: false}
	if err := ValidateSeccompPosture(probe, "host-local"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateSeccompPostureFailsInactiveContainer(t *testing.T) {
	probe := IsolationProbe{SeccompActive: false}
	if err := ValidateSeccompPosture(probe, "container-runtime"); err == nil {
		t.Fatal("expected error for inactive seccomp on container backend")
	}
}

func TestValidateSeccompPosturePassesActiveContainer(t *testing.T) {
	probe := IsolationProbe{SeccompActive: true}
	if err := ValidateSeccompPosture(probe, "container-runtime"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDescribeBackendAttestationHostLocalIsLauncherOnly(t *testing.T) {
	attestation := DescribeBackendAttestation(Profile{Backend: "host-local"}, IsolationProbe{})
	if attestation.AttestationStatus != "launcher-only" {
		t.Fatalf("expected launcher-only status, got %q", attestation.AttestationStatus)
	}
	if len(attestation.RequiredChecks) != 0 {
		t.Fatalf("expected no required checks, got %v", attestation.RequiredChecks)
	}
}

func TestDescribeBackendAttestationContainerRequiresRuntimeProof(t *testing.T) {
	attestation := DescribeBackendAttestation(Profile{Backend: "container-runtime"}, IsolationProbe{})
	if attestation.AttestationStatus != "insufficient" {
		t.Fatalf("expected insufficient status, got %q", attestation.AttestationStatus)
	}
	if len(attestation.FailureReasons) == 0 {
		t.Fatal("expected attestation failure reasons")
	}
}

func TestDescribeBackendAttestationContainerVerified(t *testing.T) {
	probe := IsolationProbe{
		PIDNamespaced:      true,
		MountNamespaced:    true,
		NetNamespaced:      true,
		SeccompActive:      true,
		CgroupFenced:       true,
		NamespaceProofHash: "sha256:test",
	}
	attestation := DescribeBackendAttestation(Profile{Backend: "container-runtime"}, probe)
	if attestation.AttestationStatus != "verified" {
		t.Fatalf("expected verified status, got %q", attestation.AttestationStatus)
	}
	if len(attestation.FailureReasons) != 0 {
		t.Fatalf("unexpected failure reasons: %v", attestation.FailureReasons)
	}
}
