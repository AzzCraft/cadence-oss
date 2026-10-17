package integration

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstalledExecutableVersionAndLockIdentity(t *testing.T) {
	bin := buildBinary(t)
	work := t.TempDir()
	if err := os.WriteFile(filepath.Join(work, "VERSION"), []byte("999.0.0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	// A relative argv[0] must not make the digest refer to a caller's file.
	if err := os.WriteFile(filepath.Join(work, "cadence"), []byte("caller decoy"), 0600); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) ([]byte, error) {
		cmd := exec.Command(bin, args...)
		cmd.Args[0] = "cadence"
		cmd.Dir = work
		return cmd.CombinedOutput()
	}
	out, err := run("version", "--json")
	if err != nil {
		t.Fatalf("version: %v %s", err, out)
	}
	var identity map[string]any
	if err := json.Unmarshal(out, &identity); err != nil {
		t.Fatal(err)
	}
	version, err := os.ReadFile(filepath.Join(coreRoot(t), "..", "VERSION"))
	if err != nil {
		t.Fatal(err)
	}
	payload, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(payload)
	wantHash := "sha256:" + hex.EncodeToString(sum[:])
	if identity["releaseVersion"] != strings.TrimSpace(string(version)) || identity["binarySha256"] != wantHash {
		t.Fatalf("incorrect executable identity: %s", out)
	}
	lock := filepath.Join(work, "cadence.lock")
	if out, err := run("lock", "--out", lock); err != nil {
		t.Fatalf("lock: %v %s", err, out)
	}
	if out, err := run("lock", "--check", "--out", lock); err != nil {
		t.Fatalf("check: %v %s", err, out)
	}
	original, err := os.ReadFile(lock)
	if err != nil {
		t.Fatal(err)
	}
	for _, corrupt := range []string{
		strings.Replace(string(original), strings.TrimSpace(string(version)), "999.0.0", 1),
		strings.Replace(string(original), wantHash, "sha256:"+strings.Repeat("0", 64), 1),
	} {
		if err := os.WriteFile(lock, []byte(corrupt), 0600); err != nil {
			t.Fatal(err)
		}
		if out, err := run("lock", "--check", "--out", lock); err == nil {
			t.Fatalf("corrupt lock accepted: %s", out)
		}
	}
}

// The ordinary suite must catch opt-in configurations that silently skip,
// without requiring either runtime to be installed on the test host.
func TestExplicitRuntimeSelectionRequiresAdapter(t *testing.T) {
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"Container", "Microvm"} {
		t.Run(kind, func(t *testing.T) {
			cmd := exec.Command(binary, "-test.run=^TestVerifyUsesReal"+kind+"Runtime$", "-test.v")
			for _, entry := range os.Environ() {
				if !strings.HasPrefix(entry, "CADENCE_TEST_REAL_") && !strings.HasPrefix(entry, "CADENCE_SANDBOX_CONTAINER_ADAPTER=") && !strings.HasPrefix(entry, "CADENCE_SANDBOX_MICROVM_ADAPTER=") {
					cmd.Env = append(cmd.Env, entry)
				}
			}
			flag := "CADENCE_TEST_REAL_CONTAINER_RUNTIME"
			if kind == "Microvm" {
				flag = "CADENCE_TEST_REAL_MICROVM_RUNTIME"
			}
			cmd.Env = append(cmd.Env, flag+"=1")
			out, err := cmd.CombinedOutput()
			if err == nil || !strings.Contains(string(out), "requires CADENCE_SANDBOX_") || strings.Contains(string(out), "--- SKIP:") {
				t.Fatalf("selected runtime without adapter must fail configuration, got %v: %s", err, out)
			}
		})
	}
}
