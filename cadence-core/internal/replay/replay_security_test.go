package replay

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestBuildRejectsSymlinkArtifacts(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink setup requires platform privileges on Windows")
	}
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(outside, []byte("not governed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "escaped")); err != nil {
		t.Fatal(err)
	}
	if _, err := Build("test", "run.json", "result.json", root); err == nil {
		t.Fatal("expected replay inventory to reject a symlink")
	}
}

func TestVerifyBundleRejectsEscapingSnapshot(t *testing.T) {
	bundle := &Bundle{Snapshots: []Snapshot{{RelPath: "../outside", FileHash: "sha256:unused"}}}
	if err := VerifyBundle(bundle, t.TempDir()); err == nil {
		t.Fatal("expected escaping snapshot path to be rejected")
	}
}
