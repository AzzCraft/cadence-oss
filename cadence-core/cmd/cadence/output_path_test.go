package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestSafeOutputRootRejectsSymlinkAncestor(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink setup requires platform privileges on Windows")
	}
	root := t.TempDir()
	outside := t.TempDir()
	link := filepath.Join(root, "linked-output")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	if _, err := safeOutputRoot(root, filepath.Join(link, "runs")); err == nil {
		t.Fatal("expected a symlinked output ancestor to be rejected")
	}
}

func TestWriteStableAliasRejectsRunCollision(t *testing.T) {
	root := t.TempDir()
	run := filepath.Join(root, "same")
	if err := os.Mkdir(run, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := writeStableAlias(root, run, run, "same"); err == nil {
		t.Fatal("expected alias/run directory collision to be rejected")
	}
}
