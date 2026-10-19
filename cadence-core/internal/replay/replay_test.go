package replay

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBuildAndVerify(t *testing.T) {
	outDir := t.TempDir()

	// Create some test artifacts
	if err := os.WriteFile(filepath.Join(outDir, "manifest.json"), []byte(`{"runId": "test"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outDir, "result.json"), []byte(`{"status": "ok"}`), 0o644); err != nil {
		t.Fatal(err)
	}

	bundle, err := Build("test-replay", "manifest.json", "result.json", outDir)
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	if bundle.ReplayID != "test-replay" {
		t.Fatalf("expected replayId test-replay, got %s", bundle.ReplayID)
	}
	if len(bundle.Snapshots) != 2 {
		t.Fatalf("expected 2 snapshots, got %d", len(bundle.Snapshots))
	}
	if bundle.BundleHash[:7] != "sha256:" {
		t.Fatalf("expected sha256: prefix on bundleHash, got %s", bundle.BundleHash)
	}

	// Verify snapshots are sorted
	if bundle.Snapshots[0].RelPath >= bundle.Snapshots[1].RelPath {
		t.Fatal("snapshots should be sorted by path")
	}
	if bundle.Snapshots[0].Mode == "" || bundle.Snapshots[1].Mode == "" {
		t.Fatal("snapshots should record file mode")
	}

	// Verify the bundle
	if err := VerifyBundle(bundle, outDir); err != nil {
		t.Fatalf("VerifyBundle failed: %v", err)
	}
}

func TestVerifyBundleDetectsModeTamper(t *testing.T) {
	outDir := t.TempDir()
	target := filepath.Join(outDir, "script.sh")
	if err := os.WriteFile(target, []byte("#!/bin/sh\necho ok\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	bundle, err := Build("test", "script.sh", "script.sh", outDir)
	if err != nil {
		t.Fatal(err)
	}

	if err := os.Chmod(target, 0o644); err != nil {
		t.Fatal(err)
	}

	if err := VerifyBundle(bundle, outDir); err == nil {
		t.Fatal("expected VerifyBundle to detect mode tamper")
	}
}

func TestVerifyBundleDetectsTamper(t *testing.T) {
	outDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(outDir, "test.json"), []byte(`original`), 0o644); err != nil {
		t.Fatal(err)
	}

	bundle, err := Build("test", "test.json", "test.json", outDir)
	if err != nil {
		t.Fatal(err)
	}

	// Tamper with the file
	if err := os.WriteFile(filepath.Join(outDir, "test.json"), []byte(`tampered`), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := VerifyBundle(bundle, outDir); err == nil {
		t.Fatal("expected VerifyBundle to detect tampered file")
	}
}

func TestSaveAndLoad(t *testing.T) {
	outDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(outDir, "a.json"), []byte("content"), 0o644); err != nil {
		t.Fatal(err)
	}

	bundle, err := Build("test", "a.json", "a.json", outDir)
	if err != nil {
		t.Fatal(err)
	}

	bundlePath := filepath.Join(t.TempDir(), "replay.json")
	if err := Save(bundlePath, bundle); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	loaded, err := Load(bundlePath)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if loaded.BundleHash != bundle.BundleHash {
		t.Fatal("loaded bundle hash doesn't match saved")
	}
}

func TestBuildExcludesReplayArtifacts(t *testing.T) {
	outDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(outDir, "run-manifest.json"), []byte(`{"runId":"demo"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outDir, "replay-package.json"), []byte(`old-package`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outDir, "replay-bundle.json"), []byte(`old-bundle`), 0o644); err != nil {
		t.Fatal(err)
	}

	bundle, err := Build("test", "run-manifest.json", "run-manifest.json", outDir)
	if err != nil {
		t.Fatal(err)
	}

	if len(bundle.Snapshots) != 1 {
		t.Fatalf("expected replay artifacts to be excluded, got %d snapshots", len(bundle.Snapshots))
	}
	if bundle.Snapshots[0].RelPath != "run-manifest.json" {
		t.Fatalf("unexpected snapshot captured: %s", bundle.Snapshots[0].RelPath)
	}
}

func TestBuildExcludesMutableDerivedArtifacts(t *testing.T) {
	outDir := t.TempDir()
	for rel, content := range map[string]string{
		"RUN_ID":                           "demo\n",
		"RUN_PATH":                         outDir + "\n",
		"run-manifest.json":                `{"runId":"demo"}`,
		"evidence-bundle.json":             `{"bundleId":"stale"}`,
		"manifest-signature.json":          `{"signature":"stale"}`,
		"bundle-signature.json":            `{"signature":"stale"}`,
		"run-manifest.json.signature.json": `{"signature":"stale"}`,
	} {
		if err := os.WriteFile(filepath.Join(outDir, rel), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	bundle, err := Build("test", "run-manifest.json", "run-manifest.json", outDir)
	if err != nil {
		t.Fatal(err)
	}

	if len(bundle.Snapshots) != 1 {
		t.Fatalf("expected only primary artifacts to be captured, got %d snapshots", len(bundle.Snapshots))
	}
	if bundle.Snapshots[0].RelPath != "run-manifest.json" {
		t.Fatalf("unexpected snapshot captured: %s", bundle.Snapshots[0].RelPath)
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "nonexistent.json"))
	if err == nil {
		t.Fatal("expected error loading missing file")
	}
}

func TestBuildEmptyDir(t *testing.T) {
	dir := t.TempDir()
	bundle, err := Build("run-empty", "manifest.json", "result.json", dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if bundle.ReplayID != "run-empty" {
		t.Fatalf("expected run-empty, got %s", bundle.ReplayID)
	}
}
