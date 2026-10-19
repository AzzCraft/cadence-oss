package evidence

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBuildAndVerifyEvidenceBundle(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.json"), []byte(`{"ok":true}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.json"), []byte(`{"ok":false}`), 0o644); err != nil {
		t.Fatal(err)
	}

	bundle, err := BuildEvidenceBundle(dir, "run-1", "pipeline-1")
	if err != nil {
		t.Fatal(err)
	}
	if bundle.BundleHash == "" {
		t.Fatal("bundle hash should not be empty")
	}
	if len(bundle.ArtifactPaths) != 2 {
		t.Fatalf("expected 2 artifacts, got %d", len(bundle.ArtifactPaths))
	}

	if err := VerifyBundleIntegrity(*bundle, dir); err != nil {
		t.Fatalf("integrity check failed: %v", err)
	}
}

func TestVerifyBundleIntegrityDetectsTampering(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "x.json"), []byte(`original`), 0o644); err != nil {
		t.Fatal(err)
	}

	bundle, err := BuildEvidenceBundle(dir, "run-2", "pipeline-2")
	if err != nil {
		t.Fatal(err)
	}

	// tamper
	os.WriteFile(filepath.Join(dir, "x.json"), []byte(`tampered`), 0o644)

	if err := VerifyBundleIntegrity(*bundle, dir); err == nil {
		t.Fatal("expected integrity error after tampering")
	}
}

func TestBuildEvidenceBundleEmptyDir(t *testing.T) {
	dir := t.TempDir()
	// No run-manifest.json or pipeline-result.json
	_, err := BuildEvidenceBundle(dir, "run-manifest.json", "pipeline-result.json")
	if err == nil {
		t.Fatal("empty completed-run inventory must be rejected; only the generic chain helper retains empty-chain semantics")
	}
}

func TestVerifyBundleIntegrityRejectsTamper(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(dir+"/a.json", []byte(`{"x":1}`), 0o644)
	bundle, _ := BuildEvidenceBundle(dir, "a.json", "")
	// Tamper with path list
	bundle.ArtifactPaths = append(bundle.ArtifactPaths, "ghost.json")
	err := VerifyBundleIntegrity(*bundle, dir)
	if err == nil {
		t.Fatal("expected integrity failure after tampering artifact paths")
	}
}

func TestBuildEvidenceBundleExcludesDerivedArtifacts(t *testing.T) {
	dir := t.TempDir()
	for rel, content := range map[string]string{
		"a.json":                  `{"x":1}`,
		"evidence-bundle.json":    `{"bundleId":"stale"}`,
		"replay-package.json":     `{"bundleId":"stale"}`,
		"replay-bundle.json":      `{"bundleId":"stale"}`,
		"manifest-signature.json": `{"signature":"stale"}`,
		"bundle-signature.json":   `{"signature":"stale"}`,
		"a.json.signature.json":   `{"signature":"stale"}`,
	} {
		if err := os.WriteFile(filepath.Join(dir, rel), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	bundle, err := BuildEvidenceBundle(dir, "run-manifest.json", "pipeline-result.json")
	if err != nil {
		t.Fatal(err)
	}

	if len(bundle.ArtifactPaths) != 1 {
		t.Fatalf("expected only primary artifacts in bundle, got %d", len(bundle.ArtifactPaths))
	}
	if bundle.ArtifactPaths[0] != "a.json" {
		t.Fatalf("unexpected artifact captured: %s", bundle.ArtifactPaths[0])
	}
}
