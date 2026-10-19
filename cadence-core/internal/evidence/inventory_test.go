package evidence

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInventoryV2IsUnambiguousAndConfined(t *testing.T) {
	a, b := t.TempDir(), t.TempDir()
	os.WriteFile(filepath.Join(a, "a"), []byte("bc"), 0600)
	os.WriteFile(filepath.Join(b, "ab"), []byte("c"), 0600)
	x, err := BuildEvidenceBundle(a, "run-manifest.json", "pipeline-result.json")
	if err != nil {
		t.Fatal(err)
	}
	y, err := BuildEvidenceBundle(b, "run-manifest.json", "pipeline-result.json")
	if err != nil {
		t.Fatal(err)
	}
	if x.BundleHash == y.BundleHash || x.SchemaVersion != InventoryV2 {
		t.Fatal("ambiguous inventory digest")
	}
	for _, name := range []string{"../outside", "/outside", "a/../a", ".", "a\\b", "a\nb", "a", "linked"} {
		changed := *x
		changed.ArtifactPaths = []string{name, name}
		if err := VerifyBundleIntegrity(changed, a); err == nil {
			t.Fatalf("accepted path/duplicate %q", name)
		}
	}
	outside := filepath.Join(b, "ab")
	if err := os.Symlink(outside, filepath.Join(a, "linked")); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(a)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if _, err = ReadArtifact(root, "linked", MaxArtifactBytes); err == nil {
		t.Fatal("followed external symlink")
	}
	if _, err = ReadArtifact(root, "a", 1); err == nil {
		t.Fatal("ignored file byte budget")
	}
	x.ArtifactPaths = make([]string, MaxArtifacts+1)
	if err = VerifyBundleIntegrity(*x, a); err == nil {
		t.Fatal("ignored count budget")
	}
}
