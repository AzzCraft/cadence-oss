package checks

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

func writeWalkFile(t *testing.T, root, rel string, body string, mode os.FileMode) {
	t.Helper()
	path := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
}

func collectPaths(t *testing.T, walkFn func(string, func(FileRecord) error) error, root string) []string {
	t.Helper()
	var paths []string
	if err := walkFn(root, func(record FileRecord) error {
		paths = append(paths, record.RelPath)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	sort.Strings(paths)
	return paths
}

func TestWalkFilesDetailedExcludesCadenceOutputs(t *testing.T) {
	root := t.TempDir()
	writeWalkFile(t, root, "src/main.ts", "console.log('ok')\n", 0o644)
	writeWalkFile(t, root, ".cadence/out/run-manifest.json", "{}", 0o644)
	writeWalkFile(t, root, ".cadence/tmp/cache.txt", "cache", 0o644)

	paths := collectPaths(t, WalkFilesDetailed, root)
	if len(paths) != 1 || paths[0] != "src/main.ts" {
		t.Fatalf("unexpected governed source paths: %v", paths)
	}
}

func TestWalkIdentityFilesDetailedIncludesGovernedCadenceInputsOnly(t *testing.T) {
	root := t.TempDir()
	writeWalkFile(t, root, "src/main.ts", "console.log('ok')\n", 0o644)
	writeWalkFile(t, root, ".cadence/config/runtime.env", "SAFE=1\n", 0o600)
	writeWalkFile(t, root, ".cadence/out/run-manifest.json", "{}", 0o644)
	writeWalkFile(t, root, ".cadence/bin/tool", "binary", 0o755)

	var records []FileRecord
	if err := WalkIdentityFilesDetailed(root, func(record FileRecord) error {
		records = append(records, record)
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	got := make([]string, 0, len(records))
	for _, record := range records {
		got = append(got, record.RelPath)
		if record.RelPath == ".cadence/config/runtime.env" && record.Mode != 0o600 {
			t.Fatalf("expected mode 0600 to be preserved, got %#o", record.Mode)
		}
	}
	sort.Strings(got)

	want := []string{".cadence/config/runtime.env", "src/main.ts"}
	if len(got) != len(want) {
		t.Fatalf("identity paths mismatch: got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("identity paths mismatch: got %v want %v", got, want)
		}
	}
}
