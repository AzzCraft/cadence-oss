package checks

import (
  "io/fs"
  "os"
  "path/filepath"
  "strings"
)

// WalkFiles walks the repo tree and calls fn for each eligible file.
// It skips common directories to keep the demo fast and deterministic.
func WalkFiles(repoRoot string, fn func(relPath string, b []byte) error) error {
  skipDirs := map[string]bool{
    ".git":        true,
    ".cadence":    true,
    "node_modules": true,
    "dist":        true,
    "build":       true,
    "vendor":      true,
  }

  exts := map[string]bool{".ts": true, ".tsx": true, ".js": true, ".jsx": true, ".go": true, ".py": true, ".java": true, ".kt": true, ".json": true, ".yaml": true, ".yml": true, ".md": true}

  return filepath.WalkDir(repoRoot, func(path string, d fs.DirEntry, err error) error {
    if err != nil {
      return err
    }
    name := d.Name()
    if d.IsDir() {
      if skipDirs[name] {
        return filepath.SkipDir
      }
      return nil
    }
    ext := strings.ToLower(filepath.Ext(name))
    if !exts[ext] {
      return nil
    }
    // Ignore very large files to avoid accidental slow scans.
    info, err := d.Info()
    if err == nil && info.Size() > 2*1024*1024 {
      return nil
    }
    rel, _ := filepath.Rel(repoRoot, path)
    b, err := os.ReadFile(path)
    if err != nil {
      return err
    }
    return fn(filepath.ToSlash(rel), b)
  })
}
