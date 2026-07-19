package checks

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

type FileRecord struct {
	RelPath string
	Mode    fs.FileMode
	Bytes   []byte
}

type walkOptions struct {
	includeCadenceDir   bool
	excludedDirPrefixes []string
}

// WalkFiles walks the governed repo tree and calls fn for each eligible file.
func WalkFiles(repoRoot string, fn func(relPath string, b []byte) error) error {
	return WalkFilesDetailed(repoRoot, func(record FileRecord) error {
		return fn(record.RelPath, record.Bytes)
	})
}

// WalkFilesDetailed exposes additional governed metadata such as file mode.
func WalkFilesDetailed(repoRoot string, fn func(record FileRecord) error) error {
	return walkFilesDetailed(repoRoot, walkOptions{
		includeCadenceDir: false,
	}, fn)
}

// WalkIdentityFilesDetailed walks the full governed identity surface. Unlike
// rule scanning, it includes `.cadence` inputs while still excluding transient
// runtime outputs and caches that would otherwise make the identity unstable.
func WalkIdentityFilesDetailed(repoRoot string, fn func(record FileRecord) error) error {
	return walkFilesDetailed(repoRoot, walkOptions{
		includeCadenceDir: true,
		excludedDirPrefixes: []string{
			".cadence/out",
			".cadence/tmp",
			".cadence/bin",
		},
	}, fn)
}

func walkFilesDetailed(repoRoot string, options walkOptions, fn func(record FileRecord) error) error {
	skipDirs := map[string]bool{
		".git":         true,
		"node_modules": true,
		"dist":         true,
		"build":        true,
	}

	return filepath.WalkDir(repoRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		rel := "."
		if path != repoRoot {
			relPath, relErr := filepath.Rel(repoRoot, path)
			if relErr != nil {
				return relErr
			}
			rel = filepath.ToSlash(relPath)
		}

		name := d.Name()
		if d.IsDir() {
			if skipDirs[name] {
				return filepath.SkipDir
			}
			if name == ".cadence" && !options.includeCadenceDir {
				return filepath.SkipDir
			}
			if shouldSkipRelativeDir(rel, options.excludedDirPrefixes) {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return fn(FileRecord{
			RelPath: rel,
			Mode:    info.Mode().Perm(),
			Bytes:   b,
		})
	})
}

func shouldSkipRelativeDir(rel string, prefixes []string) bool {
	if rel == "." {
		return false
	}
	for _, prefix := range prefixes {
		if rel == prefix || strings.HasPrefix(rel, prefix+"/") {
			return true
		}
	}
	return false
}
