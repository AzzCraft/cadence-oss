package replay

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const TaskCAD003 = "CAD-003"

var excludedReplayArtifacts = map[string]struct{}{
	"replay-package.json":      {},
	"replay-bundle.json":       {},
	"evidence-bundle.json":     {},
	"manifest-signature.json":  {},
	"bundle-signature.json":    {},
	"offline-attestation.json": {},
	"report-summary.json":      {},
	"cadence-report.json":      {},
}

func shouldExcludeReplayArtifact(rel string) bool {
	rel = filepath.ToSlash(rel)
	if _, excluded := excludedReplayArtifacts[rel]; excluded {
		return true
	}
	return strings.HasSuffix(rel, ".signature.json")
}

type Bundle struct {
	SchemaVersion  string            `json:"schemaVersion"`
	ReplayID       string            `json:"replayId"`
	RunManifest    string            `json:"runManifestRef"`
	PipelineResult string            `json:"pipelineResultRef"`
	Snapshots      []Snapshot        `json:"snapshots,omitempty"`
	Inputs         map[string]string `json:"inputs,omitempty"`
	BundleHash     string            `json:"bundleHash,omitempty"`
}

type ArtifactRef struct {
	Path string `json:"path"`
	Hash string `json:"hash,omitempty"`
	URI  string `json:"uri,omitempty"`
}

type Diff struct {
	Field    string `json:"field"`
	Expected string `json:"expected,omitempty"`
	Actual   string `json:"actual,omitempty"`
	Reason   string `json:"reason"`
}

type CompareSummary struct {
	Same  bool   `json:"same"`
	Diffs []Diff `json:"diffs"`
}

type Diagnostic struct {
	Task    string `json:"task"`
	Code    string `json:"code"`
	Field   string `json:"field"`
	Message string `json:"message"`
}

// CompareReport is the CAD-003 offline replay comparison report.
type CompareReport struct {
	Task             string         `json:"task"`
	Offline          bool           `json:"offline"`
	RunManifestRef   string         `json:"runManifestRef"`
	InputCassetteRef string         `json:"inputCassetteRef,omitempty"`
	Compare          CompareSummary `json:"compare"`
	Artifacts        []ArtifactRef  `json:"artifacts"`
	Diagnostics      []Diagnostic   `json:"diagnostics"`
}

// Snapshot records a deterministic file snapshot within the replay bundle.
type Snapshot struct {
	RelPath  string `json:"relPath"`
	Mode     string `json:"mode,omitempty"`
	Size     int64  `json:"size"`
	FileHash string `json:"fileHash"`
}

func Load(path string) (Bundle, error) {
	var bundle Bundle
	data, err := os.ReadFile(path)
	if err != nil {
		return bundle, err
	}
	err = json.Unmarshal(data, &bundle)
	return bundle, err
}

// Compare builds a CAD-003 report from an original replay bundle and replayed bundle.
func Compare(original *Bundle, replayed *Bundle) CompareReport {
	report := CompareReport{
		Task:           TaskCAD003,
		Offline:        true,
		RunManifestRef: original.RunManifest,
		Compare: CompareSummary{
			Same:  true,
			Diffs: []Diff{},
		},
		Artifacts:   artifactRefs(original),
		Diagnostics: []Diagnostic{},
	}
	if original.BundleHash != replayed.BundleHash {
		report.Compare.Same = false
		report.Compare.Diffs = append(report.Compare.Diffs, Diff{
			Field:    "bundleHash",
			Expected: original.BundleHash,
			Actual:   replayed.BundleHash,
			Reason:   "replay bundle hash mismatch",
		})
	}

	originalSnaps := snapshotsByPath(original.Snapshots)
	replayedSnaps := snapshotsByPath(replayed.Snapshots)
	for path, originalSnap := range originalSnaps {
		replayedSnap, ok := replayedSnaps[path]
		if !ok {
			report.Compare.Same = false
			report.Compare.Diffs = append(report.Compare.Diffs, Diff{Field: "snapshots." + path, Reason: "missing replay artifact"})
			continue
		}
		if originalSnap.FileHash != replayedSnap.FileHash {
			report.Compare.Same = false
			report.Compare.Diffs = append(report.Compare.Diffs, Diff{
				Field:    "snapshots." + path + ".fileHash",
				Expected: originalSnap.FileHash,
				Actual:   replayedSnap.FileHash,
				Reason:   "replay artifact hash mismatch",
			})
		}
	}
	for path := range replayedSnaps {
		if _, ok := originalSnaps[path]; !ok {
			report.Compare.Same = false
			report.Compare.Diffs = append(report.Compare.Diffs, Diff{Field: "snapshots." + path, Reason: "unexpected replay artifact"})
		}
	}
	return report
}

func snapshotsByPath(snaps []Snapshot) map[string]Snapshot {
	out := make(map[string]Snapshot, len(snaps))
	for _, snap := range snaps {
		out[snap.RelPath] = snap
	}
	return out
}

func artifactRefs(bundle *Bundle) []ArtifactRef {
	refs := make([]ArtifactRef, 0, len(bundle.Snapshots))
	for _, snap := range bundle.Snapshots {
		refs = append(refs, ArtifactRef{Path: snap.RelPath, Hash: snap.FileHash})
	}
	return refs
}

// Build creates a replay bundle by capturing the current state of the output
// directory. It records file hashes for all artifacts and computes a
// deterministic bundle hash from the sorted snapshot list.
func Build(replayID, runManifestRef, pipelineResultRef, outDir string) (*Bundle, error) {
	bundle := &Bundle{
		SchemaVersion:  "1.0.0",
		ReplayID:       replayID,
		RunManifest:    runManifestRef,
		PipelineResult: pipelineResultRef,
		Inputs:         make(map[string]string),
	}

	err := filepath.Walk(outDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("replay inventory rejects non-regular artifact: %s", path)
		}
		rel, err := filepath.Rel(outDir, path)
		if err != nil {
			return err
		}
		if shouldExcludeReplayArtifact(rel) {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		h := sha256.Sum256(data)
		bundle.Snapshots = append(bundle.Snapshots, Snapshot{
			RelPath:  filepath.ToSlash(rel),
			Mode:     fmt.Sprintf("%#o", info.Mode().Perm()),
			Size:     info.Size(),
			FileHash: "sha256:" + hex.EncodeToString(h[:]),
		})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("snapshot walk: %w", err)
	}

	// Sort snapshots by path for deterministic ordering
	sort.Slice(bundle.Snapshots, func(i, j int) bool {
		return bundle.Snapshots[i].RelPath < bundle.Snapshots[j].RelPath
	})

	// Compute bundle hash from the governed tuple.
	combined := sha256.New()
	for _, s := range bundle.Snapshots {
		combined.Write([]byte(s.RelPath))
		combined.Write([]byte{0})
		combined.Write([]byte(s.Mode))
		combined.Write([]byte{0})
		combined.Write([]byte(fmt.Sprintf("%d", s.Size)))
		combined.Write([]byte{0})
		combined.Write([]byte(s.FileHash))
		combined.Write([]byte{'\n'})
	}
	bundle.BundleHash = "sha256:" + hex.EncodeToString(combined.Sum(nil))

	return bundle, nil
}

// Save writes the replay bundle to disk as canonical JSON.
func Save(path string, bundle *Bundle) error {
	data, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

// VerifyBundle checks that all recorded snapshot hashes match the actual files
// in the given output directory.
func VerifyBundle(bundle *Bundle, outDir string) error {
	for _, snap := range bundle.Snapshots {
		if snap.RelPath == "" || filepath.IsAbs(snap.RelPath) || strings.Contains(filepath.ToSlash(snap.RelPath), "../") || filepath.ToSlash(snap.RelPath) == ".." {
			return fmt.Errorf("snapshot path escapes output directory: %q", snap.RelPath)
		}
		fullPath := filepath.Join(outDir, filepath.FromSlash(snap.RelPath))
		info, err := os.Lstat(fullPath)
		if err != nil {
			return fmt.Errorf("snapshot %s: %w", snap.RelPath, err)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("snapshot %s: non-regular artifact", snap.RelPath)
		}
		data, err := os.ReadFile(fullPath)
		if err != nil {
			return fmt.Errorf("snapshot %s: %w", snap.RelPath, err)
		}
		if info, err := os.Stat(fullPath); err == nil {
			mode := fmt.Sprintf("%#o", info.Mode().Perm())
			if snap.Mode != "" && snap.Mode != mode {
				return fmt.Errorf("snapshot %s: mode mismatch (expected %s, got %s)", snap.RelPath, snap.Mode, mode)
			}
			if snap.Size != info.Size() {
				return fmt.Errorf("snapshot %s: size mismatch (expected %d, got %d)", snap.RelPath, snap.Size, info.Size())
			}
		}
		h := sha256.Sum256(data)
		actual := "sha256:" + hex.EncodeToString(h[:])
		if actual != snap.FileHash {
			return fmt.Errorf("snapshot %s: hash mismatch (expected %s, got %s)", snap.RelPath, snap.FileHash, actual)
		}
	}
	return nil
}
