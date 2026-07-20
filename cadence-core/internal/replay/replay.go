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
	if err := json.Unmarshal(data, &bundle); err != nil {
		return bundle, err
	}
	if err := ValidateBundle(&bundle); err != nil {
		return bundle, err
	}
	return bundle, nil
}

// ValidateBundle verifies the governed replay-bundle shape and its declared
// deterministic hash before a caller compares it with another result.
func ValidateBundle(bundle *Bundle) error {
	if bundle == nil {
		return fmt.Errorf("replay bundle is missing")
	}
	if bundle.SchemaVersion != "1.0.0" {
		return fmt.Errorf("unsupported replay bundle schemaVersion %q", bundle.SchemaVersion)
	}
	if strings.TrimSpace(bundle.ReplayID) == "" || strings.TrimSpace(bundle.RunManifest) == "" || strings.TrimSpace(bundle.PipelineResult) == "" {
		return fmt.Errorf("replay bundle is missing replayId, runManifestRef, or pipelineResultRef")
	}
	if len(bundle.Snapshots) == 0 {
		return fmt.Errorf("replay bundle has no snapshots")
	}
	seen := make(map[string]struct{}, len(bundle.Snapshots))
	previous := ""
	for _, snap := range bundle.Snapshots {
		rel, err := normalizedSnapshotPath(snap.RelPath)
		if err != nil {
			return err
		}
		if rel != snap.RelPath {
			return fmt.Errorf("snapshot path is not normalized: %q", snap.RelPath)
		}
		if _, exists := seen[rel]; exists {
			return fmt.Errorf("replay bundle has duplicate snapshot path %q", rel)
		}
		seen[rel] = struct{}{}
		if previous != "" && previous >= rel {
			return fmt.Errorf("replay bundle snapshots are not strictly sorted")
		}
		previous = rel
		if snap.Size < 0 || !isSHA256(snap.FileHash) {
			return fmt.Errorf("invalid replay snapshot metadata for %q", rel)
		}
	}
	if !isSHA256(bundle.BundleHash) {
		return fmt.Errorf("invalid replay bundleHash")
	}
	if actual := bundleHash(bundle.Snapshots); actual != bundle.BundleHash {
		return fmt.Errorf("replay bundleHash mismatch: expected %s, got %s", bundle.BundleHash, actual)
	}
	return nil
}

func normalizedSnapshotPath(rel string) (string, error) {
	if strings.TrimSpace(rel) == "" || filepath.IsAbs(rel) {
		return "", fmt.Errorf("snapshot path escapes output directory: %q", rel)
	}
	clean := filepath.Clean(filepath.FromSlash(rel))
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("snapshot path escapes output directory: %q", rel)
	}
	return filepath.ToSlash(clean), nil
}

func isSHA256(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+64 {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil
}

func bundleHash(snapshots []Snapshot) string {
	combined := sha256.New()
	for _, snap := range snapshots {
		combined.Write([]byte(snap.RelPath))
		combined.Write([]byte{0})
		combined.Write([]byte(snap.Mode))
		combined.Write([]byte{0})
		combined.Write([]byte(fmt.Sprintf("%d", snap.Size)))
		combined.Write([]byte{0})
		combined.Write([]byte(snap.FileHash))
		combined.Write([]byte{'\n'})
	}
	return "sha256:" + hex.EncodeToString(combined.Sum(nil))
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
	bundle.BundleHash = bundleHash(bundle.Snapshots)

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
	if err := ValidateBundle(bundle); err != nil {
		return err
	}
	root, err := filepath.EvalSymlinks(outDir)
	if err != nil {
		return fmt.Errorf("resolve output directory: %w", err)
	}
	rootInfo, err := os.Stat(root)
	if err != nil || !rootInfo.IsDir() {
		return fmt.Errorf("output directory is not a directory: %s", outDir)
	}
	for _, snap := range bundle.Snapshots {
		rel, err := normalizedSnapshotPath(snap.RelPath)
		if err != nil {
			return err
		}
		fullPath := filepath.Join(root, filepath.FromSlash(rel))
		info, err := os.Lstat(fullPath)
		if err != nil {
			return fmt.Errorf("snapshot %s: %w", snap.RelPath, err)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("snapshot %s: non-regular artifact", snap.RelPath)
		}
		resolved, err := filepath.EvalSymlinks(fullPath)
		if err != nil {
			return fmt.Errorf("snapshot %s: %w", snap.RelPath, err)
		}
		contained, err := filepath.Rel(root, resolved)
		if err != nil || contained == ".." || strings.HasPrefix(contained, ".."+string(filepath.Separator)) {
			return fmt.Errorf("snapshot path escapes output directory: %q", snap.RelPath)
		}
		data, err := os.ReadFile(resolved)
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
