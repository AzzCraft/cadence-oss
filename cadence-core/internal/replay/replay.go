package replay

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/AzzCraft/cadence-oss/cadence-core/internal/exactjson"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const TaskCAD003 = "CAD-003"

var excludedReplayArtifacts = map[string]struct{}{
	// Human-facing locators are not replay inputs; RUN_PATH varies by host.
	"RUN_ID":                   {},
	"RUN_PATH":                 {},
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
	if _, err = exactjson.Parse(data); err != nil {
		return bundle, err
	}
	if err = json.Unmarshal(data, &bundle); err != nil {
		return bundle, err
	}
	return bundle, Validate(&bundle)
}

// Validate accepts the historical 1.0.0 inventory shape, including absent modes.
// It does not reinterpret old bundle hashes as a new algorithm or reexecute a run.
func Validate(b *Bundle) error {
	if b == nil || b.SchemaVersion != "1.0.0" || strings.TrimSpace(b.ReplayID) == "" || !safePath(b.RunManifest) || !safePath(b.PipelineResult) || !digestPattern.MatchString(b.BundleHash) {
		return fmt.Errorf("invalid replay identity/version/digest")
	}
	seen := map[string]bool{}
	for _, s := range b.Snapshots {
		if !safePath(s.RelPath) || seen[s.RelPath] || s.Size < 0 || !digestPattern.MatchString(s.FileHash) || (s.Mode != "" && !modePattern.MatchString(s.Mode)) {
			return fmt.Errorf("invalid or duplicate replay snapshot: %q", s.RelPath)
		}
		seen[s.RelPath] = true
	}
	return nil
}

var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var modePattern = regexp.MustCompile(`^0[0-7]{1,4}$`)

func safePath(p string) bool {
	if p == "" || p == "." || filepath.IsAbs(p) || strings.ContainsAny(p, "\\\x00\r\n") || filepath.ToSlash(filepath.Clean(p)) != p {
		return false
	}
	for _, part := range strings.Split(p, "/") {
		if part == ".." || part == "" {
			return false
		}
	}
	return true
}

// Compare builds a CAD-003 report from an original replay bundle and replayed bundle.
func Compare(original *Bundle, replayed *Bundle) CompareReport {
	if original == nil || replayed == nil {
		return CompareReport{Task: TaskCAD003, Diagnostics: []Diagnostic{{Task: TaskCAD003, Code: "INVALID_BUNDLE", Message: "missing replay bundle"}}}
	}
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
	for _, b := range []*Bundle{original, replayed} {
		if err := Validate(b); err != nil {
			report.Compare.Same = false
			report.Diagnostics = append(report.Diagnostics, Diagnostic{Task: TaskCAD003, Code: "INVALID_BUNDLE", Message: err.Error()})
			return report
		}
	}
	for _, item := range [][3]string{{"schemaVersion", original.SchemaVersion, replayed.SchemaVersion}, {"replayId", original.ReplayID, replayed.ReplayID}, {"runManifestRef", original.RunManifest, replayed.RunManifest}, {"pipelineResultRef", original.PipelineResult, replayed.PipelineResult}} {
		if item[1] != item[2] {
			report.Compare.Same = false
			report.Compare.Diffs = append(report.Compare.Diffs, Diff{Field: item[0], Expected: item[1], Actual: item[2], Reason: "replay identity mismatch"})
		}
	}
	left, _ := json.Marshal(original.Inputs)
	right, _ := json.Marshal(replayed.Inputs)
	if string(left) != string(right) {
		report.Compare.Same = false
		report.Compare.Diffs = append(report.Compare.Diffs, Diff{Field: "inputs", Expected: string(left), Actual: string(right), Reason: "replay inputs mismatch"})
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
		if originalSnap.Mode != replayedSnap.Mode || originalSnap.Size != replayedSnap.Size {
			report.Compare.Same = false
			report.Compare.Diffs = append(report.Compare.Diffs, Diff{Field: "snapshots." + path + ".metadata", Expected: fmt.Sprintf("%s/%d", originalSnap.Mode, originalSnap.Size), Actual: fmt.Sprintf("%s/%d", replayedSnap.Mode, replayedSnap.Size), Reason: "replay metadata mismatch"})
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
	sort.Slice(report.Compare.Diffs, func(i, j int) bool {
		a, b := report.Compare.Diffs[i], report.Compare.Diffs[j]
		for _, pair := range [][2]string{{a.Field, b.Field}, {a.Reason, b.Reason}, {a.Expected, b.Expected}, {a.Actual, b.Actual}} {
			if pair[0] != pair[1] {
				return pair[0] < pair[1]
			}
		}
		return false
	})
	sort.Slice(report.Artifacts, func(i, j int) bool { return report.Artifacts[i].Path < report.Artifacts[j].Path })
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
