package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"
)

const InventoryV2 = "cadence-evidence-bundle/v2"
const NativeChainProfile = "cadence-run/v1"
const MaxArtifacts = 256
const MaxArtifactBytes int64 = 32 * 1024 * 1024
const MaxTotalArtifactBytes int64 = 128 * 1024 * 1024

// RequiredRunArtifacts is the native producer/consumer delivery contract.
// Signatures, waiver, offline and hardware records remain conditional.
var RequiredRunArtifacts = []string{
	"run-manifest.json", "run-manifest.canonical.json", "pipeline-result.json",
	"pipeline-result.canonical.json", "job-envelope.json", "job-envelope.canonical.json",
	"input-identity.json", "audit-telemetry.json", "deterministic-evidence.json",
	"summary.json", "summary.md", "cadence-report.json", "report-summary.json", "step-hash-chain.json",
}

func ValidArtifactPath(name string) bool {
	if name == "" || name == "." || !utf8.ValidString(name) || !filepath.IsLocal(name) || path.Clean(name) != name || strings.ContainsAny(name, "\\:") {
		return false
	}
	for _, ch := range name {
		if unicode.IsControl(ch) {
			return false
		}
	}
	return true
}

// OpenRoot enforces confinement during the actual open, including symlink races.
// All artifact readers share this boundary; FIFOs/devices are never read.
func ReadArtifact(root *os.Root, name string, limit int64) ([]byte, error) {
	if !ValidArtifactPath(name) {
		return nil, fmt.Errorf("invalid artifact path")
	}
	info, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("artifact is not a regular file: %s", name)
	}
	f, err := openArtifact(root, name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err = f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return nil, fmt.Errorf("artifact type or size limit: %s", name)
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("artifact size limit: %s", name)
	}
	return data, nil
}

func ValidDigest(value string) bool {
	if len(value) != 71 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	_, err := hex.DecodeString(value[7:])
	return err == nil && strings.ToLower(value) == value
}

func fileHash(data []byte) string {
	h := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(h[:])
}

func ValidateRunFiles(dir string) error {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	for _, name := range RequiredRunArtifacts {
		if _, err := ReadArtifact(root, name, MaxArtifactBytes); err != nil {
			return fmt.Errorf("required artifact %s: %w", name, err)
		}
	}
	return nil
}

func ValidateDeliveryFiles(dir string) error {
	if err := ValidateRunFiles(dir); err != nil {
		return err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	for _, name := range []string{"evidence-bundle.json", "replay-package.json", "replay-bundle.json"} {
		if _, err := ReadArtifact(root, name, MaxArtifactBytes); err != nil {
			return err
		}
	}
	return nil
}
