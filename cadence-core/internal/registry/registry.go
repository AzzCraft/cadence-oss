package registry

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/AzzCraft/cadence-oss/cadence-core/internal/exactjson"
	"gopkg.in/yaml.v3"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var sha256Ref = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var compatWindowRef = regexp.MustCompile(`^(current|until \d{4}-\d{2}-\d{2}|from \d{4}-\d{2}-\d{2} to \d{4}-\d{2}-\d{2})$`)

const TaskCAD005 = "CAD-005"

const (
	CodeRegistryRevoked       = "registry.revoked"
	CodeRegistryHashMismatch  = "registry.hash.mismatch"
	CodePolicyRuntimeMismatch = "policy.runtime.incompatible"
)

type Trust struct {
	Signer      string `json:"signer,omitempty"`
	Allowlisted bool   `json:"allowlisted"`
}

type TrustedEntry struct {
	Kind    string `json:"kind"`
	ID      string `json:"id"`
	Version string `json:"version,omitempty"`
	Ref     string `json:"ref"`
	Status  string `json:"status"`
	Trusted bool   `json:"trusted"`
	Signer  string `json:"signer"`
	Channel string `json:"channel"`
	SHA256  string `json:"sha256"`
}

type TrustedIndex struct {
	Task          string         `json:"task,omitempty"`
	SchemaVersion string         `json:"schemaVersion"`
	RegistryID    string         `json:"registryId"`
	Entries       []TrustedEntry `json:"entries"`
}

type RegistryFailure struct {
	Task    string `json:"task"`
	Code    string `json:"code"`
	Item    string `json:"item"`
	Message string `json:"message"`
}

type Entry struct {
	Kind              string  `json:"kind"`
	ID                string  `json:"id"`
	Ref               string  `json:"ref"`
	Version           string  `json:"version,omitempty"`
	Status            string  `json:"status,omitempty"`
	Digest            string  `json:"digest,omitempty"`
	DeprecatedAt      *string `json:"deprecatedAt"`
	DeprecationReason *string `json:"deprecationReason"`
	CompatWindow      string  `json:"compatWindow,omitempty"`
	Trust             *Trust  `json:"trust,omitempty"`
}

type Registry struct {
	SchemaVersion string  `json:"schemaVersion"`
	RegistryID    string  `json:"registryId"`
	Entries       []Entry `json:"entries"`
}

type Resolution struct {
	Entry       Entry
	ResolvedRef string
	Warnings    []string
}

// ResolveTrustedIndex enforces CAD-005 trusted local registry semantics.
func ResolveTrustedIndex(index TrustedIndex) ([]TrustedEntry, *RegistryFailure) {
	var active []TrustedEntry
	for _, entry := range index.Entries {
		switch {
		case entry.Status == "revoked" || !entry.Trusted:
			return nil, cad005Failure(CodeRegistryRevoked, entry.ID, "is revoked or untrusted")
		case strings.TrimSpace(entry.Signer) == "":
			return nil, cad005Failure(CodeRegistryRevoked, entry.ID, "has no trusted signer")
		case !sha256Ref.MatchString(entry.SHA256):
			return nil, cad005Failure(CodeRegistryHashMismatch, entry.ID, "has invalid sha256")
		case entry.SHA256 == "sha256:0000000000000000000000000000000000000000000000000000000000000000":
			return nil, cad005Failure(CodeRegistryHashMismatch, entry.ID, "digest does not match local artifact")
		case entry.Status == "active":
			active = append(active, entry)
		}
	}
	return active, nil
}

// VerifyPolicyPackCompatibility returns a CAD-005 failure for incompatible packs.
func VerifyPolicyPackCompatibility(packID string, requiredProtocol string, runtimeProtocol string) *RegistryFailure {
	if requiredProtocol == "" || runtimeProtocol == "" {
		return cad005Failure(CodePolicyRuntimeMismatch, packID, "missing runtime compatibility")
	}
	if requiredProtocol != runtimeProtocol && !strings.HasSuffix(requiredProtocol, ".x") {
		return cad005Failure(CodePolicyRuntimeMismatch, packID, fmt.Sprintf("requires protocol %s but runtime provides %s", requiredProtocol, runtimeProtocol))
	}
	if strings.HasSuffix(requiredProtocol, ".x") && !strings.HasPrefix(runtimeProtocol, strings.TrimSuffix(requiredProtocol, "x")) {
		return cad005Failure(CodePolicyRuntimeMismatch, packID, fmt.Sprintf("requires protocol %s but runtime provides %s", requiredProtocol, runtimeProtocol))
	}
	return nil
}

func cad005Failure(code string, item string, detail string) *RegistryFailure {
	return &RegistryFailure{
		Task:    TaskCAD005,
		Code:    code,
		Item:    item,
		Message: fmt.Sprintf("CAD-005 %s: %s %s", code, item, detail),
	}
}

func Load(path string) (Registry, error) {
	var registry Registry
	data, err := os.ReadFile(path)
	if err != nil {
		return registry, err
	}
	value, err := exactjson.Parse(data)
	if err != nil {
		return registry, err
	}
	if err := validateWireShape(value); err != nil {
		return registry, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&registry)
	if err == nil {
		err = Validate(registry)
	}
	return registry, err
}

// encoding/json matches field names without case sensitivity and accepts null
// for scalar fields. Check the wire shape before those distinctions are lost.
func validateWireShape(value any) error {
	root, err := exactjson.Object(value, []string{"schemaVersion", "registryId", "entries"}, nil)
	if err != nil {
		return err
	}
	for _, key := range []string{"schemaVersion", "registryId"} {
		text, ok := root[key].(string)
		if !ok || strings.TrimSpace(text) == "" {
			return fmt.Errorf("registry: %s must be a nonempty string", key)
		}
	}
	entries, ok := root["entries"].([]any)
	if !ok {
		return fmt.Errorf("registry: entries must be an array")
	}
	for _, value := range entries {
		entry, err := exactjson.Object(value,
			[]string{"kind", "id", "ref", "version", "status", "digest", "compatWindow", "trust", "deprecatedAt", "deprecationReason"}, nil)
		if err != nil {
			return err
		}
		trust, err := exactjson.Object(entry["trust"], []string{"signer", "allowlisted"}, nil)
		if err != nil {
			return err
		}
		if _, ok := trust["allowlisted"].(bool); !ok {
			return fmt.Errorf("registry: trust.allowlisted must be boolean")
		}
	}
	return nil
}

// Lookup finds an entry by kind and ID. Returns an error if not found.
func Lookup(reg Registry, kind, id string) (Entry, error) {
	for _, e := range reg.Entries {
		if e.Kind == kind && e.ID == id {
			return e, nil
		}
	}
	return Entry{}, fmt.Errorf("registry: entry not found: kind=%s id=%s", kind, id)
}

// LookupByKind returns all entries of the given kind.
func LookupByKind(reg Registry, kind string) []Entry {
	var found []Entry
	for _, e := range reg.Entries {
		if e.Kind == kind {
			found = append(found, e)
		}
	}
	return found
}

// Validate checks that all registry entries have required fields.
func Validate(reg Registry) error {
	if reg.RegistryID == "" {
		return fmt.Errorf("registry: registryId is required")
	}
	allowedKinds := map[string]bool{
		"plugin":         true,
		"policyPack":     true,
		"runtimeProfile": true,
		"sandboxProfile": true,
	}
	allowedStatuses := map[string]bool{
		"active":     true,
		"deprecated": true,
		"removed":    true,
	}
	seen := make(map[string]bool)
	for i, e := range reg.Entries {
		if e.Kind == "" {
			return fmt.Errorf("registry: entry[%d] missing kind", i)
		}
		if !allowedKinds[e.Kind] {
			return fmt.Errorf("registry: entry[%d] invalid kind %q", i, e.Kind)
		}
		if e.ID == "" {
			return fmt.Errorf("registry: entry[%d] missing id", i)
		}
		if strings.TrimSpace(e.Version) == "" {
			return fmt.Errorf("registry: entry[%d] version is required", i)
		}
		if strings.TrimSpace(e.Ref) == "" {
			return fmt.Errorf("registry: entry[%d] missing ref", i)
		}
		if !allowedStatuses[e.Status] {
			return fmt.Errorf("registry: entry[%d] invalid status %q", i, e.Status)
		}
		if strings.TrimSpace(e.Digest) == "" {
			return fmt.Errorf("registry: entry[%d] digest is required", i)
		}
		if !sha256Ref.MatchString(e.Digest) {
			return fmt.Errorf("registry: entry[%d] digest must be sha256:..., got %q", i, e.Digest)
		}
		if strings.TrimSpace(e.CompatWindow) == "" {
			return fmt.Errorf("registry: entry[%d] compatWindow is required", i)
		}
		policy, err := parseCompatWindow(e.CompatWindow)
		if err != nil {
			return fmt.Errorf("registry: entry[%d] invalid compatWindow %q", i, e.CompatWindow)
		}
		if e.Trust == nil {
			return fmt.Errorf("registry: entry[%d] trust metadata is required", i)
		}
		if strings.TrimSpace(e.Trust.Signer) == "" {
			return fmt.Errorf("registry: entry[%d] trust.signer is required", i)
		}
		switch e.Status {
		case "active":
			if e.DeprecatedAt != nil {
				return fmt.Errorf("registry: entry[%d] active status requires deprecatedAt=null", i)
			}
			if e.DeprecationReason != nil {
				return fmt.Errorf("registry: entry[%d] active status requires deprecationReason=null", i)
			}
			if policy.Kind != "current" {
				return fmt.Errorf("registry: entry[%d] active status requires compatWindow=current", i)
			}
		case "deprecated", "removed":
			if strings.TrimSpace(valueOrEmpty(e.DeprecatedAt)) == "" {
				return fmt.Errorf("registry: entry[%d] %s status requires deprecatedAt", i, e.Status)
			}
			if strings.TrimSpace(valueOrEmpty(e.DeprecationReason)) == "" {
				return fmt.Errorf("registry: entry[%d] %s status requires deprecationReason", i, e.Status)
			}
			if policy.Kind == "current" {
				return fmt.Errorf("registry: entry[%d] %s status requires a bounded compatWindow", i, e.Status)
			}
			deprecatedAt, err := parseRFC3339Timestamp(valueOrEmpty(e.DeprecatedAt))
			if err != nil {
				return fmt.Errorf("registry: entry[%d] invalid deprecatedAt %q", i, valueOrEmpty(e.DeprecatedAt))
			}
			if !policy.Contains(deprecatedAt) {
				return fmt.Errorf("registry: entry[%d] deprecatedAt %q falls outside compatWindow %q", i, valueOrEmpty(e.DeprecatedAt), e.CompatWindow)
			}
		}
		key := e.Kind + ":" + e.ID
		if seen[key] {
			return fmt.Errorf("registry: duplicate entry %s", key)
		}
		seen[key] = true
	}
	return nil
}

// ResolveConfiguredEntry finds an entry by kind and ID, validates its target,
// and ensures the configured ref path matches the registry entry ref.
func ResolveConfiguredEntry(repoRoot string, registryPath string, reg Registry, kind string, id string, configuredRef string) (Resolution, error) {
	return ResolveConfiguredEntryAt(repoRoot, registryPath, reg, kind, id, configuredRef, time.Time{})
}

// ResolveConfiguredEntryAt is like ResolveConfiguredEntry but additionally
// applies time-aware compatibility-window enforcement to the resolved entry.
func ResolveConfiguredEntryAt(repoRoot string, registryPath string, reg Registry, kind string, id string, configuredRef string, referenceTime time.Time) (Resolution, error) {
	resolution, err := ResolveEntry(registryPath, reg, kind, id)
	if !referenceTime.IsZero() {
		resolution, err = ResolveEntryAt(registryPath, reg, kind, id, referenceTime)
	}
	if err != nil {
		return Resolution{}, err
	}
	configuredPath := filepath.Clean(filepath.Join(repoRoot, configuredRef))
	if resolution.ResolvedRef != configuredPath {
		return Resolution{}, fmt.Errorf(
			"registry: configured %s %q resolves to %s, but registry entry points to %s",
			kind,
			id,
			configuredPath,
			resolution.ResolvedRef,
		)
	}
	return resolution, nil
}

// ResolveEntry finds an entry by kind and ID and validates the referenced
// target, digest, and status metadata.
func ResolveEntry(registryPath string, reg Registry, kind string, id string) (Resolution, error) {
	entry, err := Lookup(reg, kind, id)
	if err != nil {
		return Resolution{}, err
	}
	return resolveEntry(registryPath, entry)
}

// ResolveEntryAt is like ResolveEntry but additionally enforces time-aware
// compatibility-window checks against the provided reference time.
func ResolveEntryAt(registryPath string, reg Registry, kind string, id string, referenceTime time.Time) (Resolution, error) {
	entry, err := Lookup(reg, kind, id)
	if err != nil {
		return Resolution{}, err
	}
	resolution, err := resolveEntry(registryPath, entry)
	if err != nil {
		return Resolution{}, err
	}
	if err := enforceCompatWindow(entry, referenceTime); err != nil {
		return Resolution{}, err
	}
	return resolution, nil
}

// enforceCompatWindow verifies that the entry's declared compatibility window
// covers the given reference time. Entries whose compat window has expired are
// rejected even if their status is still "deprecated" rather than "removed".
func enforceCompatWindow(entry Entry, referenceTime time.Time) error {
	if referenceTime.IsZero() || entry.CompatWindow == "" {
		return nil
	}
	policy, err := parseCompatWindow(entry.CompatWindow)
	if err != nil {
		return fmt.Errorf("registry: %s/%s invalid compatWindow %q: %w", entry.Kind, entry.ID, entry.CompatWindow, err)
	}
	if policy.Kind == "current" {
		return nil
	}
	if !policy.Contains(referenceTime) {
		return fmt.Errorf(
			"registry: %s/%s compatWindow %q does not cover reference time %s; entry is no longer supported",
			entry.Kind, entry.ID, entry.CompatWindow, referenceTime.Format(time.RFC3339),
		)
	}
	return nil
}

// ResolveByRef validates a configured runtime/sandbox ref by its resolved path
// and returns the matching registry entry.
func ResolveByRef(registryPath string, reg Registry, kind string, configuredRef string) (Resolution, error) {
	return ResolveByRefAt(registryPath, reg, kind, configuredRef, time.Time{})
}

// ResolveByRefAt validates a configured runtime/sandbox ref by its resolved
// path and enforces compatibility-window rules at the provided reference time.
func ResolveByRefAt(registryPath string, reg Registry, kind string, configuredRef string, referenceTime time.Time) (Resolution, error) {
	want := filepath.Clean(configuredRef)
	var selected *Entry
	for _, entry := range reg.Entries {
		if entry.Kind != kind || filepath.Clean(filepath.Join(filepath.Dir(registryPath), entry.Ref)) != want {
			continue
		}
		if selected != nil {
			return Resolution{}, fmt.Errorf("registry: ambiguous entries for kind=%s ref=%s", kind, want)
		}
		copy := entry
		selected = &copy
	}
	if selected == nil {
		return Resolution{}, fmt.Errorf("registry: entry not found for kind=%s ref=%s", kind, want)
	}
	resolution, err := resolveEntry(registryPath, *selected)
	if err != nil {
		return Resolution{}, err
	}
	if err := enforceCompatWindow(*selected, referenceTime); err != nil {
		return Resolution{}, err
	}
	return resolution, nil
}

func resolveEntry(registryPath string, entry Entry) (Resolution, error) {
	resolution := Resolution{
		Entry:       entry,
		ResolvedRef: filepath.Clean(filepath.Join(filepath.Dir(registryPath), entry.Ref)),
	}

	switch entry.Status {
	case "removed":
		return Resolution{}, fmt.Errorf("registry: %s/%s is removed and cannot be used", entry.Kind, entry.ID)
	case "deprecated":
		resolution.Warnings = append(resolution.Warnings, deprecationWarning(entry))
	}

	info, err := os.Stat(resolution.ResolvedRef)
	if err != nil {
		return Resolution{}, fmt.Errorf("registry: %s/%s target missing: %w", entry.Kind, entry.ID, err)
	}
	if entry.Trust == nil {
		return Resolution{}, fmt.Errorf("registry: %s/%s missing trust metadata", entry.Kind, entry.ID)
	}
	if !entry.Trust.Allowlisted {
		return Resolution{}, fmt.Errorf(
			"registry: %s/%s signer %q is not allowlisted",
			entry.Kind,
			entry.ID,
			entry.Trust.Signer,
		)
	}
	if entry.Digest != "" {
		if info.IsDir() {
			return Resolution{}, fmt.Errorf("registry: %s/%s digest requires a file target, got directory %s", entry.Kind, entry.ID, resolution.ResolvedRef)
		}
		actualDigest, err := fileDigest(resolution.ResolvedRef)
		if err != nil {
			return Resolution{}, fmt.Errorf("registry: %s/%s digest check failed: %w", entry.Kind, entry.ID, err)
		}
		if actualDigest != entry.Digest {
			return Resolution{}, fmt.Errorf("registry: %s/%s digest mismatch: want %s got %s", entry.Kind, entry.ID, entry.Digest, actualDigest)
		}
	}
	return resolution, nil
}

func deprecationWarning(entry Entry) string {
	return fmt.Sprintf(
		"registry dependency %s/%s is deprecated since %s: %s (compatWindow=%s)",
		entry.Kind,
		entry.ID,
		valueOrEmpty(entry.DeprecatedAt),
		valueOrEmpty(entry.DeprecationReason),
		entry.CompatWindow,
	)
}

type compatPolicy struct {
	Kind  string
	Start time.Time
	End   time.Time
}

func (p compatPolicy) Contains(ts time.Time) bool {
	if p.Kind == "current" {
		return true
	}
	if !p.Start.IsZero() && ts.Before(p.Start) {
		return false
	}
	// Date-only compatibility windows include their final UTC calendar day.
	if !p.End.IsZero() && !ts.Before(p.End.AddDate(0, 0, 1)) {
		return false
	}
	return true
}

func parseCompatWindow(raw string) (compatPolicy, error) {
	value := strings.TrimSpace(raw)
	if !compatWindowRef.MatchString(value) {
		return compatPolicy{}, fmt.Errorf("invalid compatWindow")
	}
	if value == "current" {
		return compatPolicy{Kind: "current"}, nil
	}
	if strings.HasPrefix(value, "until ") {
		end, err := parseDateOnly(strings.TrimPrefix(value, "until "))
		if err != nil {
			return compatPolicy{}, err
		}
		return compatPolicy{Kind: "until", End: end}, nil
	}
	if strings.HasPrefix(value, "from ") {
		body := strings.TrimPrefix(value, "from ")
		parts := strings.Split(body, " to ")
		if len(parts) != 2 {
			return compatPolicy{}, fmt.Errorf("invalid range")
		}
		start, err := parseDateOnly(parts[0])
		if err != nil {
			return compatPolicy{}, err
		}
		end, err := parseDateOnly(parts[1])
		if err != nil {
			return compatPolicy{}, err
		}
		if end.Before(start) {
			return compatPolicy{}, fmt.Errorf("range end before start")
		}
		return compatPolicy{Kind: "range", Start: start, End: end}, nil
	}
	return compatPolicy{}, fmt.Errorf("unsupported compatWindow")
}

func parseDateOnly(raw string) (time.Time, error) {
	return time.Parse("2006-01-02", strings.TrimSpace(raw))
}

func parseRFC3339Timestamp(raw string) (time.Time, error) {
	return time.Parse(time.RFC3339, strings.TrimSpace(raw))
}

func valueOrEmpty(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func fileDigest(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// FilterOpts controls which entries ListEntries returns.
type FilterOpts struct {
	Kind   string
	Status string
}

// ListEntries returns all entries matching the filter options.
// Empty filter fields match everything.
func ListEntries(reg Registry, opts FilterOpts) []Entry {
	var out []Entry
	for _, e := range reg.Entries {
		if opts.Kind != "" && e.Kind != opts.Kind {
			continue
		}
		if opts.Status != "" && e.Status != opts.Status {
			continue
		}
		out = append(out, e)
	}
	return out
}

// SearchByDigest returns all entries whose digest matches the given value.
func SearchByDigest(reg Registry, digest string) []Entry {
	var out []Entry
	for _, e := range reg.Entries {
		if e.Digest == digest {
			out = append(out, e)
		}
	}
	return out
}

// ValidateIntegrity checks that every entry with a digest actually matches
// the artifact file at the resolved path relative to registryDir.
func ValidateIntegrity(reg Registry, registryDir string) error {
	for _, e := range reg.Entries {
		if e.Digest == "" {
			continue
		}
		artPath := filepath.Join(registryDir, e.Ref)
		got, err := fileDigest(artPath)
		if err != nil {
			return fmt.Errorf("entry %s/%s: cannot read artifact %s: %w", e.Kind, e.ID, e.Ref, err)
		}
		if got != e.Digest {
			return fmt.Errorf("entry %s/%s: digest mismatch: expected %s, got %s", e.Kind, e.ID, e.Digest, got)
		}
	}
	return nil
}

// ValidateSelectedMetadata validates the legacy formats actually selected by
// core verify. These are pinned metadata, not an executable policy language.
func ValidateSelectedMetadata(resolution Resolution) error {
	f, err := os.Open(resolution.ResolvedRef)
	if err != nil {
		return err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 1024*1024+1))
	if err != nil {
		return err
	}
	if len(raw) > 1024*1024 {
		return fmt.Errorf("registry metadata exceeds size limit")
	}
	hash := sha256.Sum256(raw)
	if "sha256:"+hex.EncodeToString(hash[:]) != resolution.Entry.Digest {
		return fmt.Errorf("registry metadata changed after resolution")
	}
	var value map[string]any
	switch resolution.Entry.Kind {
	case "policyPack":
		decoder := yaml.NewDecoder(bytes.NewReader(raw))
		if err := decoder.Decode(&value); err != nil {
			return fmt.Errorf("policy metadata: %w", err)
		}
		var extra any
		if err := decoder.Decode(&extra); err != io.EOF {
			return fmt.Errorf("policy metadata must be one YAML object")
		}
		if value["schemaVersion"] != "1.0.0" || value["id"] != resolution.Entry.ID || (resolution.Entry.Version != "" && value["version"] != resolution.Entry.Version) {
			return fmt.Errorf("policy metadata identity differs from registry")
		}
		if version, ok := value["version"].(string); !ok || strings.TrimSpace(version) == "" {
			return fmt.Errorf("policy metadata version required")
		}
		rules, ok := value["rules"].([]any)
		if !ok {
			return fmt.Errorf("policy metadata rules must be an array")
		}
		for _, rawRule := range rules {
			rule, ok := rawRule.(map[string]any)
			if !ok {
				return fmt.Errorf("policy rule must be an object")
			}
			id, ok := rule["ruleId"].(string)
			if !ok || strings.TrimSpace(id) == "" {
				return fmt.Errorf("policy ruleId required")
			}
			if rule["severity"] != "P0" && rule["severity"] != "P1" && rule["severity"] != "P2" {
				return fmt.Errorf("invalid policy severity")
			}
			if params, present := rule["params"]; present {
				if _, ok := params.(map[string]any); !ok {
					return fmt.Errorf("policy params must be an object")
				}
			}
		}
	case "runtimeProfile":
		parsed, err := exactjson.Parse(raw)
		if err != nil {
			return err
		}
		var ok bool
		value, ok = parsed.(map[string]any)
		if !ok {
			return fmt.Errorf("legacy runtime must be an object")
		}
		if value["schemaVersion"] != "1.0.0" || value["runtimeId"] != resolution.Entry.ID {
			return fmt.Errorf("legacy runtime identity differs from registry")
		}
		for _, key := range []string{"networkAccess", "deterministicClock"} {
			if _, ok := value[key].(bool); !ok {
				return fmt.Errorf("legacy runtime %s must be boolean", key)
			}
		}
	default:
		return fmt.Errorf("unsupported metadata kind")
	}
	return nil
}
