package registry

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLookup(t *testing.T) {
	reg := Registry{
		RegistryID: "test-registry",
		Entries: []Entry{
			{Kind: "plugin", ID: "scanner-v1", Ref: "./plugins/scanner"},
			{Kind: "policy-pack", ID: "ui-v5", Ref: "./packs/ui-v5"},
		},
	}

	e, err := Lookup(reg, "plugin", "scanner-v1")
	if err != nil {
		t.Fatalf("Lookup failed: %v", err)
	}
	if e.Ref != "./plugins/scanner" {
		t.Fatalf("expected ref ./plugins/scanner, got %s", e.Ref)
	}

	_, err = Lookup(reg, "plugin", "nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent entry")
	}
}

func TestLookupByKind(t *testing.T) {
	reg := Registry{
		Entries: []Entry{
			{Kind: "plugin", ID: "a"},
			{Kind: "plugin", ID: "b"},
			{Kind: "policy-pack", ID: "c"},
		},
	}
	plugins := LookupByKind(reg, "plugin")
	if len(plugins) != 2 {
		t.Fatalf("expected 2 plugins, got %d", len(plugins))
	}
}

func TestValidateDetectsDuplicates(t *testing.T) {
	digest := "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	reg := Registry{
		RegistryID: "test",
		Entries: []Entry{
			{
				Kind:         "plugin",
				ID:           "dup",
				Ref:          "./plugins/dup.json",
				Version:      "1.0.0",
				Status:       "active",
				Digest:       digest,
				CompatWindow: "current",
				Trust:        &Trust{Signer: "cadence-oss-team", Allowlisted: true},
			},
			{
				Kind:         "plugin",
				ID:           "dup",
				Ref:          "./plugins/dup-v2.json",
				Version:      "1.0.0",
				Status:       "active",
				Digest:       digest,
				CompatWindow: "current",
				Trust:        &Trust{Signer: "cadence-oss-team", Allowlisted: true},
			},
		},
	}
	if err := Validate(reg); err == nil {
		t.Fatal("expected error for duplicate entries")
	}
}

func TestValidateRequiresRegistryID(t *testing.T) {
	reg := Registry{Entries: []Entry{{Kind: "plugin", ID: "ok"}}}
	if err := Validate(reg); err == nil {
		t.Fatal("expected error for missing registryId")
	}
}

func TestValidateRequiresRef(t *testing.T) {
	reg := Registry{
		RegistryID: "test",
		Entries:    []Entry{{Kind: "plugin", ID: "ok"}},
	}
	if err := Validate(reg); err == nil {
		t.Fatal("expected error for missing ref")
	}
}

func TestValidateRejectsInvalidDigest(t *testing.T) {
	reg := Registry{
		RegistryID: "test",
		Entries: []Entry{{
			Kind:         "plugin",
			ID:           "ok",
			Ref:          "./plugins/ok",
			Version:      "1.0.0",
			Status:       "active",
			Digest:       "not-a-sha",
			CompatWindow: "current",
			Trust:        &Trust{Signer: "cadence-oss-team", Allowlisted: true},
		}},
	}
	if err := Validate(reg); err == nil {
		t.Fatal("expected error for invalid digest")
	}
}

func TestValidateRequiresDeprecationMetadata(t *testing.T) {
	digest := "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	reg := Registry{
		RegistryID: "test",
		Entries: []Entry{{
			Kind:         "policyPack",
			ID:           "legacy-pack",
			Ref:          "./packs/legacy",
			Version:      "1.0.0",
			Status:       "deprecated",
			Digest:       digest,
			CompatWindow: "until 2026-06-01",
			Trust:        &Trust{Signer: "cadence-oss-team", Allowlisted: true},
		}},
	}
	if err := Validate(reg); err == nil {
		t.Fatal("expected error for deprecated entry without metadata")
	}
}

func TestValidateRejectsActiveEntryWithBoundedCompatWindow(t *testing.T) {
	reg := Registry{
		RegistryID: "test",
		Entries: []Entry{{
			Kind:         "policyPack",
			ID:           "ui-v140",
			Ref:          "./policy.yaml",
			Version:      "1.0.0",
			Status:       "active",
			Digest:       "sha256:1111111111111111111111111111111111111111111111111111111111111111",
			CompatWindow: "until 2026-06-01",
			Trust:        &Trust{Signer: "cadence-oss-team", Allowlisted: true},
		}},
	}
	if err := Validate(reg); err == nil {
		t.Fatal("expected active entry with bounded compatWindow to fail")
	}
}

func TestValidateRejectsDeprecatedEntryWithCurrentCompatWindow(t *testing.T) {
	reg := Registry{
		RegistryID: "test",
		Entries: []Entry{{
			Kind:              "runtimeProfile",
			ID:                "legacy-runtime",
			Ref:               "./runtime.json",
			Version:           "1.0.0",
			Status:            "deprecated",
			Digest:            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
			DeprecatedAt:      strPtr("2026-04-13T00:00:00Z"),
			DeprecationReason: strPtr("migrate"),
			CompatWindow:      "current",
			Trust:             &Trust{Signer: "cadence-oss-team", Allowlisted: true},
		}},
	}
	if err := Validate(reg); err == nil {
		t.Fatal("expected deprecated entry with current compatWindow to fail")
	}
}

func TestValidateRejectsDeprecatedAtOutsideCompatWindow(t *testing.T) {
	reg := Registry{
		RegistryID: "test",
		Entries: []Entry{{
			Kind:              "runtimeProfile",
			ID:                "legacy-runtime",
			Ref:               "./runtime.json",
			Version:           "1.0.0",
			Status:            "deprecated",
			Digest:            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
			DeprecatedAt:      strPtr("2026-07-01T00:00:00Z"),
			DeprecationReason: strPtr("migrate"),
			CompatWindow:      "until 2026-06-01",
			Trust:             &Trust{Signer: "cadence-oss-team", Allowlisted: true},
		}},
	}
	if err := Validate(reg); err == nil {
		t.Fatal("expected deprecatedAt outside compat window to fail")
	}
}

func TestResolveConfiguredEntryValidatesDigestAndRef(t *testing.T) {
	root := t.TempDir()
	registryPath := filepath.Join(root, "registry.json")
	targetPath := filepath.Join(root, "policy.yaml")
	if err := os.WriteFile(targetPath, []byte("id: ui-v140\n"), 0o644); err != nil {
		t.Fatalf("write target: %v", err)
	}
	digest, err := fileDigest(targetPath)
	if err != nil {
		t.Fatalf("fileDigest: %v", err)
	}

	reg := Registry{
		RegistryID: "test",
		Entries: []Entry{{
			Kind:         "policyPack",
			ID:           "ui-v140",
			Ref:          "./policy.yaml",
			Version:      "1.0.0",
			Status:       "active",
			Digest:       digest,
			CompatWindow: "current",
			Trust: &Trust{
				Signer:      "cadence-oss-team",
				Allowlisted: true,
			},
		}},
	}

	resolution, err := ResolveConfiguredEntry(root, registryPath, reg, "policyPack", "ui-v140", "policy.yaml")
	if err != nil {
		t.Fatalf("ResolveConfiguredEntry failed: %v", err)
	}
	if resolution.ResolvedRef != targetPath {
		t.Fatalf("resolved ref mismatch: got %s want %s", resolution.ResolvedRef, targetPath)
	}
}

func TestResolveConfiguredEntryWarnsOnDeprecated(t *testing.T) {
	root := t.TempDir()
	registryPath := filepath.Join(root, "registry.json")
	targetPath := filepath.Join(root, "policy.yaml")
	if err := os.WriteFile(targetPath, []byte("id: ui-v140\n"), 0o644); err != nil {
		t.Fatalf("write target: %v", err)
	}
	digest, err := fileDigest(targetPath)
	if err != nil {
		t.Fatalf("fileDigest: %v", err)
	}

	reg := Registry{
		RegistryID: "test",
		Entries: []Entry{{
			Kind:              "policyPack",
			ID:                "ui-v140",
			Ref:               "./policy.yaml",
			Version:           "1.0.0",
			Status:            "deprecated",
			Digest:            digest,
			DeprecatedAt:      strPtr("2026-04-13T00:00:00Z"),
			DeprecationReason: strPtr("use ui-v147"),
			CompatWindow:      "until 2026-06-01",
			Trust: &Trust{
				Signer:      "cadence-oss-team",
				Allowlisted: true,
			},
		}},
	}

	resolution, err := ResolveConfiguredEntry(root, registryPath, reg, "policyPack", "ui-v140", "policy.yaml")
	if err != nil {
		t.Fatalf("ResolveConfiguredEntry failed: %v", err)
	}
	if len(resolution.Warnings) != 1 {
		t.Fatalf("expected one deprecation warning, got %d", len(resolution.Warnings))
	}
}

func TestResolveByRefAtRejectsExpiredCompatWindow(t *testing.T) {
	root := t.TempDir()
	registryPath := filepath.Join(root, "registry.json")
	targetPath := filepath.Join(root, "runtime.json")
	if err := os.WriteFile(targetPath, []byte("{\"runtimeId\":\"legacy\"}\n"), 0o644); err != nil {
		t.Fatalf("write target: %v", err)
	}
	digest, err := fileDigest(targetPath)
	if err != nil {
		t.Fatalf("fileDigest: %v", err)
	}
	reg := Registry{
		RegistryID: "test",
		Entries: []Entry{{
			Kind:              "runtimeProfile",
			ID:                "legacy-runtime",
			Ref:               "./runtime.json",
			Version:           "1.0.0",
			Status:            "deprecated",
			Digest:            digest,
			DeprecatedAt:      strPtr("2026-04-13T00:00:00Z"),
			DeprecationReason: strPtr("migrate"),
			CompatWindow:      "until 2026-04-14",
			Trust:             &Trust{Signer: "cadence-oss-team", Allowlisted: true},
		}},
	}
	if _, err := ResolveByRefAt(registryPath, reg, "runtimeProfile", targetPath, time.Date(2026, 4, 15, 0, 0, 0, 0, time.UTC)); err == nil {
		t.Fatal("expected ResolveByRefAt to reject expired compatWindow")
	}
}

func TestResolveConfiguredEntryAtRejectsExpiredCompatWindow(t *testing.T) {
	root := t.TempDir()
	registryPath := filepath.Join(root, "registry.json")
	targetPath := filepath.Join(root, "sandbox.json")
	if err := os.WriteFile(targetPath, []byte("{\"sandboxId\":\"legacy\"}\n"), 0o644); err != nil {
		t.Fatalf("write target: %v", err)
	}
	digest, err := fileDigest(targetPath)
	if err != nil {
		t.Fatalf("fileDigest: %v", err)
	}
	reg := Registry{
		RegistryID: "test",
		Entries: []Entry{{
			Kind:              "sandboxProfile",
			ID:                "legacy-sandbox",
			Ref:               "./sandbox.json",
			Version:           "1.0.0",
			Status:            "deprecated",
			Digest:            digest,
			DeprecatedAt:      strPtr("2026-04-13T00:00:00Z"),
			DeprecationReason: strPtr("migrate"),
			CompatWindow:      "until 2026-04-14",
			Trust:             &Trust{Signer: "cadence-oss-team", Allowlisted: true},
		}},
	}
	if _, err := ResolveConfiguredEntryAt(root, registryPath, reg, "sandboxProfile", "legacy-sandbox", "sandbox.json", time.Date(2026, 4, 15, 0, 0, 0, 0, time.UTC)); err == nil {
		t.Fatal("expected ResolveConfiguredEntryAt to reject expired compatWindow")
	}
}

func TestResolveConfiguredEntryRejectsRemovedEntries(t *testing.T) {
	root := t.TempDir()
	registryPath := filepath.Join(root, "registry.json")
	targetPath := filepath.Join(root, "policy.yaml")
	if err := os.WriteFile(targetPath, []byte("id: ui-v140\n"), 0o644); err != nil {
		t.Fatalf("write target: %v", err)
	}

	reg := Registry{
		RegistryID: "test",
		Entries: []Entry{{
			Kind:              "policyPack",
			ID:                "ui-v140",
			Ref:               "./policy.yaml",
			Version:           "1.0.0",
			Status:            "removed",
			Digest:            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
			DeprecatedAt:      strPtr("2026-04-13T00:00:00Z"),
			DeprecationReason: strPtr("removed"),
			CompatWindow:      "until 2026-06-01",
			Trust: &Trust{
				Signer:      "cadence-oss-team",
				Allowlisted: true,
			},
		}},
	}

	if _, err := ResolveConfiguredEntry(root, registryPath, reg, "policyPack", "ui-v140", "policy.yaml"); err == nil {
		t.Fatal("expected removed registry entry to fail")
	}
}

func TestResolveConfiguredEntryRejectsNonAllowlistedTrust(t *testing.T) {
	root := t.TempDir()
	registryPath := filepath.Join(root, "registry.json")
	targetPath := filepath.Join(root, "policy.yaml")
	if err := os.WriteFile(targetPath, []byte("id: ui-v140\n"), 0o644); err != nil {
		t.Fatalf("write target: %v", err)
	}

	reg := Registry{
		RegistryID: "test",
		Entries: []Entry{{
			Kind:         "policyPack",
			ID:           "ui-v140",
			Ref:          "./policy.yaml",
			Version:      "1.0.0",
			Status:       "active",
			Digest:       "sha256:1111111111111111111111111111111111111111111111111111111111111111",
			CompatWindow: "current",
			Trust: &Trust{
				Signer:      "unknown-signer",
				Allowlisted: false,
			},
		}},
	}

	if _, err := ResolveConfiguredEntry(root, registryPath, reg, "policyPack", "ui-v140", "policy.yaml"); err == nil {
		t.Fatal("expected non-allowlisted trust to fail")
	}
}

func strPtr(value string) *string {
	return &value
}

func TestEnforceCompatWindowRejectsExpired(t *testing.T) {
	entry := Entry{
		Kind:         "plugin",
		ID:           "old-scanner",
		CompatWindow: "until 2025-01-01",
	}
	refTime, _ := time.Parse("2006-01-02", "2026-04-14")
	err := enforceCompatWindow(entry, refTime)
	if err == nil {
		t.Fatal("expected error for expired compat window")
	}
	if !containsSubstring(err.Error(), "does not cover reference time") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestEnforceCompatWindowAcceptsCurrent(t *testing.T) {
	entry := Entry{
		Kind:         "plugin",
		ID:           "active-scanner",
		CompatWindow: "current",
	}
	refTime, _ := time.Parse("2006-01-02", "2026-04-14")
	if err := enforceCompatWindow(entry, refTime); err != nil {
		t.Fatalf("current compat window should always pass: %v", err)
	}
}

func TestEnforceCompatWindowAcceptsValidRange(t *testing.T) {
	entry := Entry{
		Kind:         "plugin",
		ID:           "ranged-scanner",
		CompatWindow: "from 2026-01-01 to 2027-01-01",
	}
	refTime, _ := time.Parse("2006-01-02", "2026-06-15")
	if err := enforceCompatWindow(entry, refTime); err != nil {
		t.Fatalf("reference time within range should pass: %v", err)
	}
}

func TestEnforceCompatWindowRejectsOutOfRange(t *testing.T) {
	entry := Entry{
		Kind:         "plugin",
		ID:           "ranged-scanner",
		CompatWindow: "from 2026-01-01 to 2026-03-01",
	}
	refTime, _ := time.Parse("2006-01-02", "2026-04-14")
	if err := enforceCompatWindow(entry, refTime); err == nil {
		t.Fatal("reference time outside range should fail")
	}
}

func containsSubstring(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && containsHelper(s, sub))
}

func containsHelper(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestListEntriesFiltersByKind(t *testing.T) {
	reg := Registry{
		Entries: []Entry{
			{Kind: "plugin", ID: "a"},
			{Kind: "policy-pack", ID: "b"},
			{Kind: "plugin", ID: "c"},
		},
	}
	got := ListEntries(reg, FilterOpts{Kind: "plugin"})
	if len(got) != 2 {
		t.Fatalf("expected 2, got %d", len(got))
	}
}

func TestListEntriesNoFilter(t *testing.T) {
	reg := Registry{
		Entries: []Entry{
			{Kind: "plugin", ID: "a"},
			{Kind: "policy-pack", ID: "b"},
		},
	}
	got := ListEntries(reg, FilterOpts{})
	if len(got) != 2 {
		t.Fatalf("expected 2, got %d", len(got))
	}
}

func TestSearchByDigestFindsMatch(t *testing.T) {
	reg := Registry{
		Entries: []Entry{
			{Kind: "plugin", ID: "a", Digest: "sha256:abc123"},
			{Kind: "plugin", ID: "b", Digest: "sha256:def456"},
		},
	}
	got := SearchByDigest(reg, "sha256:abc123")
	if len(got) != 1 || got[0].ID != "a" {
		t.Fatalf("expected 1 match for ID=a, got %v", got)
	}
}

func TestSearchByDigestNoMatch(t *testing.T) {
	reg := Registry{
		Entries: []Entry{
			{Kind: "plugin", ID: "a", Digest: "sha256:abc123"},
		},
	}
	got := SearchByDigest(reg, "sha256:xxxxxx")
	if len(got) != 0 {
		t.Fatalf("expected 0 matches, got %d", len(got))
	}
}

func TestResolveByRefValidatesOnlySelectedTargetAndRejectsAmbiguity(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "runtime.json")
	os.WriteFile(path, []byte("{}"), 0600)
	digest, err := fileDigest(path)
	if err != nil {
		t.Fatal(err)
	}
	selected := Entry{Kind: "runtimeProfile", ID: "active", Ref: "runtime.json", Version: "1.0.0", Status: "active", Digest: digest, CompatWindow: "current", Trust: &Trust{Signer: "test", Allowlisted: true}}
	retired := selected
	retired.ID = "retired"
	retired.Ref = "missing.json"
	retired.Status = "removed"
	regPath := filepath.Join(root, "registry.json")
	for _, entries := range [][]Entry{{selected}, {retired, selected}, {selected, retired}} {
		if _, err := ResolveByRefAt(regPath, Registry{Entries: entries}, "runtimeProfile", path, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	for _, status := range []string{"removed", "active"} {
		bad := selected
		bad.Status = status
		if status == "active" {
			bad.Digest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
		}
		if _, err := ResolveByRefAt(regPath, Registry{Entries: []Entry{bad}}, "runtimeProfile", path, time.Now()); err == nil {
			t.Fatal("selected bad dependency accepted")
		}
	}
	alias := selected
	alias.ID = "alias"
	if _, err := ResolveByRefAt(regPath, Registry{Entries: []Entry{selected, alias}}, "runtimeProfile", path, time.Now()); err == nil {
		t.Fatal("ambiguous target accepted")
	}
}
