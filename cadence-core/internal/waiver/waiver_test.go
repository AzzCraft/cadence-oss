package waiver

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestValidateRequiresFields(t *testing.T) {
	r := Record{} // empty
	if err := Validate(r); err == nil {
		t.Fatal("expected error for empty record")
	}

	r = Record{
		Reason:        "bypass",
		Ticket:        "JIRA-99",
		ReferenceTime: "2026-04-12T00:00:00Z",
		Signature:     "sig",
		// missing Owner
	}
	if err := Validate(r); err == nil {
		t.Fatal("expected error for missing owner")
	}
}

func TestValidateExpiredWaiver(t *testing.T) {
	past := time.Now().Add(-24 * time.Hour).Format(time.RFC3339)
	r := Record{
		Reason:        "expired",
		Ticket:        "JIRA-100",
		Owner:         "test-user",
		ApprovedBy:    "approver",
		ExpiresAt:     past,
		ReferenceTime: time.Now().UTC().Format(time.RFC3339),
		Signature:     "sig",
	}
	err := Validate(r)
	if err == nil {
		t.Fatal("expected error for expired waiver")
	}
}

func TestValidateGoodWaiver(t *testing.T) {
	future := time.Now().Add(30 * 24 * time.Hour).Format(time.RFC3339)
	r := Record{
		Reason:        "approved exception",
		Ticket:        "JIRA-101",
		Owner:         "test-user",
		ApprovedBy:    "approver",
		ExpiresAt:     future,
		ReferenceTime: time.Now().UTC().Format(time.RFC3339),
		Signature:     "sig",
	}
	if err := Validate(r); err != nil {
		t.Fatalf("expected valid waiver: %v", err)
	}
}

func TestWaiverFileRoundTrip(t *testing.T) {
	r := Record{
		Reason:        "round-trip test",
		Ticket:        "TEST-1",
		Owner:         "tester",
		ApprovedBy:    "approver",
		CreatedAt:     "2026-04-12T00:00:00Z",
		ReferenceTime: "2026-04-12T00:00:00Z",
		Signature:     "sig",
	}
	wf := &WaiverFile{SchemaVersion: SchemaVersion, Waivers: []Record{r}}

	path := filepath.Join(t.TempDir(), "waivers.json")
	if err := SaveFile(path, wf); err != nil {
		t.Fatalf("SaveFile failed: %v", err)
	}

	loaded, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile failed: %v", err)
	}
	if len(loaded.Waivers) != 1 || loaded.Waivers[0].Ticket != "TEST-1" {
		t.Fatal("loaded waivers don't match saved")
	}
	if err := ValidateFile(loaded); err != nil {
		t.Fatalf("loaded waiver file should validate: %v", err)
	}
}

func TestFindByTicket(t *testing.T) {
	wf := &WaiverFile{
		SchemaVersion: SchemaVersion,
		Waivers: []Record{
			{Reason: "r1", Ticket: "JIRA-1", Owner: "a", ApprovedBy: "approver", ReferenceTime: "2026-04-12T00:00:00Z", Signature: "sig"},
			{Reason: "r2", Ticket: "JIRA-2", Owner: "b", ApprovedBy: "approver", ReferenceTime: "2026-04-12T00:00:00Z", Signature: "sig"},
		},
	}
	found := FindByTicket(wf, "JIRA-2")
	if len(found) != 1 || found[0].Owner != "b" {
		t.Fatalf("expected owner b, got %v", found)
	}
	none := FindByTicket(wf, "JIRA-999")
	if len(none) != 0 {
		t.Fatal("expected no results for nonexistent ticket")
	}
}

func TestLoadFileMissing(t *testing.T) {
	_, err := LoadFile(filepath.Join(os.TempDir(), "does-not-exist.json"))
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestValidateFileRejectsMissingSchemaVersion(t *testing.T) {
	if err := ValidateFile(&WaiverFile{}); err == nil {
		t.Fatal("expected missing schemaVersion to fail")
	}
}

func TestSelectRecordByTicketRejectsDuplicateMatches(t *testing.T) {
	wf := &WaiverFile{
		SchemaVersion: SchemaVersion,
		Waivers: []Record{
			{Reason: "r1", Ticket: "OPS-1", Owner: "a", ApprovedBy: "approver", ReferenceTime: "2026-04-12T00:00:00Z", Signature: "sig"},
			{Reason: "r2", Ticket: "OPS-1", Owner: "b", ApprovedBy: "approver", ReferenceTime: "2026-04-12T00:00:00Z", Signature: "sig"},
		},
	}
	if _, err := SelectRecordByTicket(wf, "OPS-1"); err == nil {
		t.Fatal("expected duplicate ticket selection to fail")
	}
}

func TestValidateScopeAcceptsValid(t *testing.T) {
	for _, scope := range []string{"", "check", "policy-pack", "profile"} {
		r := Record{Scope: scope}
		if err := ValidateScope(r); err != nil {
			t.Fatalf("scope %q should be valid: %v", scope, err)
		}
	}
}

func TestValidateScopeRejectsInvalid(t *testing.T) {
	r := Record{Scope: "everything"}
	if err := ValidateScope(r); err == nil {
		t.Fatal("expected error for invalid scope")
	}
}

func TestValidateDurationAcceptsShort(t *testing.T) {
	r := Record{
		CreatedAt: "2025-01-01T00:00:00Z",
		ExpiresAt: "2025-06-01T00:00:00Z",
	}
	if err := ValidateDuration(r); err != nil {
		t.Fatalf("short duration should be valid: %v", err)
	}
}

func TestValidateDurationRejectsLong(t *testing.T) {
	r := Record{
		CreatedAt: "2025-01-01T00:00:00Z",
		ExpiresAt: "2027-01-01T00:00:00Z",
	}
	if err := ValidateDuration(r); err == nil {
		t.Fatal("expected error for 2-year duration")
	}
}

func TestBuildApprovalChain(t *testing.T) {
	r := Record{
		Owner:      "alice",
		ApprovedBy: "bob",
		Ticket:     "JIRA-100",
		CreatedAt:  "2025-01-01T00:00:00Z",
	}
	ac := BuildApprovalChain(r)
	if ac.Depth != 2 {
		t.Fatalf("expected depth 2, got %d", ac.Depth)
	}
	if err := ValidateApprovalChain(ac); err != nil {
		t.Fatalf("valid chain should pass: %v", err)
	}
}

func TestApprovalChainRoundTrip(t *testing.T) {
	ac := ApprovalChain{
		WaiverTicket: "JIRA-CHAIN-1",
		Entries: []ApprovalChainEntry{
			{Role: "requester", Identity: "alice", Timestamp: "2025-01-01T00:00:00Z"},
			{Role: "approver", Identity: "bob", Timestamp: "2025-01-01T00:05:00Z"},
		},
		Depth: 2,
	}
	path := filepath.Join(t.TempDir(), "approval-chain.json")
	if err := SaveApprovalChain(path, ac); err != nil {
		t.Fatalf("SaveApprovalChain failed: %v", err)
	}
	loaded, err := LoadApprovalChain(path)
	if err != nil {
		t.Fatalf("LoadApprovalChain failed: %v", err)
	}
	if loaded.WaiverTicket != ac.WaiverTicket || loaded.Depth != ac.Depth {
		t.Fatalf("loaded approval chain mismatch: %+v", loaded)
	}
	if err := ValidateApprovalChain(loaded); err != nil {
		t.Fatalf("loaded approval chain should validate: %v", err)
	}
}

func TestValidateApprovalChainRejectsSelfApproval(t *testing.T) {
	r := Record{
		Owner:      "alice",
		ApprovedBy: "alice",
		Ticket:     "JIRA-101",
		CreatedAt:  "2025-01-01T00:00:00Z",
	}
	ac := BuildApprovalChain(r)
	if err := ValidateApprovalChain(ac); err == nil {
		t.Fatal("expected error for self-approval")
	}
}

func TestValidateApprovalChainRejectsTicketMismatchSurface(t *testing.T) {
	ac := ApprovalChain{
		WaiverTicket: "",
		Entries: []ApprovalChainEntry{
			{Role: "requester", Identity: "alice", Timestamp: "2025-01-01T00:00:00Z"},
			{Role: "approver", Identity: "bob", Timestamp: "2025-01-01T00:05:00Z"},
		},
		Depth: 2,
	}
	if err := ValidateApprovalChain(ac); err == nil {
		t.Fatal("expected error for missing waiver ticket")
	}
}

func TestValidateApprovalChainForRecordRejectsMismatch(t *testing.T) {
	r := Record{
		Ticket:     "OPS-42",
		Owner:      "alice",
		ApprovedBy: "carol",
	}
	ac := ApprovalChain{
		WaiverTicket: "OPS-42",
		Entries: []ApprovalChainEntry{
			{Role: "requester", Identity: "alice", Timestamp: "2025-01-01T00:00:00Z"},
			{Role: "approver", Identity: "bob", Timestamp: "2025-01-01T00:05:00Z"},
		},
		Depth: 2,
	}
	if err := ValidateApprovalChainForRecord(r, ac); err == nil {
		t.Fatal("expected error for mismatched final approver")
	}
}

func suppressUnused() {
	_ = time.Now()
	_ = os.TempDir()
	_ = filepath.Join("")
}

func TestClassifyEscalationNone(t *testing.T) {
	r := Record{Scope: "check"}
	if ClassifyEscalation(r) != EscalationNone {
		t.Fatal("expected none")
	}
}

func TestClassifyEscalationTier1Scope(t *testing.T) {
	r := Record{Scope: "policy-pack"}
	if ClassifyEscalation(r) != EscalationTier1 {
		t.Fatal("expected tier 1")
	}
}

func TestClassifyEscalationTier2Duration(t *testing.T) {
	r := Record{
		Scope:     "check",
		CreatedAt: "2025-01-01T00:00:00Z",
		ExpiresAt: "2025-08-01T00:00:00Z", // ~212 days > 180
	}
	if ClassifyEscalation(r) != EscalationTier2 {
		t.Fatal("expected tier 2")
	}
}

func TestRequireEscalationPasses(t *testing.T) {
	r := Record{Scope: "check"}
	ac := ApprovalChain{Depth: 2, Entries: make([]ApprovalChainEntry, 2)}
	if err := RequireEscalation(r, ac); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRequireEscalationFails(t *testing.T) {
	r := Record{Scope: "profile"}
	ac := ApprovalChain{Depth: 2, Entries: make([]ApprovalChainEntry, 2)}
	if err := RequireEscalation(r, ac); err == nil {
		t.Fatal("expected escalation error for profile scope with depth 2")
	}
}

func TestBuildAuditTrailCompliant(t *testing.T) {
	r := Record{
		Reason:        "temporary waiver",
		Ticket:        "JIRA-201",
		Owner:         "alice",
		ApprovedBy:    "bob",
		CreatedAt:     "2025-01-01T00:00:00Z",
		ReferenceTime: "2025-01-01T00:00:00Z",
		ExpiresAt:     "2025-02-01T00:00:00Z",
		Signature:     "sig",
		Scope:         "check",
	}
	ac := BuildApprovalChain(r)
	trail := BuildAuditTrail(r, ac)
	if !trail.Compliant {
		t.Fatalf("expected compliant trail, got %+v", trail)
	}
	if trail.EscalationLevel != "none" {
		t.Fatalf("expected none escalation, got %s", trail.EscalationLevel)
	}
	if err := ValidateAuditTrail(trail); err != nil {
		t.Fatalf("expected valid audit trail: %v", err)
	}
}

func TestBuildAuditTrailFlagsProfileDepthGap(t *testing.T) {
	r := Record{
		Reason:        "operator break-glass",
		Ticket:        "JIRA-202",
		Owner:         "alice",
		ApprovedBy:    "bob",
		CreatedAt:     "2025-01-01T00:00:00Z",
		ReferenceTime: "2025-01-01T00:00:00Z",
		ExpiresAt:     "2025-02-01T00:00:00Z",
		Signature:     "sig",
		Scope:         "profile",
	}
	ac := BuildApprovalChain(r)
	trail := BuildAuditTrail(r, ac)
	if trail.Compliant {
		t.Fatalf("expected non-compliant trail, got %+v", trail)
	}
	if trail.EscalationLevel != "tier2" {
		t.Fatalf("expected tier2 escalation, got %s", trail.EscalationLevel)
	}
	if trail.RequiredChainDepth != 4 {
		t.Fatalf("expected required depth 4, got %d", trail.RequiredChainDepth)
	}
	found := false
	for _, decision := range trail.Decisions {
		if decision.Check == "escalation" && decision.Status == "fail" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected escalation failure in audit trail decisions")
	}
}

func TestValidateAuditTrailRejectsDepthMismatch(t *testing.T) {
	trail := AuditTrail{
		SchemaVersion:      "1.0.0",
		Ticket:             "JIRA-203",
		Scope:              "check",
		ReferenceTime:      "2025-01-01T00:00:00Z",
		EscalationLevel:    "none",
		RequiredChainDepth: 2,
		ActualChainDepth:   3,
		ApprovalChain: ApprovalChain{
			WaiverTicket: "JIRA-203",
			Depth:        2,
			Entries: []ApprovalChainEntry{
				{Role: "requester", Identity: "alice", Timestamp: "2025-01-01T00:00:00Z"},
				{Role: "approver", Identity: "bob", Timestamp: "2025-01-01T00:00:00Z"},
			},
		},
		Decisions: []AuditDecision{{Check: "record", Status: "pass"}},
	}
	if err := ValidateAuditTrail(trail); err == nil {
		t.Fatal("expected error for depth mismatch")
	}
}
