package waiver

import "testing"

func TestPersistedPolicyRejectsInsufficientSelfAndRepeatedApproval(t *testing.T) {
	r := New("synthetic exception", "TEST-APPROVAL", "requester-a", "approver-d", "2026-10-19T00:00:00Z", "metadata-only")
	r.Scope = "profile"
	chain := ApprovalChain{WaiverTicket: r.Ticket, Depth: 4, Entries: []ApprovalChainEntry{
		{Role: "requester", Identity: "requester-a", Timestamp: r.ReferenceTime},
		{Role: "manager", Identity: "manager-b", Timestamp: r.ReferenceTime},
		{Role: "security", Identity: "security-c", Timestamp: r.ReferenceTime},
		{Role: "approver", Identity: "approver-d", Timestamp: r.ReferenceTime},
	}}
	if err := ValidatePersistedAcceptance(r, chain); err != nil {
		t.Fatal(err)
	}
	short := chain
	short.Entries = chain.Entries[:2]
	short.Depth = 2
	if err := ValidatePersistedAcceptance(r, short); err == nil {
		t.Fatal("accepted insufficient approval")
	}
	chain.Entries[2].Identity = chain.Entries[1].Identity
	if err := ValidatePersistedAcceptance(r, chain); err == nil {
		t.Fatal("counted duplicate principal twice")
	}
	chain.Entries[3].Identity = r.Owner
	r.ApprovedBy = r.Owner
	if err := ValidatePersistedAcceptance(r, chain); err == nil {
		t.Fatal("accepted self approval")
	}
	trail := BuildAuditTrail(r, chain)
	if trail.Compliant {
		t.Fatal("trail did not expose self approval")
	}
	if err := ValidateAuditTrail(trail); err != nil {
		t.Fatalf("historical rejected trail must stay readable: %v", err)
	}
}
