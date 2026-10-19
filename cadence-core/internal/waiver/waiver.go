package waiver

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

const SchemaVersion = "1.0.0"

type Record struct {
	Reason        string `json:"reason"`
	Ticket        string `json:"ticket"`
	Owner         string `json:"owner"`
	ApprovedBy    string `json:"approvedBy"`
	CreatedAt     string `json:"createdAt,omitempty"`
	ExpiresAt     string `json:"expiresAt,omitempty"`
	ReferenceTime string `json:"referenceTime"`
	Signature     string `json:"signature"`
	Scope         string `json:"scope,omitempty"`
}

// WaiverFile represents a persisted set of waiver records.
type WaiverFile struct {
	SchemaVersion string   `json:"schemaVersion"`
	Waivers       []Record `json:"waivers"`
}

func New(reason string, ticket string, owner string, approvedBy string, referenceTime string, signature string) Record {
	return Record{
		Reason:        reason,
		Ticket:        ticket,
		Owner:         owner,
		ApprovedBy:    approvedBy,
		CreatedAt:     referenceTime,
		ReferenceTime: referenceTime,
		Signature:     signature,
	}
}

// ValidateFile checks that a persisted waiver file container is structurally
// valid before selecting a specific record from it.
func ValidateFile(wf *WaiverFile) error {
	if wf == nil {
		return errors.New("waiver: waiver file is required")
	}
	if strings.TrimSpace(wf.SchemaVersion) != SchemaVersion {
		return fmt.Errorf("waiver: waiver file schemaVersion must be %q", SchemaVersion)
	}
	if len(wf.Waivers) == 0 {
		return errors.New("waiver: waiver file must contain at least one waiver")
	}
	return nil
}

// Validate checks that a waiver record has the required fields and is stable under replay.
func Validate(r Record) error {
	return ValidateAt(r, time.Time{})
}

// ValidateAt checks expiry against an explicit reference time.
func ValidateAt(r Record, reference time.Time) error {
	if r.Reason == "" {
		return errors.New("waiver: reason is required")
	}
	if r.Ticket == "" {
		return errors.New("waiver: ticket reference is required")
	}
	if r.Owner == "" {
		return errors.New("waiver: owner is required")
	}
	if r.ApprovedBy == "" {
		return errors.New("waiver: approvedBy is required")
	}
	if r.Signature == "" {
		return errors.New("waiver: signature is required")
	}
	if r.CreatedAt != "" {
		if _, err := time.Parse(time.RFC3339, r.CreatedAt); err != nil {
			return errors.New("waiver: invalid createdAt format")
		}
	}
	if r.ReferenceTime == "" {
		if reference.IsZero() {
			return errors.New("waiver: referenceTime is required")
		}
		r.ReferenceTime = reference.UTC().Format(time.RFC3339)
	}
	ref, err := time.Parse(time.RFC3339, r.ReferenceTime)
	if err != nil {
		return errors.New("waiver: invalid referenceTime format")
	}
	if r.ExpiresAt != "" {
		expiry, err := time.Parse(time.RFC3339, r.ExpiresAt)
		if err != nil {
			return errors.New("waiver: invalid expiresAt format")
		}
		if ref.After(expiry) {
			return errors.New("waiver: expired")
		}
	}
	return nil
}

// LoadFile loads a waiver file from disk.
func LoadFile(path string) (*WaiverFile, error) {
	var wf WaiverFile
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(data, &wf)
	return &wf, err
}

// SelectRecordByTicket returns exactly one waiver record for the given ticket.
func SelectRecordByTicket(wf *WaiverFile, ticket string) (Record, error) {
	if strings.TrimSpace(ticket) == "" {
		return Record{}, errors.New("waiver: ticket is required for waiver-file selection")
	}
	found := FindByTicket(wf, ticket)
	switch len(found) {
	case 0:
		return Record{}, fmt.Errorf("waiver: no record found for ticket %q", ticket)
	case 1:
		return found[0], nil
	default:
		return Record{}, fmt.Errorf("waiver: expected exactly one record for ticket %q, found %d", ticket, len(found))
	}
}

// SaveFile writes a waiver file to disk.
func SaveFile(path string, wf *WaiverFile) error {
	data, err := json.MarshalIndent(wf, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

// LoadApprovalChain loads a governed approval-chain document from disk.
func LoadApprovalChain(path string) (ApprovalChain, error) {
	var ac ApprovalChain
	data, err := os.ReadFile(path)
	if err != nil {
		return ac, err
	}
	err = json.Unmarshal(data, &ac)
	return ac, err
}

// SaveApprovalChain writes an approval-chain document to disk.
func SaveApprovalChain(path string, ac ApprovalChain) error {
	data, err := json.MarshalIndent(ac, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

// FindByTicket returns all waiver records matching a ticket ID.
func FindByTicket(wf *WaiverFile, ticket string) []Record {
	var found []Record
	for _, w := range wf.Waivers {
		if w.Ticket == ticket {
			found = append(found, w)
		}
	}
	return found
}

// MaxWaiverDuration is the maximum allowed duration from creation to expiry.
// Waivers lasting longer than this must be escalated.
var MaxWaiverDuration = 365 * 24 * time.Hour // 1 year

// ValidScope values constrain waiver reach.
var ValidScopes = []string{
	"check",       // single check bypass
	"policy-pack", // entire policy pack bypass
	"profile",     // profile-scoped verify bypass
}

// ValidateScope ensures the waiver scope is one of the allowed values. An empty
// scope defaults to "check" (narrowest).
func ValidateScope(r Record) error {
	scope := r.Scope
	if scope == "" {
		scope = "check"
	}
	for _, v := range ValidScopes {
		if scope == v {
			return nil
		}
	}
	return fmt.Errorf("waiver: invalid scope %q, must be one of %s", scope, strings.Join(ValidScopes, ", "))
}

// ValidateDuration checks that the waiver does not exceed MaxWaiverDuration.
// If ExpiresAt or CreatedAt is empty the check is skipped (caught by other
// validators).
func ValidateDuration(r Record) error {
	if r.CreatedAt == "" || r.ExpiresAt == "" {
		return nil
	}
	created, err := time.Parse(time.RFC3339, r.CreatedAt)
	if err != nil {
		return errors.New("waiver: invalid createdAt format")
	}
	expiry, err := time.Parse(time.RFC3339, r.ExpiresAt)
	if err != nil {
		return errors.New("waiver: invalid expiresAt format")
	}
	if expiry.Sub(created) > MaxWaiverDuration {
		return fmt.Errorf("waiver: duration %v exceeds maximum %v", expiry.Sub(created), MaxWaiverDuration)
	}
	return nil
}

// ApprovalChainEntry represents one step in a waiver approval chain.
type ApprovalChainEntry struct {
	Role      string `json:"role"`
	Identity  string `json:"identity"`
	Timestamp string `json:"timestamp"`
}

// ApprovalChain captures the full chain of approvals for a waiver, from
// requester to final approver. A minimum depth of 2 (requester + approver)
// is required for governance compliance.
type ApprovalChain struct {
	WaiverTicket string               `json:"waiverTicket"`
	Entries      []ApprovalChainEntry `json:"entries"`
	Depth        int                  `json:"depth"`
}

// AuditDecision captures one governance check applied to a waiver record.
type AuditDecision struct {
	Check   string `json:"check"`
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
}

// AuditTrail records the governance decisions applied to a waiver record.
type AuditTrail struct {
	SchemaVersion      string          `json:"schemaVersion"`
	Ticket             string          `json:"ticket"`
	Scope              string          `json:"scope"`
	ReferenceTime      string          `json:"referenceTime"`
	EscalationLevel    string          `json:"escalationLevel"`
	RequiredChainDepth int             `json:"requiredChainDepth"`
	ActualChainDepth   int             `json:"actualChainDepth"`
	Compliant          bool            `json:"compliant"`
	ApprovalChain      ApprovalChain   `json:"approvalChain"`
	Decisions          []AuditDecision `json:"decisions"`
}

// BuildApprovalChain constructs an approval chain from a waiver record.
// In the current model, the chain always has depth 2: the owner (requester)
// and the approvedBy (approver).
func BuildApprovalChain(r Record) ApprovalChain {
	chain := ApprovalChain{
		WaiverTicket: r.Ticket,
		Entries: []ApprovalChainEntry{
			{Role: "requester", Identity: r.Owner, Timestamp: r.CreatedAt},
			{Role: "approver", Identity: r.ApprovedBy, Timestamp: r.CreatedAt},
		},
	}
	chain.Depth = len(chain.Entries)
	return chain
}

// ValidateApprovalChain checks that the chain has sufficient depth and that
// requester != approver (no self-approval).
func ValidateApprovalChain(ac ApprovalChain) error {
	if strings.TrimSpace(ac.WaiverTicket) == "" {
		return errors.New("waiver: approval chain waiverTicket is required")
	}
	if ac.Depth < 2 {
		return fmt.Errorf("waiver: approval chain depth %d < minimum 2", ac.Depth)
	}
	if ac.Depth != len(ac.Entries) {
		return fmt.Errorf("waiver: depth %d does not match entry count %d", ac.Depth, len(ac.Entries))
	}
	for i, entry := range ac.Entries {
		if strings.TrimSpace(entry.Role) == "" {
			return fmt.Errorf("waiver: approval chain entry %d role is required", i)
		}
		if strings.TrimSpace(entry.Identity) == "" {
			return fmt.Errorf("waiver: approval chain entry %d identity is required", i)
		}
		if strings.TrimSpace(entry.Timestamp) == "" {
			return fmt.Errorf("waiver: approval chain entry %d timestamp is required", i)
		}
		if _, err := time.Parse(time.RFC3339, entry.Timestamp); err != nil {
			return fmt.Errorf("waiver: approval chain entry %d timestamp is invalid", i)
		}
	}
	if len(ac.Entries) >= 2 && strings.TrimSpace(ac.Entries[0].Identity) == strings.TrimSpace(ac.Entries[len(ac.Entries)-1].Identity) {
		return errors.New("waiver: self-approval is not allowed")
	}
	return nil
}

// ValidatePersistedAcceptance computes policy from current input, never from a
// supplied trail. This is metadata/policy validation, not authentication.
func ValidatePersistedAcceptance(r Record, ac ApprovalChain) error {
	trail := BuildAuditTrail(r, ac)
	if !trail.Compliant {
		return errors.New("waiver: persisted policy checks failed")
	}
	roles := [][]string{{"requester"}, {"approver"}}
	switch RequiredChainDepth(ClassifyEscalation(r)) {
	case 3:
		roles = [][]string{{"requester"}, {"manager"}, {"security", "security-lead"}}
	case 4:
		roles = [][]string{{"requester"}, {"manager"}, {"security", "security-lead"}, {"approver", "exec"}}
	}
	if len(ac.Entries) != len(roles) {
		return errors.New("waiver: unsupported persisted approval stages")
	}
	principals := map[string]bool{}
	for i, entry := range ac.Entries {
		roleOK := false
		for _, role := range roles[i] {
			roleOK = roleOK || entry.Role == role
		}
		principal := strings.TrimSpace(entry.Identity)
		if !roleOK || principals[principal] {
			return errors.New("waiver: approval stages require distinct principals and ordered roles")
		}
		principals[principal] = true
	}
	return nil
}

// ValidateApprovalChainForRecord ensures the approval chain belongs to the
// waiver record it is authorizing.
func ValidateApprovalChainForRecord(r Record, ac ApprovalChain) error {
	if strings.TrimSpace(ac.WaiverTicket) != strings.TrimSpace(r.Ticket) {
		return fmt.Errorf("waiver: approval chain ticket %q does not match waiver ticket %q", ac.WaiverTicket, r.Ticket)
	}
	if len(ac.Entries) == 0 {
		return errors.New("waiver: approval chain entries are required")
	}
	if strings.TrimSpace(ac.Entries[0].Identity) != strings.TrimSpace(r.Owner) {
		return fmt.Errorf("waiver: approval chain requester %q does not match waiver owner %q", ac.Entries[0].Identity, r.Owner)
	}
	if strings.TrimSpace(ac.Entries[len(ac.Entries)-1].Identity) != strings.TrimSpace(r.ApprovedBy) {
		return fmt.Errorf("waiver: approval chain final approver %q does not match waiver approvedBy %q", ac.Entries[len(ac.Entries)-1].Identity, r.ApprovedBy)
	}
	return nil
}

// EscalationLevel classifies waiver risk. Higher levels require deeper
// approval chains.
type EscalationLevel int

const (
	EscalationNone  EscalationLevel = 0 // default: standard dual-approval
	EscalationTier1 EscalationLevel = 1 // scope=policy-pack OR duration > 90 days
	EscalationTier2 EscalationLevel = 2 // scope=profile OR duration > 180 days
)

// EscalationLabel renders a stable machine-readable string for an escalation level.
func EscalationLabel(level EscalationLevel) string {
	switch level {
	case EscalationTier2:
		return "tier2"
	case EscalationTier1:
		return "tier1"
	default:
		return "none"
	}
}

// ClassifyEscalation returns the escalation level for a waiver based on its
// scope and duration. Higher tiers require a longer approval chain.
func ClassifyEscalation(r Record) EscalationLevel {
	level := EscalationNone

	switch r.Scope {
	case "policy-pack":
		if level < EscalationTier1 {
			level = EscalationTier1
		}
	case "profile":
		if level < EscalationTier2 {
			level = EscalationTier2
		}
	}

	if r.CreatedAt != "" && r.ExpiresAt != "" {
		created, err1 := time.Parse(time.RFC3339, r.CreatedAt)
		expiry, err2 := time.Parse(time.RFC3339, r.ExpiresAt)
		if err1 == nil && err2 == nil {
			dur := expiry.Sub(created)
			if dur > 180*24*time.Hour && level < EscalationTier2 {
				level = EscalationTier2
			} else if dur > 90*24*time.Hour && level < EscalationTier1 {
				level = EscalationTier1
			}
		}
	}
	return level
}

// RequiredChainDepth returns the minimum approval chain depth for a given
// escalation level.
func RequiredChainDepth(level EscalationLevel) int {
	switch level {
	case EscalationTier2:
		return 4 // requester + manager + security-lead + exec
	case EscalationTier1:
		return 3 // requester + manager + security-lead
	default:
		return 2 // requester + approver
	}
}

// RequireEscalation validates that a waiver's approval chain meets the depth
// required by its escalation level.
func RequireEscalation(r Record, ac ApprovalChain) error {
	level := ClassifyEscalation(r)
	required := RequiredChainDepth(level)
	if ac.Depth < required {
		return fmt.Errorf("waiver: escalation tier %d requires chain depth >= %d, got %d", level, required, ac.Depth)
	}
	return nil
}

// BuildAuditTrail evaluates a waiver record and approval chain, recording the
// full governance decision path as machine-readable evidence.
func BuildAuditTrail(r Record, ac ApprovalChain) AuditTrail {
	scope := r.Scope
	if scope == "" {
		scope = "check"
	}
	level := ClassifyEscalation(r)
	requiredDepth := RequiredChainDepth(level)
	decisions := make([]AuditDecision, 0, 5)
	compliant := true
	appendDecision := func(check string, err error) {
		if err == nil {
			decisions = append(decisions, AuditDecision{Check: check, Status: "pass"})
			return
		}
		compliant = false
		decisions = append(decisions, AuditDecision{
			Check:   check,
			Status:  "fail",
			Message: err.Error(),
		})
	}

	appendDecision("record", Validate(r))
	appendDecision("scope", ValidateScope(r))
	appendDecision("duration", ValidateDuration(r))
	appendDecision("approval-chain", ValidateApprovalChain(ac))
	appendDecision("approval-binding", ValidateApprovalChainForRecord(r, ac))
	appendDecision("escalation", RequireEscalation(r, ac))

	return AuditTrail{
		SchemaVersion:      "1.0.0",
		Ticket:             r.Ticket,
		Scope:              scope,
		ReferenceTime:      r.ReferenceTime,
		EscalationLevel:    EscalationLabel(level),
		RequiredChainDepth: requiredDepth,
		ActualChainDepth:   ac.Depth,
		Compliant:          compliant,
		ApprovalChain:      ac,
		Decisions:          decisions,
	}
}

// ValidateAuditTrail checks that a trail is internally consistent and complete.
func ValidateAuditTrail(trail AuditTrail) error {
	if trail.SchemaVersion == "" {
		return errors.New("waiver: audit trail schemaVersion is required")
	}
	if trail.Ticket == "" {
		return errors.New("waiver: audit trail ticket is required")
	}
	if trail.Scope == "" {
		return errors.New("waiver: audit trail scope is required")
	}
	if trail.ReferenceTime == "" {
		return errors.New("waiver: audit trail referenceTime is required")
	}
	if trail.EscalationLevel == "" {
		return errors.New("waiver: audit trail escalationLevel is required")
	}
	if trail.RequiredChainDepth <= 0 {
		return errors.New("waiver: audit trail requiredChainDepth must be > 0")
	}
	if trail.ActualChainDepth != trail.ApprovalChain.Depth {
		return fmt.Errorf(
			"waiver: audit trail actualChainDepth %d does not match approvalChain.depth %d",
			trail.ActualChainDepth,
			trail.ApprovalChain.Depth,
		)
	}
	if len(trail.Decisions) == 0 {
		return errors.New("waiver: audit trail must include at least one decision")
	}
	return nil
}
