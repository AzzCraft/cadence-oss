package resolver

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/AzzCraft/cadence-oss/cadence-core/internal/dsse"
	"github.com/AzzCraft/cadence-oss/cadence-core/internal/exactjson"
)

const ApprovedFactsPayloadType = "application/vnd.das.approved-facts.v1+json"

func factsRejected(code string) error { return errors.New("resolver: approved_facts_" + code) }

func factInteger(value any) (int64, error) { return exactjson.SafeInteger(value) }

// ApprovedFactsPreview checks native signatures, independent principals, current
// observation and all signed bindings under the SUPPLIED control context. A
// public caller can choose that context: it is not an installed trust boundary.
// The result remains an unapproved v3 complete-mapping preview. An installed
// protected consumer must supply its own authenticated current context and
// current Standard/content bindings; this method grants no action/adoption authority.
func ApprovedFactsPreview(input any) (map[string]any, error) {
	checked, err := CheckApprovedFacts(input)
	if err != nil {
		return nil, err
	}
	return checked["preview"].(map[string]any), nil
}

// CheckApprovedFacts also identifies the exact verified bytes and independent
// signers. Supplied current context is still not installed authority. Protected
// consumers must obtain it from their own authenticated, current control loader.
func CheckApprovedFacts(input any) (map[string]any, error) {
	if err := schemas(); err != nil {
		return nil, factsRejected("schema_unavailable")
	}
	if err := compiledApprovedFactsInput.Validate(input); err != nil {
		return nil, factsRejected("invalid_input")
	}
	request := input.(map[string]any)
	current := request["controlContext"].(map[string]any)
	if current["factsRevoked"].(bool) || current["policyRevoked"].(bool) {
		return nil, factsRejected("revoked")
	}
	stamps := map[string]time.Time{}
	for _, name := range []string{"earliest", "latest", "observedAt"} {
		value, err := time.Parse(time.RFC3339Nano, current[name].(string))
		if err != nil {
			return nil, factsRejected("invalid_time")
		}
		stamps[name] = value
	}
	staleness, err := factInteger(current["maxStalenessSeconds"])
	if err != nil || stamps["earliest"].IsZero() || stamps["latest"].Before(stamps["earliest"]) ||
		stamps["observedAt"].After(stamps["earliest"]) || stamps["observedAt"].IsZero() ||
		stamps["latest"].Sub(stamps["observedAt"]) > time.Duration(staleness)*time.Second {
		return nil, factsRejected("stale_or_uncertain_context")
	}
	threshold, err := factInteger(current["threshold"])
	if err != nil {
		return nil, factsRejected("invalid_trust")
	}
	keys := []dsse.Key{}
	for _, raw := range current["keys"].([]any) {
		entry := raw.(map[string]any)
		public, err := dsse.Decode(entry["publicKeyBase64"].(string), ed25519.PublicKeySize)
		if err != nil || len(public) != ed25519.PublicKeySize {
			return nil, factsRejected("invalid_trust")
		}
		roles := []string{}
		// Keep all keys for duplicate-key validation, but a proposing caller's
		// signature cannot count as independent approval. Extra caller signatures
		// do not invalidate a sufficient independent threshold.
		if entry["principal"] != current["callerPrincipal"] {
			for _, role := range entry["roles"].([]any) {
				roles = append(roles, role.(string))
			}
		}
		keys = append(keys, dsse.Key{Public: public, Principal: entry["principal"].(string), Issuer: entry["issuer"].(string), Roles: roles})
	}
	envelope, err := exactjson.Canonical(request["factsEnvelope"])
	if err != nil {
		return nil, factsRejected("invalid_envelope")
	}
	verified, err := dsse.Verify(envelope, ApprovedFactsPayloadType, current["issuer"].(string), "facts_approver", keys, int(threshold))
	if err != nil {
		return nil, factsRejected("signature_rejected")
	}
	value, err := exactjson.Parse(verified.Payload)
	if err != nil {
		return nil, factsRejected("invalid_payload")
	}
	if err := compiledApprovedFacts.Validate(value); err != nil {
		return nil, factsRejected("invalid_payload")
	}
	payload := value.(map[string]any)
	for _, name := range []string{"issuer", "audience", "scope", "factsId"} {
		if payload[name] != current[name] {
			return nil, factsRejected("binding_mismatch")
		}
	}
	if payload["proposedBy"] != current["callerPrincipal"] {
		return nil, factsRejected("binding_mismatch")
	}
	generation, err := factInteger(payload["factsGeneration"])
	expectedGeneration, expectedErr := factInteger(current["factsGeneration"])
	if err != nil || expectedErr != nil || generation != expectedGeneration {
		return nil, factsRejected("generation_mismatch")
	}
	policy := payload["policyRef"].(map[string]any)
	expectedPolicy := current["policyRef"].(map[string]any)
	for _, name := range []string{"policyId", "policyDigest"} {
		if policy[name] != expectedPolicy[name] {
			return nil, factsRejected("binding_mismatch")
		}
	}
	for _, name := range []string{"policyGeneration", "authorityEpoch"} {
		actual, err := factInteger(policy[name])
		expected, expectedErr := factInteger(expectedPolicy[name])
		if err != nil || expectedErr != nil || actual != expected {
			return nil, factsRejected("generation_mismatch")
		}
	}
	target := payload["target"].(map[string]any)
	expectedTarget := current["target"].(map[string]any)
	for _, name := range []string{"candidateDigest", "deploymentBaselineDigest"} {
		if target[name] != expectedTarget[name] {
			return nil, factsRejected("binding_mismatch")
		}
	}
	start, err := time.Parse(time.RFC3339Nano, payload["notBefore"].(string))
	if err != nil {
		return nil, factsRejected("invalid_time")
	}
	end, err := time.Parse(time.RFC3339Nano, payload["expiresAt"].(string))
	if err != nil || !end.After(start) || stamps["earliest"].Before(start) || !stamps["latest"].Before(end) {
		return nil, factsRejected("outside_validity")
	}
	catalog := request["catalog"].(map[string]any)
	requirements := request["requirementsCatalog"].(map[string]any)
	catalogDigest, err := exactjson.Digest(catalog)
	if err != nil || catalogDigest != supportedModuleDigest || payload["catalogDigest"] != catalogDigest || payload["standardVersion"] != catalog["standardVersion"] {
		return nil, factsRejected("unsupported_catalog")
	}
	requirementsDigest, err := exactjson.DigestCatalog(requirements)
	if err != nil || requirementsDigest != supportedRequirementsDigest || payload["requirementsCatalogDigest"] != requirementsDigest {
		return nil, factsRejected("unsupported_catalog")
	}
	// Consume only the very payload whose native bytes were verified. Do not
	// reload proposals or select facts from a different envelope after checking.
	preview, err := Preview(map[string]any{
		"contractIdentity": "das-bundle-preview-input/v3", "scope": payload["scope"], "policyDigest": policy["policyDigest"],
		"catalog": catalog, "requirementsCatalog": requirements, "facts": payload["facts"],
	})
	if err != nil {
		return nil, err
	}
	envelopeDigest, err := exactjson.Digest(request["factsEnvelope"])
	if err != nil {
		return nil, err
	}
	contextDigest, err := exactjson.Digest(current)
	if err != nil {
		return nil, err
	}
	payloadDigest, err := exactjson.Digest(payload)
	if err != nil {
		return nil, err
	}
	// Facts are a keyed/source-qualified set for resolution. Preserve exact
	// signed byte and JCS identities separately from the normalized full input.
	normalized := map[string]any{}
	for name, value := range payload {
		normalized[name] = value
	}
	facts := append([]any(nil), payload["facts"].([]any)...)
	sort.Slice(facts, func(i, j int) bool {
		a, b := facts[i].(map[string]any), facts[j].(map[string]any)
		if a["key"] != b["key"] {
			return a["key"].(string) < b["key"].(string)
		}
		return a["sourceRef"].(string) < b["sourceRef"].(string)
	})
	normalized["facts"] = facts
	approvedFactsDigest, err := exactjson.Digest(normalized)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"contractIdentity": "das-approved-facts-check/v2", "authority": false, "qualification": false,
		"preview": preview,
		"checkedRefs": map[string]any{
			"envelopeDigest": envelopeDigest, "payloadDigest": payloadDigest, "approvedFactsDigest": approvedFactsDigest,
			"payloadBytesDigest":   fmt.Sprintf("sha256:%x", sha256.Sum256(verified.Payload)),
			"controlContextDigest": contextDigest, "principals": verified.Principals, "keyFingerprints": verified.KeyFingerprints,
		},
	}, nil
}
