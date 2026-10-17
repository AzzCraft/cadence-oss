package main

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"io"

	"github.com/AzzCraft/cadence-oss/cadence-core/internal/exactjson"
	"github.com/AzzCraft/cadence-oss/cadence-core/internal/httpinventory"
	"github.com/AzzCraft/cadence-oss/cadence-core/internal/qualification"
	"github.com/santhosh-tekuri/jsonschema/v5"
)

// These original-byte copies come from the sole protocol authors. Validation
// checks structure/exact numbers only; it is not evidence or resource authority.
//
//go:embed integration_plan.schema.json
var integrationPlanSchema []byte

//go:embed integration_receipt.schema.json
var integrationReceiptSchema []byte

//go:embed completion.schema.json
var completionSchema []byte

//go:embed approved_facts_check.schema.json
var factsCheckSchema []byte

//go:embed bundle_resolution.schema.json
var bundleResolutionSchema []byte

//go:embed context_pack.schema.json
var contextPackSchema []byte

//go:embed approved_facts_check_v2.schema.json
var factsCheckV2Schema []byte

//go:embed bundle_resolution_v2.schema.json
var bundleResolutionV2Schema []byte

//go:embed context_pack_v2.schema.json
var contextPackV2Schema []byte

func exactReferenceNumbers(value any) (any, error) {
	switch v := value.(type) {
	case json.Number:
		return exactjson.SafeInteger(v)
	case []any:
		for i, child := range v {
			checked, err := exactReferenceNumbers(child)
			if err != nil {
				return nil, err
			}
			v[i] = checked
		}
	case map[string]any:
		for name, child := range v {
			checked, err := exactReferenceNumbers(child)
			if err != nil {
				return nil, err
			}
			v[name] = checked
		}
	}
	return value, nil
}

func validateIntegrationContract(value any, identity string) (any, error) {
	if identity == "das-http-declaration/v1" || identity == "das-http-inventory/v1" {
		checked, err := exactReferenceNumbers(value)
		if err != nil {
			return nil, err
		}
		return checked, httpinventory.Validate(checked, identity)
	}
	if identity == "das-verification-plan/v1" || identity == "das-verification-evidence/v1" || identity == "das-action-decision/v1" ||
		identity == "das-analysis-task-binding/v1" || identity == "das-analysis-verification-plan/v1" ||
		identity == "das-analysis-verification-evidence/v1" || identity == "das-analysis-action-decision/v1" || identity == "das-analysis-completion/v1" ||
		identity == "das-version-verification-plan/v1" || identity == "das-version-verification-evidence/v1" || identity == "das-version-action-decision/v1" {
		// Check exact numbers before canonical conversion can round them.
		checked, err := exactReferenceNumbers(value)
		if err != nil {
			return nil, err
		}
		encoded, err := exactjson.Canonical(checked)
		if err != nil {
			return nil, err
		}
		return qualification.Validate(encoded, identity)
	}
	data, ok := map[string][]byte{
		"das-integration-plan/v1":     integrationPlanSchema,
		"das-integration-receipt/v1":  integrationReceiptSchema,
		"das-completion/v1":           completionSchema,
		"das-approved-facts-check/v1": factsCheckSchema,
		"das-bundle-resolution/v1":    bundleResolutionSchema,
		"das-context-pack/v1":         contextPackSchema,
		"das-approved-facts-check/v2": factsCheckV2Schema,
		"das-bundle-resolution/v2":    bundleResolutionV2Schema,
		"das-context-pack/v2":         contextPackV2Schema,
	}[identity]
	if !ok {
		return nil, errors.New("unsupported integration contract identity")
	}
	compiler := jsonschema.NewCompiler()
	compiler.Draft = jsonschema.Draft2020
	compiler.AssertFormat = true
	compiler.LoadURL = func(string) (io.ReadCloser, error) {
		return nil, errors.New("external integration schema loading forbidden")
	}
	const resource = "https://cadence.das.dev/embedded/integration-contract"
	if err := compiler.AddResource(resource, bytes.NewReader(data)); err != nil {
		return nil, err
	}
	schema, err := compiler.Compile(resource)
	if err != nil {
		return nil, err
	}
	checked, err := exactReferenceNumbers(value)
	if err != nil {
		return nil, err
	}
	if err = schema.Validate(checked); err != nil {
		return nil, err
	}
	object := checked.(map[string]any)
	if identity == "das-bundle-resolution/v1" || identity == "das-context-pack/v1" || identity == "das-bundle-resolution/v2" || identity == "das-context-pack/v2" {
		field := "recordDigest"
		if identity == "das-context-pack/v1" || identity == "das-context-pack/v2" {
			field = "contextPackDigest"
		}
		subject := map[string]any{}
		for name, child := range object {
			if name != field {
				subject[name] = child
			}
		}
		var digest string
		if identity == "das-context-pack/v1" || identity == "das-context-pack/v2" {
			digest, err = exactjson.DigestCatalog(subject)
		} else {
			digest, err = exactjson.Digest(subject)
			derivation := map[string]any{}
			for _, name := range []string{"contractIdentity", "scope", "standardVersion", "policyRef", "target", "resolver", "resolution", "status", "digestMethod"} {
				derivation[name] = object[name]
			}
			current := object["current"].(map[string]any)
			factsRef := object["factsRef"].(map[string]any)
			derivation["authorityDomain"] = current["authorityDomain"]
			derivation["factsRef"] = map[string]any{"factsId": factsRef["factsId"], "factsGeneration": factsRef["factsGeneration"], "approvedFactsDigest": factsRef["approvedFactsDigest"]}
			if standardRef, exists := object["standardRef"]; exists {
				derivation["standardRef"] = standardRef
			}
			stableDigest, stableErr := exactjson.Digest(derivation)
			if stableErr != nil || stableDigest != object["bundleDigest"] {
				return nil, errors.New("stable Bundle derivation digest changed")
			}
			resolution := object["resolution"].(map[string]any)
			previewSubject := map[string]any{}
			for name, child := range resolution {
				if name != "previewDigest" {
					previewSubject[name] = child
				}
			}
			previewDigest, previewErr := exactjson.Digest(previewSubject)
			if previewErr != nil || previewDigest != resolution["previewDigest"] {
				return nil, errors.New("Bundle native resolution digest changed")
			}
			policy := object["policyRef"].(map[string]any)
			if resolution["scope"] != object["scope"] || resolution["standardVersion"] != object["standardVersion"] ||
				resolution["policyDigest"] != policy["policyDigest"] || current["authorityEpoch"] != policy["authorityEpoch"] ||
				(resolution["leafMigrationComplete"] == false && object["status"] != "migration_incomplete") {
				return nil, errors.New("Bundle bindings or migration status changed")
			}
		}
		if err != nil || digest != object[field] {
			return nil, errors.New("derived Bundle or Context Pack digest changed")
		}
	}
	if identity == "das-integration-receipt/v1" && object["afterGeneration"].(int64) != object["beforeGeneration"].(int64)+1 {
		return nil, errors.New("integration receipt generation is not the actual next generation")
	}
	if identity == "das-integration-plan/v1" && object["beforeCandidateDigest"] == object["afterCandidateDigest"] {
		return nil, errors.New("integration plan does not change the target")
	}
	if identity == "das-completion/v1" {
		parent := object["parentChange"].(map[string]any)
		if parent["status"] == "closing" && parent["taskSetDigest"] == nil {
			return nil, errors.New("closing Completion lacks its frozen task set")
		}
	}
	return checked, nil
}
