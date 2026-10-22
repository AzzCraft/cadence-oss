// Package resolver owns DAS three-valued module resolution. Preview does not
// approve facts or confer protected authority; approved execution is a separate
// boundary and remains disabled until its evidence and deployment gates close.
package resolver

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"sort"
	"sync"

	"github.com/AzzCraft/cadence-oss/cadence-core/internal/exactjson"
	"github.com/santhosh-tekuri/jsonschema/v5"
)

//go:embed module_catalog.schema.json
var catalogSchema []byte

//go:embed preview_input.schema.json
var inputSchema []byte

//go:embed preview_input_v2.schema.json
var inputV2Schema []byte

//go:embed preview_input_v3.schema.json
var inputV3Schema []byte

//go:embed requirement_catalog.schema.json
var requirementSchema []byte

//go:embed requirement_catalog.json
var requirementCatalog []byte

//go:embed testdata/module_catalog.json
var supportedModuleCatalog []byte

//go:embed approved_facts.schema.json
var approvedFactsSchema []byte

//go:embed approved_facts_preview_input.schema.json
var approvedFactsInputSchema []byte

var once sync.Once
var compiledCatalog, compiledInput *jsonschema.Schema
var compiledInputV2, compiledInputV3, compiledRequirements *jsonschema.Schema
var compiledApprovedFacts, compiledApprovedFactsInput *jsonschema.Schema
var supportedRequirementsDigest string
var supportedModuleDigest string
var compileError error

func schemas() error {
	once.Do(func() {
		compiler := jsonschema.NewCompiler()
		compiler.Draft = jsonschema.Draft2020
		compiler.AssertFormat = true
		compiler.LoadURL = func(string) (io.ReadCloser, error) {
			return nil, errors.New("resolver: external schema loading forbidden")
		}
		for name, data := range map[string][]byte{
			"https://cadence.das.dev/embedded/modules":              catalogSchema,
			"https://cadence.das.dev/embedded/preview":              inputSchema,
			"https://cadence.das.dev/embedded/preview-v2":           inputV2Schema,
			"https://cadence.das.dev/embedded/preview-v3":           inputV3Schema,
			"https://cadence.das.dev/embedded/requirements":         requirementSchema,
			"https://cadence.das.dev/embedded/approved-facts":       approvedFactsSchema,
			"https://cadence.das.dev/embedded/approved-facts-input": approvedFactsInputSchema,
		} {
			if err := compiler.AddResource(name, bytes.NewReader(data)); err != nil {
				compileError = err
				return
			}
		}
		compiledCatalog, compileError = compiler.Compile("https://cadence.das.dev/embedded/modules")
		if compileError == nil {
			compiledInput, compileError = compiler.Compile("https://cadence.das.dev/embedded/preview")
		}
		if compileError == nil {
			compiledInputV2, compileError = compiler.Compile("https://cadence.das.dev/embedded/preview-v2")
		}
		if compileError == nil {
			compiledInputV3, compileError = compiler.Compile("https://cadence.das.dev/embedded/preview-v3")
		}
		if compileError == nil {
			compiledRequirements, compileError = compiler.Compile("https://cadence.das.dev/embedded/requirements")
		}
		if compileError == nil {
			compiledApprovedFacts, compileError = compiler.Compile("https://cadence.das.dev/embedded/approved-facts")
		}
		if compileError == nil {
			compiledApprovedFactsInput, compileError = compiler.Compile("https://cadence.das.dev/embedded/approved-facts-input")
		}
		if compileError == nil {
			var supported any
			supported, compileError = exactjson.ParseCatalog(requirementCatalog)
			if compileError == nil {
				compileError = compiledRequirements.Validate(supported)
			}
			if compileError == nil {
				supportedRequirementsDigest, compileError = exactjson.DigestCatalog(supported)
			}
		}
		if compileError == nil {
			var supported any
			supported, compileError = exactjson.Parse(supportedModuleCatalog)
			if compileError == nil {
				compileError = compiledCatalog.Validate(supported)
			}
			if compileError == nil {
				supportedModuleDigest, compileError = exactjson.Digest(supported)
			}
		}
	})
	return compileError
}

type Truth string

const (
	True     Truth = "true"
	False    Truth = "false"
	Unknown  Truth = "unknown"
	Conflict Truth = "conflict"
)

func Not(value Truth) (Truth, error) {
	switch value {
	case True:
		return False, nil
	case False:
		return True, nil
	case Unknown:
		return Unknown, nil
	case Conflict:
		return Conflict, nil
	default:
		return "", errors.New("resolver: invalid truth")
	}
}

func combine(values []Truth, all bool) (Truth, error) {
	if len(values) == 0 {
		return "", errors.New("resolver: empty rule")
	}
	unknown, decisive := false, false
	for _, value := range values {
		switch value {
		case Conflict:
			return Conflict, nil
		case Unknown:
			unknown = true
		case True:
			if !all {
				decisive = true
			}
		case False:
			if all {
				decisive = true
			}
		default:
			return "", errors.New("resolver: invalid truth")
		}
	}
	if decisive {
		if all {
			return False, nil
		}
		return True, nil
	}
	if unknown {
		return Unknown, nil
	}
	if all {
		return True, nil
	}
	return False, nil
}

func All(values ...Truth) (Truth, error) { return combine(values, true) }
func Any(values ...Truth) (Truth, error) { return combine(values, false) }

type fact struct {
	truth   Truth
	sources map[string]bool
}

func evaluate(expression map[string]any, facts map[string]fact, depth int, budget *int) (Truth, error) {
	*budget--
	if depth > 32 || *budget < 0 {
		return "", errors.New("resolver: rule limit exceeded")
	}
	switch expression["op"] {
	case "const":
		if expression["value"].(bool) {
			return True, nil
		}
		return False, nil
	case "fact", "exists":
		value, ok := facts[expression["key"].(string)]
		if !ok {
			return Unknown, nil
		}
		if expression["op"] == "exists" && (value.truth == True || value.truth == False) {
			return True, nil
		}
		return value.truth, nil
	case "all", "any":
		values := []Truth{}
		for _, child := range expression["args"].([]any) {
			value, err := evaluate(child.(map[string]any), facts, depth+1, budget)
			if err != nil {
				return "", err
			}
			values = append(values, value)
		}
		return combine(values, expression["op"] == "all")
	default:
		return "", errors.New("resolver: unsupported operation")
	}
}

func sortedKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// Preview evaluates proposals only. It never returns an approved Bundle identity.
func Preview(input any) (map[string]any, error) {
	if err := schemas(); err != nil {
		return nil, errors.New("resolver: schema unavailable")
	}
	request, ok := input.(map[string]any)
	if !ok {
		return nil, errors.New("resolver: invalid exact preview input")
	}
	v2 := request["contractIdentity"] == "das-bundle-preview-input/v2"
	v3 := request["contractIdentity"] == "das-bundle-preview-input/v3"
	validator := compiledInput
	if v2 {
		validator = compiledInputV2
	} else if v3 {
		validator = compiledInputV3
	}
	if err := validator.Validate(input); err != nil {
		return nil, errors.New("resolver: invalid exact preview input")
	}
	catalog := request["catalog"].(map[string]any)
	if err := compiledCatalog.Validate(catalog); err != nil {
		return nil, errors.New("resolver: invalid exact module catalog")
	}
	modules := map[string]map[string]any{}
	owners := map[string]string{}
	for _, raw := range catalog["modules"].([]any) {
		module := raw.(map[string]any)
		id := module["id"].(string)
		if _, exists := modules[id]; exists {
			return nil, errors.New("resolver: duplicate module")
		}
		if module["effect"] != "normative" {
			return nil, errors.New("resolver: normative effect cannot be downgraded")
		}
		modules[id] = module
		for _, unit := range module["legacyUnitIds"].([]any) {
			idUnit := unit.(string)
			if _, exists := owners[idUnit]; exists {
				return nil, errors.New("resolver: duplicate unit ownership")
			}
			owners[idUnit] = id
		}
	}
	if len(modules) != 10 {
		return nil, errors.New("resolver: incomplete module set")
	}
	for _, id := range []string{"das.core", "das.security-agent", "das.governance.verification-release"} {
		activation := modules[id]["activation"].(map[string]any)
		if activation["op"] != "const" || activation["value"] != true {
			return nil, errors.New("resolver: nonwaivable module disabled")
		}
	}
	visited, visiting := map[string]bool{}, map[string]bool{}
	var visit func(string) error
	visit = func(id string) error {
		if visiting[id] {
			return errors.New("resolver: dependency cycle")
		}
		if visited[id] {
			return nil
		}
		module, ok := modules[id]
		if !ok {
			return errors.New("resolver: unknown dependency")
		}
		visiting[id] = true
		for _, dependency := range module["dependsOn"].([]any) {
			if err := visit(dependency.(string)); err != nil {
				return err
			}
		}
		visiting[id] = false
		visited[id] = true
		return nil
	}
	for _, id := range sortedKeys(modules) {
		if err := visit(id); err != nil {
			return nil, err
		}
	}
	hasUI := false
	for _, dep := range modules["das.interaction.hfvi"]["dependsOn"].([]any) {
		hasUI = hasUI || dep == "das.interaction.standard-ui"
	}
	if !hasUI {
		return nil, errors.New("resolver: HFVI omits UI dependency")
	}
	// A pinned binary supports the exact current catalog, not arbitrary
	// caller-supplied rewrites of mandatory predicates. Source validation checks
	// its fragments; runtime binding cannot itself approve policy or facts.
	leaves := map[string]map[string]any{}
	if v2 || v3 {
		moduleDigest, err := exactjson.Digest(catalog)
		if v3 && (err != nil || moduleDigest != supportedModuleDigest) {
			return nil, errors.New("resolver: unsupported module catalog identity")
		}
		requirements := request["requirementsCatalog"].(map[string]any)
		// The old closed v2 output promises incomplete mapping. Never emit a
		// complete catalog through that identity, or infer support from a version
		// range. Historical v2 records remain readable by their own schemas.
		if (v3 && requirements["migrationStage"] != "complete-leaf-mapping") ||
			(v2 && requirements["migrationStage"] != "partial-leaf-mapping") {
			return nil, errors.New("resolver: unsupported catalog/output combination")
		}
		digest, err := exactjson.DigestCatalog(requirements)
		if err != nil || digest != supportedRequirementsDigest {
			return nil, errors.New("resolver: unsupported requirement catalog identity")
		}
		// schemas already validates the immutable embedded catalog. Exact JCS
		// identity binds this input to that same object, including every field
		// and predicate. Validate it once, rather than rescan every schema
		// branch for each call; an unpinned catalog is always rejected above.
		if requirements["standardVersion"] != catalog["standardVersion"] || requirements["baselineSha256"] != catalog["baselineSha256"] {
			return nil, errors.New("resolver: requirement and module catalog identities differ")
		}
		for _, group := range []string{"requirements", "editionRequirements"} {
			for _, raw := range requirements[group].([]any) {
				leaf := raw.(map[string]any)
				id, owner := leaf["id"].(string), leaf["ownerModule"].(string)
				if _, duplicate := leaves[id]; duplicate {
					return nil, errors.New("resolver: duplicate requirement")
				}
				module, present := modules[owner]
				if !present {
					return nil, errors.New("resolver: unknown requirement owner")
				}
				parentFound := false
				for _, clause := range module["clauseIds"].([]any) {
					parentFound = parentFound || clause == leaf["parentClause"]
				}
				if !parentFound {
					return nil, errors.New("resolver: requirement parent absent from owner")
				}
				if unit, legacy := leaf["legacyUnitId"]; legacy && owners[unit.(string)] != owner {
					return nil, errors.New("resolver: requirement legacy unit has another owner")
				}
				leaves[id] = leaf
			}
		}
	}
	facts := map[string]fact{}
	identities := map[string]bool{}
	normalizedFacts := []any{}
	for _, raw := range request["facts"].([]any) {
		record := raw.(map[string]any)
		key := record["key"].(string)
		source := record["sourceRef"].(string)
		identity := key + "\x00" + source
		if identities[identity] {
			return nil, errors.New("resolver: repeated fact source identity")
		}
		identities[identity] = true
		truth := Unknown
		if value, ok := record["value"].(bool); ok {
			if value {
				truth = True
			} else {
				truth = False
			}
		}
		old, present := facts[key]
		if !present {
			old = fact{truth: truth, sources: map[string]bool{}}
		} else if old.truth != truth {
			old.truth = Conflict
		}
		old.sources[source] = true
		facts[key] = old
		normalizedFacts = append(normalizedFacts, record)
	}
	sort.Slice(normalizedFacts, func(i, j int) bool {
		a, b := normalizedFacts[i].(map[string]any), normalizedFacts[j].(map[string]any)
		if a["key"] != b["key"] {
			return a["key"].(string) < b["key"].(string)
		}
		return a["sourceRef"].(string) < b["sourceRef"].(string)
	})
	selected := map[string]bool{}
	unresolved := []any{}
	trace := []any{}
	budget := 10000
	for _, id := range sortedKeys(modules) {
		truth, err := evaluate(modules[id]["activation"].(map[string]any), facts, 0, &budget)
		if err != nil {
			return nil, err
		}
		trace = append(trace, map[string]any{"moduleId": id, "state": string(truth)})
		if truth == True {
			selected[id] = true
		} else if truth == Unknown || truth == Conflict {
			unresolved = append(unresolved, map[string]any{"moduleId": id, "state": string(truth)})
		}
	}
	var closeDependencies func(string)
	closeDependencies = func(id string) {
		for _, raw := range modules[id]["dependsOn"].([]any) {
			dep := raw.(string)
			if !selected[dep] {
				selected[dep] = true
				closeDependencies(dep)
			}
		}
	}
	for _, id := range sortedKeys(selected) {
		closeDependencies(id)
	}
	resolved := []any{}
	for _, id := range sortedKeys(selected) {
		resolved = append(resolved, id)
	}
	factStates := []any{}
	for _, key := range sortedKeys(facts) {
		refs := []any{}
		for _, source := range sortedKeys(facts[key].sources) {
			refs = append(refs, source)
		}
		factStates = append(factStates, map[string]any{"key": key, "state": string(facts[key].truth), "sourceRefs": refs})
	}
	factsDigest, err := exactjson.Digest(normalizedFacts)
	if err != nil {
		return nil, err
	}
	catalogDigest, err := exactjson.Digest(catalog)
	if err != nil {
		return nil, err
	}
	output := map[string]any{
		"contractIdentity": "das-bundle-preview/v1", "scope": request["scope"], "standardVersion": catalog["standardVersion"],
		"policyDigest": request["policyDigest"], "factsDigest": factsDigest, "catalogDigest": catalogDigest, "digestMethod": exactjson.DigestMethod,
		"resolvedModules": resolved, "unresolvedModules": unresolved, "factStates": factStates, "ruleTrace": trace,
		"authorityVerified": false, "qualificationEligible": false, "limitations": []any{"facts_are_unapproved_proposals", "legacy_leaf_applicability_not_migrated", "protected_resolution_not_enabled"},
	}
	if v2 || v3 {
		requirementTrace := []any{}
		for _, id := range sortedKeys(leaves) {
			leaf := leaves[id]
			truth, err := evaluate(leaf["activation"].(map[string]any), facts, 0, &budget)
			if err != nil {
				return nil, err
			}
			requirementTrace = append(requirementTrace, map[string]any{
				"requirementId": id, "ownerModule": leaf["ownerModule"], "parentClause": leaf["parentClause"], "state": string(truth),
			})
		}
		output["contractIdentity"] = "das-bundle-preview/v2"
		output["requirementsCatalogDigest"] = supportedRequirementsDigest
		output["leafMigrationComplete"] = false
		output["requirementTrace"] = requirementTrace
		output["limitations"] = []any{"facts_are_unapproved_proposals", "requirement_leaf_migration_incomplete", "protected_resolution_not_enabled"}
		if v3 {
			output["contractIdentity"] = "das-bundle-preview/v3"
			output["leafMigrationComplete"] = true
			output["limitations"] = []any{"facts_are_unapproved_proposals", "protected_resolution_not_enabled"}
		}
	}
	if digest, err := exactjson.Digest(output); err == nil {
		output["previewDigest"] = digest
	} else {
		return nil, fmt.Errorf("resolver: cannot digest result")
	}
	return output, nil
}
