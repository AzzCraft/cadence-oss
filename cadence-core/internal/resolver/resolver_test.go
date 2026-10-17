package resolver

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/AzzCraft/cadence-oss/cadence-core/internal/exactjson"
)

func request(t *testing.T) map[string]any {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "module_catalog.json"))
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := exactjson.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{"contractIdentity": "das-bundle-preview-input/v1", "scope": "fixture", "policyDigest": "sha256:" + strings.Repeat("0", 64), "catalog": catalog, "facts": []any{}}
}

func setFacts(input map[string]any, values map[string]any) {
	facts := []any{}
	for _, key := range sortedKeys(values) {
		facts = append(facts, map[string]any{"key": key, "value": values[key], "sourceRef": "fixture:" + key})
	}
	input["facts"] = facts
}

func contains(values any, target string) bool {
	for _, v := range values.([]any) {
		if v == target {
			return true
		}
	}
	return false
}

func TestStrongKleeneTruthTables(t *testing.T) {
	values := []Truth{True, False, Unknown}
	and := [][]Truth{{True, False, Unknown}, {False, False, False}, {Unknown, False, Unknown}}
	or := [][]Truth{{True, True, True}, {True, False, Unknown}, {True, Unknown, Unknown}}
	for i, a := range values {
		for j, b := range values {
			got, err := All(a, b)
			if err != nil || got != and[i][j] {
				t.Fatalf("AND %s %s: %s %v", a, b, got, err)
			}
			got, err = Any(a, b)
			if err != nil || got != or[i][j] {
				t.Fatalf("OR %s %s: %s %v", a, b, got, err)
			}
		}
	}
	if got, err := Not(Unknown); err != nil || got != Unknown {
		t.Fatal("not unknown became known")
	}
	if _, err := Not("error"); err == nil {
		t.Fatal("engine error became false")
	}
	if _, err := All(); err == nil {
		t.Fatal("empty output became truth")
	}
}

func TestSurfaceCombinationsAndPendingUnknown(t *testing.T) {
	for _, profile := range []struct{ headless, ui, hfvi bool }{{true, false, false}, {false, true, false}, {false, true, true}, {true, true, true}} {
		input := request(t)
		setFacts(input, map[string]any{"surface.headless": profile.headless, "surface.ui": profile.ui, "surface.hfvi": profile.hfvi, "capability.ai": false, "capability.algorithm": false})
		result, err := Preview(input)
		if err != nil {
			t.Fatal(err)
		}
		if contains(result["resolvedModules"], "das.interaction.headless") != profile.headless || contains(result["resolvedModules"], "das.interaction.standard-ui") != (profile.ui || profile.hfvi) || contains(result["resolvedModules"], "das.interaction.hfvi") != profile.hfvi {
			t.Fatalf("incorrect modules: %v", result)
		}
		if result["authorityVerified"] != false || result["qualificationEligible"] != false {
			t.Fatal("preview granted authority")
		}
	}
	result, err := Preview(request(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(result["unresolvedModules"].([]any)) != 4 {
		t.Fatal("missing risk fact became false")
	}
}

func TestConflictingSourcesPreservedAndOrderIndependent(t *testing.T) {
	input := request(t)
	a := map[string]any{"key": "surface.ui", "value": true, "sourceRef": "scan:A"}
	b := map[string]any{"key": "surface.ui", "value": false, "sourceRef": "scan:B"}
	input["facts"] = []any{a, b}
	first, err := Preview(input)
	if err != nil {
		t.Fatal(err)
	}
	input["facts"] = []any{b, a}
	second, err := Preview(input)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatal("fact order altered Bundle")
	}
	if first["factStates"].([]any)[0].(map[string]any)["state"] != "conflict" {
		t.Fatal("conflict discarded")
	}
}

func TestExistsUnknownAndRiskMonotonicity(t *testing.T) {
	input := request(t)
	catalog := input["catalog"].(map[string]any)
	for _, raw := range catalog["modules"].([]any) {
		module := raw.(map[string]any)
		if module["id"] == "das.interaction.headless" {
			module["activation"] = map[string]any{"op": "exists", "key": "surface.headless"}
		}
	}
	setFacts(input, map[string]any{"surface.headless": "unknown"})
	result, err := Preview(input)
	if err != nil {
		t.Fatal(err)
	}
	if contains(result["resolvedModules"], "das.interaction.headless") {
		t.Fatal("exists unknown granted known truth")
	}
	// Check every subset of the five fixed risk facts, with approved-rule-like
	// positive activations. Adding true capabilities may only add modules.
	keys := []string{"surface.headless", "surface.ui", "surface.hfvi", "capability.ai", "capability.algorithm"}
	for mask := 0; mask < 32; mask++ {
		values := map[string]any{}
		for i, key := range keys {
			values[key] = mask&(1<<i) != 0
		}
		base := request(t)
		setFacts(base, values)
		before, err := Preview(base)
		if err != nil {
			t.Fatal(err)
		}
		for i, key := range keys {
			if mask&(1<<i) != 0 {
				continue
			}
			values[key] = true
			next := request(t)
			setFacts(next, values)
			after, err := Preview(next)
			if err != nil {
				t.Fatal(err)
			}
			for _, module := range before["resolvedModules"].([]any) {
				if !contains(after["resolvedModules"], module.(string)) {
					t.Fatal("risk addition reduced control")
				}
			}
			values[key] = false
		}
	}
}

func TestInvalidRulesAndForgedApprovalRejected(t *testing.T) {
	for _, mutation := range []string{"self-approve", "type-error", "unknown-op", "not-risk", "cycle", "omit-security", "duplicate-unit", "case-fold"} {
		t.Run(mutation, func(t *testing.T) {
			input := request(t)
			catalog := input["catalog"].(map[string]any)
			modules := catalog["modules"].([]any)
			core := modules[0].(map[string]any)
			switch mutation {
			case "self-approve":
				input["approved"] = true
			case "type-error":
				setFacts(input, map[string]any{"surface.ui": "false"})
			case "unknown-op":
				core["activation"] = map[string]any{"op": "undefined"}
			case "not-risk":
				core["activation"] = map[string]any{"op": "not", "args": []any{map[string]any{"op": "fact", "key": "surface.ui"}}}
			case "cycle":
				core["dependsOn"] = []any{"das.architecture-modularity"}
			case "omit-security":
				modules[9].(map[string]any)["activation"] = map[string]any{"op": "const", "value": false}
			case "duplicate-unit":
				modules[1].(map[string]any)["legacyUnitIds"] = []any{core["legacyUnitIds"].([]any)[0]}
			case "case-fold":
				input["Scope"] = input["scope"]
				delete(input, "scope")
			}
			if _, err := Preview(input); err == nil {
				t.Fatal("invalid resolution accepted")
			}
		})
	}
}

func TestEvaluationFailureCannotBecomeUnknownOrSafeFalse(t *testing.T) {
	for _, failure := range []string{"unknown-operation", "node-budget", "depth"} {
		t.Run(failure, func(t *testing.T) {
			budget, depth := 10000, 0
			expression := map[string]any{"op": "const", "value": false}
			switch failure {
			case "unknown-operation":
				expression["op"] = "undefined"
			case "node-budget":
				budget = 0
			case "depth":
				depth = 33
			}
			value, err := evaluate(expression, map[string]fact{}, depth, &budget)
			if err == nil || value != "" {
				t.Fatal("failed engine returned a semantic truth value")
			}
			if _, err := Not(value); err == nil {
				t.Fatal("undefined failure became a safe negation")
			}
		})
	}
	budget := 10000
	value, err := evaluate(map[string]any{"op": "const", "value": false}, map[string]fact{}, 0, &budget)
	if err != nil || value != False {
		t.Fatal("legitimate fully defined false was rejected")
	}
}
