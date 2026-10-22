package main

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AzzCraft/cadence-oss/cadence-core/internal/exactjson"
)

func TestIntegrationContractIndependentWireVectors(t *testing.T) {
	for name, identity := range map[string]string{
		"integration_plan":    "das-integration-plan/v1",
		"integration_receipt": "das-integration-receipt/v1",
		"completion":          "das-completion/v1",
	} {
		t.Run(name, func(t *testing.T) {
			root := filepath.Join("..", "..", "..", "cadence-protocol", "fixtures", "das_v1_5")
			raw, err := os.ReadFile(filepath.Join(root, "valid", name+".json"))
			if err != nil {
				t.Fatal(err)
			}
			value, err := exactjson.Parse(raw)
			if err != nil {
				t.Fatal(err)
			}
			checked, err := validateIntegrationContract(value, identity)
			if err != nil {
				t.Fatal(err)
			}
			canonical, err := exactjson.Canonical(checked)
			if err != nil || !bytes.Contains(canonical, []byte(`"contractIdentity":"`+identity+`"`)) {
				t.Fatal("lost exact supported identity", err)
			}
			invalid, err := os.ReadFile(filepath.Join(root, "invalid", name+".json"))
			if err != nil {
				t.Fatal(err)
			}
			bad, err := exactjson.Parse(invalid)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = validateIntegrationContract(bad, identity); err == nil {
				t.Fatal("unsupported qualification/critical field accepted")
			}
			for _, number := range []string{"1.000000000000000001", "9007199254740992", "true", `"1"`} {
				mutation := bytes.Replace(raw, []byte(`"taskRevision": 1`), []byte(`"taskRevision": `+number), 1)
				if bytes.Equal(mutation, raw) {
					t.Fatal("independent numeric mutation not applied")
				}
				bad, err := exactjson.Parse(mutation)
				if err == nil {
					_, err = validateIntegrationContract(bad, identity)
				}
				if err == nil {
					t.Fatal("lossy/incorrect security integer accepted:", number)
				}
			}
		})
	}
}

func TestIntegrationReferenceSemanticLimits(t *testing.T) {
	for name, identity := range map[string]string{
		"integration_plan":    "das-integration-plan/v1",
		"integration_receipt": "das-integration-receipt/v1",
		"completion":          "das-completion/v1",
	} {
		raw, err := os.ReadFile(filepath.Join("..", "..", "..", "cadence-protocol", "fixtures", "das_v1_5", "valid", name+".json"))
		if err != nil {
			t.Fatal(err)
		}
		value, err := exactjson.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		object := value.(map[string]any)
		switch name {
		case "integration_plan":
			object["afterCandidateDigest"] = object["beforeCandidateDigest"]
		case "integration_receipt":
			object["afterGeneration"] = object["beforeGeneration"]
		case "completion":
			object["parentChange"].(map[string]any)["status"] = "closing"
		}
		if _, err := validateIntegrationContract(object, identity); err == nil {
			t.Fatal("native integration semantic precondition bypassed:", name)
		}
	}
	if _, err := validateIntegrationContract(nil, "das-version-switch-receipt/v1"); err == nil {
		t.Fatal("legacy receipt reinterpreted as new integration contract")
	}
}

func TestHTTPCoverageProbeUsesIndependentInputs(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	example := filepath.Join(root, "cadence-examples", "examples", "headless-minimal", "http")
	declarationRaw, err := os.ReadFile(filepath.Join(example, "declaration.json"))
	if err != nil {
		t.Fatal(err)
	}
	declaration, err := exactjson.Parse(declarationRaw)
	if err != nil {
		t.Fatal(err)
	}
	sources := declaration.(map[string]any)["sources"].([]any)
	files := []string{filepath.Join(example, "openapi.json"), filepath.Join(root, "cadence-protocol", "schemas", "das_v1_5", "resource_action_intent.schema.json")}
	originals := []any{}
	for i, file := range files {
		raw, e := os.ReadFile(file)
		if e != nil {
			t.Fatal(e)
		}
		originals = append(originals, map[string]any{"uri": sources[i].(map[string]any)["uri"], "originalBase64": base64.StdEncoding.EncodeToString(raw)})
	}
	inventory, err := httpInventoryProbe(map[string]any{"declaration": declaration, "originals": originals})
	if err != nil {
		t.Fatal(err)
	}
	base := map[string]any{"inventory": inventory, "baseline": []any{
		map[string]any{"operationId": "das.reference.version.read", "method": "GET", "path": "/target"},
		map[string]any{"operationId": "das.reference.version.integrate", "method": "PUT", "path": "/integrations"}},
		"observed": []any{map[string]any{"method": "GET", "path": "/target"}, map[string]any{"method": "PUT", "path": "/integrations"}}, "observationComplete": true}
	raw, err := exactjson.Canonical(base)
	if err != nil {
		t.Fatal(err)
	}
	for _, fault := range []string{"legal", "incomplete", "deleted", "reused-id", "wrong-type", "unknown-field"} {
		t.Run(fault, func(t *testing.T) {
			copy, e := exactjson.Parse(raw)
			if e != nil {
				t.Fatal(e)
			}
			v := copy.(map[string]any)
			switch fault {
			case "incomplete":
				v["observationComplete"] = false
			case "deleted":
				v["inventory"].(map[string]any)["operations"] = v["inventory"].(map[string]any)["operations"].([]any)[:1]
			case "reused-id":
				v["baseline"].([]any)[0].(map[string]any)["operationId"] = "other"
			case "wrong-type":
				v["observationComplete"] = "true"
			case "unknown-field":
				v["authority"] = true
			}
			result, e := httpCoverageProbe(v)
			if fault != "legal" && fault != "incomplete" {
				if e == nil {
					t.Fatal("invalid supplied coverage accepted")
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			r := result.(map[string]any)
			expected := "matched"
			if fault == "incomplete" {
				expected = "unknown"
			}
			if r["coverage"] != expected || r["authority"] != false || r["qualification"] != false {
				t.Fatal(r)
			}
		})
	}
}

func TestHTTPCoverageUsesUnicodeOperationIDLimit(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "cadence-protocol", "fixtures", "das_v1_5", "valid", "http_inventory.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, character := range []string{"x", "中", "😀"} {
		for _, length := range []int{128, 129} {
			value, err := exactjson.Parse(raw)
			if err != nil {
				t.Fatal(err)
			}
			inventory := value.(map[string]any)
			operations := inventory["operations"].([]any)
			if len(operations) != 1 {
				t.Fatal("expected fixed single-operation fixture")
			}
			operation := operations[0].(map[string]any)
			id := strings.Repeat(character, length)
			operation["operationId"] = id
			route := map[string]any{"method": operation["method"], "path": operation["path"]}
			probe := map[string]any{"inventory": inventory, "baseline": []any{map[string]any{"operationId": id, "method": operation["method"], "path": operation["path"]}}, "observed": []any{route}, "observationComplete": true}
			_, err = httpCoverageProbe(probe)
			if (err == nil) != (length <= 128) {
				t.Fatalf("%s/%d: %v", character, length, err)
			}
		}
	}
}
