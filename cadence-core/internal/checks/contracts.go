package checks

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

func checkContractCompleteness(repoRoot string) ([]Violation, error) {
	schemasDir := filepath.Join(repoRoot, "contracts", "schemas")
	if _, err := os.Stat(schemasDir); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var violations []Violation
	err := filepath.WalkDir(schemasDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(strings.ToLower(d.Name()), ".json") {
			return nil
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("contract schema is not a regular file: %s", path)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var schema any
		if err := json.Unmarshal(data, &schema); err != nil {
			return fmt.Errorf("contract schema %s: %w", path, err)
		}
		if definitionLibrary(schema) {
			return nil
		}
		base := strings.TrimSuffix(strings.TrimSuffix(d.Name(), ".json"), ".schema")
		fixtureDir := filepath.Join(repoRoot, "contracts", "fixtures", base)
		ok := false
		// Canonical template layout requires valid and invalid examples. Legacy
		// flat fixtures remain readable; this checks existence, not schema semantics.
		hasJSON := func(dir string) bool {
			entries, err := os.ReadDir(dir)
			if err != nil {
				return false
			}
			for _, entry := range entries {
				if entry.Type().IsRegular() && strings.HasSuffix(strings.ToLower(entry.Name()), ".json") {
					return true
				}
			}
			return false
		}
		ok = (hasJSON(filepath.Join(fixtureDir, "valid")) && hasJSON(filepath.Join(fixtureDir, "invalid"))) || hasJSON(fixtureDir)
		if !ok {
			rel, _ := filepath.Rel(repoRoot, path)
			violations = append(violations, New("CONTRACT_FIXTURE_MISSING", SevP1, "Schema has no fixtures: "+base, filepath.ToSlash(rel), 1))
		}
		return nil
	})
	return violations, err
}

// Shared definitions have no standalone instance contract. Only the explicit
// definition-container shape is exempt, never a filename or a schema with root
// constraints such as properties, required, additionalProperties, or $ref.
func definitionLibrary(value any) bool {
	schema, ok := value.(map[string]any)
	if !ok {
		return false
	}
	definitions, _ := schema["$defs"].(map[string]any)
	legacyDefinitions, _ := schema["definitions"].(map[string]any)
	if len(definitions)+len(legacyDefinitions) == 0 {
		return false
	}
	for key, value := range schema {
		switch key {
		case "$schema", "$id", "$comment", "title", "description", "$defs", "definitions":
		case "type":
			if value != "object" {
				return false
			}
		default:
			return false
		}
	}
	return true
}
