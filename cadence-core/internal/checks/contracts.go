package checks

import (
  "io/fs"
  "os"
  "path/filepath"
  "strings"
)

func checkContractCompleteness(repoRoot string) ([]Violation, error) {
  schemasDir := filepath.Join(repoRoot, "contracts", "schemas")
  if _, err := os.Stat(schemasDir); err != nil {
    return nil, nil
  }

  var violations []Violation
  _ = filepath.WalkDir(schemasDir, func(path string, d fs.DirEntry, err error) error {
    if err != nil {
      return err
    }
    if d.IsDir() {
      return nil
    }
    if !strings.HasSuffix(strings.ToLower(d.Name()), ".json") {
      return nil
    }
    base := strings.TrimSuffix(d.Name(), ".json")
    fixtureDir := filepath.Join(repoRoot, "contracts", "fixtures", base)
    ok := false
    if entries, err := os.ReadDir(fixtureDir); err == nil {
      for _, e := range entries {
        if !e.IsDir() && strings.HasSuffix(strings.ToLower(e.Name()), ".json") {
          ok = true
          break
        }
      }
    }
    if !ok {
      rel, _ := filepath.Rel(repoRoot, path)
      violations = append(violations, New("CONTRACT_FIXTURE_MISSING", SevP1, "Schema has no fixtures: "+base, filepath.ToSlash(rel), 1))
    }
    return nil
  })
  return violations, nil
}
