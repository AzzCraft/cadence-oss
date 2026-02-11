package baseline

import (
  "encoding/json"
  "os"
  "path/filepath"

  "github.com/azzcraft/cadence-core/internal/checks"
)

type Baseline struct {
  SchemaVersion string   `json:"schemaVersion"`
  Fingerprints  []string `json:"fingerprints"`
}

func Load(path string) (Baseline, error) {
  b := Baseline{SchemaVersion: "1.0.0", Fingerprints: []string{}}
  data, err := os.ReadFile(path)
  if err != nil {
    return b, err
  }
  if err := json.Unmarshal(data, &b); err != nil {
    return b, err
  }
  return b, nil
}

func Save(path string, violations []checks.Violation) error {
  m := map[string]bool{}
  for _, v := range violations {
    m[v.Fingerprint] = true
  }
  fps := make([]string, 0, len(m))
  for fp := range m {
    fps = append(fps, fp)
  }
  b := Baseline{SchemaVersion: "1.0.0", Fingerprints: fps}
  data, err := json.MarshalIndent(b, "", "  ")
  if err != nil {
    return err
  }
  if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
    return err
  }
  return os.WriteFile(path, data, 0o644)
}

func Contains(b Baseline, fp string) bool {
  for _, x := range b.Fingerprints {
    if x == fp {
      return true
    }
  }
  return false
}
