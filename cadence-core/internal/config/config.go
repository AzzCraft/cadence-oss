package config

import (
	"bufio"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// Config is intentionally small and uses a minimal YAML subset parser to avoid
// external dependencies in this runnable scaffold.
//
// Supported YAML subset:
//   - top-level scalars: key: value
//   - simple lists:
//     policies:
//   - a
//   - b
//   - one nested block:
//     ui:
//     enabled: true
//     profile: pr
//
// Production implementations SHOULD replace this with strict schema validation.
type Config struct {
	ProjectID string
	Mode      string

	Policies []string

	UIEnabled bool
	UIProfile string

	BaselinePath string
}

func Default() Config {
	return Config{
		ProjectID:    "unknown",
		Mode:         "strict_offline",
		Policies:     []string{"unified-v17-baseline"},
		UIEnabled:    false,
		UIProfile:    "pr",
		BaselinePath: filepath.Join(".cadence", "baseline.json"),
	}
}

// Load searches for cadence.yaml or cadence.yml in the provided root.
// If not found, returns Default() with nil error.
func Load(repoRoot string) (Config, error) {
	cfg := Default()

	cand := []string{
		filepath.Join(repoRoot, "cadence.yaml"),
		filepath.Join(repoRoot, "cadence.yml"),
	}
	path := ""
	for _, c := range cand {
		if _, err := os.Stat(c); err == nil {
			path = c
			break
		}
	}
	if path == "" {
		return cfg, nil
	}

	f, err := os.Open(path)
	if err != nil {
		return cfg, err
	}
	defer f.Close()

	s := bufio.NewScanner(f)
	currentBlock := ""
	inPolicies := false
	for s.Scan() {
		line := strings.TrimRight(s.Text(), "\r\n")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		// Detect block starts: "ui:" etc.
		if strings.HasSuffix(trimmed, ":") && !strings.Contains(trimmed, " ") {
			blk := strings.TrimSuffix(trimmed, ":")
			currentBlock = blk
			inPolicies = (blk == "policies")
			if inPolicies {
				cfg.Policies = []string{}
			}
			continue
		}

		// List item
		if inPolicies && strings.HasPrefix(trimmed, "-") {
			item := strings.TrimSpace(strings.TrimPrefix(trimmed, "-"))
			if item != "" {
				cfg.Policies = append(cfg.Policies, item)
			}
			continue
		}

		// key: value
		parts := strings.SplitN(trimmed, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		val = strings.Trim(val, "\"'")

		if currentBlock == "ui" {
			switch key {
			case "enabled":
				cfg.UIEnabled = parseBool(val)
			case "profile":
				if val != "" {
					cfg.UIProfile = val
				}
			}
			continue
		}

		// Top-level keys
		switch key {
		case "projectId":
			if val != "" {
				cfg.ProjectID = val
			}
		case "mode":
			if val != "" {
				cfg.Mode = val
			}
		case "baselinePath":
			if val != "" {
				cfg.BaselinePath = val
			}
		}
	}
	if err := s.Err(); err != nil {
		return cfg, err
	}

	if cfg.ProjectID == "" {
		return cfg, errors.New("cadence.yaml missing projectId")
	}
	return cfg, nil
}

func parseBool(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "true", "1", "yes", "y", "on":
		return true
	default:
		return false
	}
}
