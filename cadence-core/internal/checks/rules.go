package checks

import (
	"bytes"
	"path/filepath"
	"regexp"
	"strings"
)

// RunAll runs the built-in baseline rules.
func RunAll(repoRoot string) ([]Violation, error) {
	var out []Violation

	// Regexes are intentionally conservative to keep the offline baseline deterministic.
	secretRules := []struct {
		id      string
		sev     Severity
		re      *regexp.Regexp
		message string
	}{
		{"SEC_TEST_AUTH_TOKEN", SevP0, regexp.MustCompile(`TEST_AUTH_TOKEN`), "Hardcoded TEST_AUTH_TOKEN detected"},
		{"SEC_PRIVATE_KEY", SevP0, regexp.MustCompile(`BEGIN (RSA |EC |DSA |OPENSSH |)PRIVATE KEY`), "Private key material detected"},
		{"SEC_AWS_KEY", SevP0, regexp.MustCompile(`AKIA[0-9A-Z]{16}`), "Potential AWS access key detected"},
		{"SEC_GCP_KEY", SevP0, regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}`), "Potential GCP API key detected"},
		{"SEC_GITHUB_TOKEN", SevP0, regexp.MustCompile(`gh[ps]_[0-9A-Za-z]{36}`), "Potential GitHub token detected"},
		{"SEC_GENERIC_SECRET", SevP1, regexp.MustCompile(`(?i)(?:password|secret|token|api_key)\s*[:=]\s*['\"][^'\"]{8,}`), "Potential hardcoded credential detected"},
		{"SEC_JWT", SevP1, regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+`), "Potential JWT token detected"},
	}

	deepImport := regexp.MustCompile(`(?m)^\s*import\s+.*\s+from\s+['\"]([^'\"]+)['\"];?\s*$`)
	deepImport2 := regexp.MustCompile(`(?m)^\s*export\s+\*\s+from\s+['\"]([^'\"]+)['\"];?\s*$`)

	err := WalkFiles(repoRoot, func(relPath string, b []byte) error {
		// Preserve the actual line and report repeated occurrences independently.
		for lineIndex, line := range bytes.Split(b, []byte("\n")) {
			for _, r := range secretRules {
				if r.re.Find(line) != nil {
					out = append(out, New(r.id, r.sev, r.message, relPath, lineIndex+1))
					break
				}
			}
		}

		ext := strings.ToLower(filepath.Ext(relPath))
		if ext == ".ts" || ext == ".tsx" || ext == ".js" || ext == ".jsx" {
			// Deep import scan (heuristic): importing internal/src paths is forbidden.
			for _, m := range deepImport.FindAllSubmatchIndex(b, -1) {
				imp := string(bytes.TrimSpace(b[m[2]:m[3]]))
				if strings.Contains(imp, "/internal/") || strings.Contains(imp, "/src/") {
					out = append(out, New("SDMM_DEEP_IMPORT", SevP1, "Deep import detected: "+imp, relPath, bytes.Count(b[:m[2]], []byte("\n"))+1))
				}
			}
			for _, m := range deepImport2.FindAllSubmatchIndex(b, -1) {
				imp := string(bytes.TrimSpace(b[m[2]:m[3]]))
				if strings.Contains(imp, "/internal/") || strings.Contains(imp, "/src/") {
					out = append(out, New("SDMM_DEEP_IMPORT", SevP1, "Deep import detected: "+imp, relPath, bytes.Count(b[:m[2]], []byte("\n"))+1))
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	// Instance contracts need canonical valid/invalid fixtures or legacy flat
	// fixtures. Shared definition libraries are not standalone instance contracts.
	contractViolations, err := checkContractCompleteness(repoRoot)
	if err != nil {
		return nil, err
	}
	out = append(out, contractViolations...)

	return out, nil
}
