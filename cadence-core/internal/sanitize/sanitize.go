// Package sanitize — strips host paths, secrets, and PII from log lines
// and structured records before they enter the evidence pack or support
// bundle.
package sanitize

import (
	"regexp"
	"strings"
)

var (
	emailRe = regexp.MustCompile(`[\w.+-]+@[\w-]+\.[\w.-]+`)
	tokenRe = regexp.MustCompile(`(?i)(?:bearer\s+|token=|api[_-]?key=)[A-Za-z0-9_\-./=]{6,}|secret-token-[A-Za-z0-9_\-]+|ghp_[A-Za-z0-9_]+`)
	uuidRe  = regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`)
	homeRe  = regexp.MustCompile(`/Users/[^/\s"']+|/home/[^/\s"']+|C:\\Users\\[^\\\s"']+`)
)

type PathLeak struct {
	Field string `json:"field"`
	Value string `json:"value"`
}

type SecretLeak struct {
	Field string `json:"field"`
	Value string `json:"value"`
}

// String returns s with sensitive substrings replaced by stable tokens.
func String(s string) string {
	s = emailRe.ReplaceAllString(s, "<email>")
	s = tokenRe.ReplaceAllString(s, "<token>")
	s = uuidRe.ReplaceAllString(s, "<uuid>")
	s = homeRe.ReplaceAllString(s, "<home>")
	return s
}

// Map applies String recursively over a JSON-like structure. Map keys
// matching SecretKeys (case-insensitive) have their entire value replaced
// with "<redacted>".
func Map(v any) any {
	switch x := v.(type) {
	case string:
		return String(x)
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, val := range x {
			if isSecretKey(k) {
				out[k] = "<redacted>"
				continue
			}
			out[k] = Map(val)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = Map(e)
		}
		return out
	default:
		return v
	}
}

// SanitizeReport applies CAD-003 path and secret redaction to a replay report.
func SanitizeReport(v any) any {
	return Map(v)
}

// SecretKeys are dropped wholesale.
var SecretKeys = []string{"password", "secret", "apikey", "api_key", "token",
	"authorization", "cookie", "set-cookie", "private_key"}

func isSecretKey(k string) bool {
	lk := strings.ToLower(k)
	for _, s := range SecretKeys {
		if lk == s {
			return true
		}
	}
	return false
}
