package checks

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// RunAll runs the built-in baseline rules.
func RunAll(repoRoot string) ([]Violation, error) {
	findings, _, err := RunAllWithTrace(repoRoot)
	return findings, err
}

func RunAllWithTrace(repoRoot string) ([]Violation, []string, error) {
	out := make([]Violation, 0)
	executed := map[string]bool{}

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

	err := WalkFiles(repoRoot, func(relPath string, b []byte) error {
		// Preserve the actual line and report repeated occurrences independently.
		for lineIndex, line := range bytes.Split(b, []byte("\n")) {
			for _, r := range secretRules {
				executed[r.id] = true
				if r.re.Find(line) != nil {
					finding := New(r.id, r.sev, r.message, relPath, lineIndex+1)
					finding.Fingerprint = fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(finding.Fingerprint+"\nsecret-content/v2\n"+fmt.Sprintf("%x", sha256.Sum256(line)))))
					out = append(out, finding)
					break
				}
			}
		}

		ext := strings.ToLower(filepath.Ext(relPath))
		if ext == ".ts" || ext == ".tsx" || ext == ".js" || ext == ".jsx" {
			executed["SDMM_DEEP_IMPORT"] = true
			for _, module := range importedJSModules(b) {
				if strings.Contains(module.value, "/internal/") || strings.Contains(module.value, "/src/") {
					out = append(out, New("SDMM_DEEP_IMPORT", SevP1, "Deep import detected: "+module.value, relPath, module.line))
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}

	// Instance contracts need canonical valid/invalid fixtures or legacy flat
	// fixtures. Shared definition libraries are not standalone instance contracts.
	executed["CONTRACT_COMPLETENESS"] = true
	contractViolations, err := checkContractCompleteness(repoRoot)
	if err != nil {
		return nil, nil, err
	}
	out = append(out, contractViolations...)

	ids := make([]string, 0, len(executed))
	for id := range executed {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return out, ids, nil
}

// Tokenize import declarations without treating comments or string contents as
// code. This supports static, side-effect, named re-export and literal dynamic
// imports; it is not a whole-language semantic/type checker.
type jsToken struct {
	value  string
	offset int
}

// Keep template text and regex bodies opaque, but scan template expressions as
// code. This is a lexical import scanner; nonconstant module names are not evaluated.
func tokenizeJS(source []byte) []jsToken {
	tokens := []jsToken{}
	i := 0
	var code func(bool)
	var template func()
	word := func(c byte) bool {
		return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '$'
	}
	add := func(start, end int) { tokens = append(tokens, jsToken{string(source[start:end]), start}) }
	template = func() {
		start, slot := i, len(tokens)
		tokens = append(tokens, jsToken{"<template>", start})
		i++
		interpolated := false
		for i < len(source) {
			if source[i] == '\\' {
				i += 2
				continue
			}
			if source[i] == '`' {
				i++
				if !interpolated {
					tokens[slot].value = string(source[start:i])
				}
				return
			}
			if source[i] == '$' && i+1 < len(source) && source[i+1] == '{' {
				interpolated = true
				i += 2
				code(true)
			} else {
				i++
			}
		}
	}
	code = func(expression bool) {
		canRegex, previous := true, ""
		statementStart, brackets := !expression, 0
		// Remember whether a body closes a declaration or an expression value.
		type bodyContext struct {
			kind                     string
			declaration              bool
			parens, braces, brackets int
		}
		type braceContext struct {
			regexAfter, statements bool
			parens                 int
		}
		pending := []bodyContext{}
		parens, blocks := []bool{}, []braceContext{}
		for i < len(source) {
			c := source[i]
			if c == ' ' || c == '\t' || c == '\r' || c == '\n' {
				i++
				continue
			}
			if c == '}' && expression && len(blocks) == 0 {
				i++
				return
			}
			start := i
			if c == '/' && i+1 < len(source) {
				if source[i+1] == '/' {
					for i < len(source) && source[i] != '\n' {
						i++
					}
					continue
				}
				if source[i+1] == '*' {
					i += 2
					for i+1 < len(source) && !(source[i] == '*' && source[i+1] == '/') {
						i++
					}
					i = min(i+2, len(source))
					continue
				}
				if canRegex {
					j, inClass, closed := i+1, false, false
					for j < len(source) && source[j] != '\n' && source[j] != '\r' {
						if source[j] == '\\' {
							j += 2
							continue
						}
						if source[j] == '[' {
							inClass = true
						}
						if source[j] == ']' {
							inClass = false
						}
						if source[j] == '/' && !inClass {
							j++
							closed = true
							break
						}
						j++
					}
					if closed {
						for j < len(source) && word(source[j]) {
							j++
						}
						tokens = append(tokens, jsToken{"<regexp>", start})
						i, canRegex, previous = j, false, "<regexp>"
						statementStart = false
						continue
					}
				}
			}
			if c == '\'' || c == '"' {
				i++
				for i < len(source) {
					if source[i] == '\\' {
						i += 2
						continue
					}
					if source[i] == c {
						i++
						break
					}
					i++
				}
				i = min(i, len(source))
				add(start, i)
				canRegex, previous = false, "<string>"
				statementStart = false
				continue
			}
			if c == '`' {
				template()
				canRegex, previous = false, "<template>"
				statementStart = false
				continue
			}
			if word(c) {
				for i < len(source) && word(source[i]) {
					i++
				}
				add(start, i)
				value := string(source[start:i])
				if (value == "function" || value == "class") && previous != "." {
					pending = append(pending, bodyContext{value, statementStart, len(parens), len(blocks), brackets})
				}
				statementStart = strings.Contains("|else|do|try|finally|", "|"+value+"|") ||
					(statementStart && strings.Contains("|export|default|async|", "|"+value+"|"))
				previous = value
				canRegex = strings.Contains("|return|throw|case|delete|void|typeof|new|in|of|yield|await|else|do|instanceof|", "|"+previous+"|")
				continue
			}
			i++
			if i < len(source) && ((c == '+' || c == '-') && source[i] == c || c == '=' && source[i] == '>') {
				i++
			}
			value := string(source[start:i])
			add(start, i)
			var body bodyContext
			atBodyDepth := false
			if len(pending) > 0 {
				body = pending[len(pending)-1]
				atBodyDepth = body.parens == len(parens) && body.braces == len(blocks) && body.brackets == brackets
			}
			wasStatementStart := statementStart
			statementStart = false
			switch value {
			case "(":
				parens = append(parens, strings.Contains("|if|while|for|switch|catch|with|", "|"+previous+"|"))
				canRegex = true
			case ")":
				canRegex = false
				if len(parens) > 0 {
					canRegex = parens[len(parens)-1]
					parens = parens[:len(parens)-1]
				}
				statementStart = canRegex
			case "{":
				construct := atBodyDepth && (body.kind == "class" || previous == ")")
				statements := construct || wasStatementStart || previous == ")" || previous == "=>"
				regexAfter := statements && previous != "=>"
				if construct {
					regexAfter = body.declaration
					pending = pending[:len(pending)-1]
				}
				blocks = append(blocks, braceContext{regexAfter, statements, len(parens)})
				canRegex = true
				statementStart = statements
			case "}":
				canRegex = true
				if len(blocks) > 0 {
					canRegex = blocks[len(blocks)-1].regexAfter
					blocks = blocks[:len(blocks)-1]
				}
				statementStart = canRegex
				for len(pending) > 0 && pending[len(pending)-1].braces > len(blocks) {
					pending = pending[:len(pending)-1]
				}
			default:
				canRegex = value != "]" && value != "." && value != "++" && value != "--"
				if value == "[" {
					brackets++
				}
				if value == "]" {
					brackets--
				}
				if value == ";" || value == ":" {
					statementStart = !expression && len(parens) == 0
					if len(blocks) > 0 {
						scope := blocks[len(blocks)-1]
						statementStart = scope.statements && scope.parens == len(parens)
					}
				}
				if atBodyDepth && (value == ";" || value == ":" || value == ",") {
					pending = pending[:len(pending)-1]
				}
			}
			previous = value
		}
	}
	code(false)
	return tokens
}

// Normalize JS string escapes once; never execute source to decode an import.
var jsEscape = regexp.MustCompile(`\\(?:u[dD][89aAbB][0-9a-fA-F]{2}\\u[dD][c-fC-F][0-9a-fA-F]{2}|u\{[0-9a-fA-F]+\}|u[0-9a-fA-F]{4}|x[0-9a-fA-F]{2}|\r\n|[\s\S])`)

func decodeJSModuleLiteral(literal string) string {
	return jsEscape.ReplaceAllStringFunc(literal[1:len(literal)-1], func(escape string) string {
		code := escape[1:]
		switch code {
		case "\n", "\r", "\r\n", "\u2028", "\u2029":
			return ""
		case "v":
			return "\v"
		case "0":
			return "\x00"
		}
		if strings.HasPrefix(code, "u{") || strings.HasPrefix(code, "x") {
			digits := code[1:]
			if strings.HasPrefix(code, "u{") {
				digits = code[2 : len(code)-1]
			}
			value, err := strconv.ParseUint(digits, 16, 32)
			if err == nil && value <= 0x10ffff {
				return string(rune(value))
			}
			return escape
		}
		var decoded string
		if json.Unmarshal([]byte(`"`+escape+`"`), &decoded) == nil {
			return decoded
		}
		return code
	})
}

type jsImport struct {
	value string
	line  int
}

func importedJSModules(source []byte) []jsImport {
	tokens := tokenizeJS(source)
	var result []jsImport
	add := func(index int) {
		value := tokens[index].value
		if len(value) >= 2 && (value[0] == '\'' || value[0] == '"' || value[0] == '`') {
			result = append(result, jsImport{decodeJSModuleLiteral(value), bytes.Count(source[:tokens[index].offset], []byte("\n")) + 1})
		}
	}
	for i := 0; i < len(tokens); i++ {
		current := tokens[i]
		if current.value != "import" && current.value != "export" {
			continue
		}
		if i > 0 && tokens[i-1].value == "." {
			continue
		}
		if i+1 >= len(tokens) {
			continue
		}
		next := tokens[i+1].value
		if current.value == "import" && (strings.HasPrefix(next, "'") || strings.HasPrefix(next, "\"")) {
			add(i + 1)
			continue
		}
		if current.value == "import" && next == "(" && i+2 < len(tokens) {
			add(i + 2)
			continue
		}
		for j := i + 1; j+1 < len(tokens); j++ {
			if tokens[j].value == ";" || tokens[j].value == "=" || tokens[j].value == "import" || tokens[j].value == "export" {
				break
			}
			if tokens[j].value == "from" && (strings.HasPrefix(tokens[j+1].value, "'") || strings.HasPrefix(tokens[j+1].value, "\"")) {
				add(j + 1)
				i = j + 1
				break
			}
		}
	}
	return result
}
