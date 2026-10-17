package exactjson

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

const DigestMethod = "rfc8785-jcs-utf8-sha256"

// Canonical implements the new RFC 8785 identity only. No trailing newline.
func Canonical(value any) ([]byte, error) {
	return canonical(value, MaxNodes)
}

func CanonicalCatalog(value any) ([]byte, error) {
	return canonical(value, MaxCatalogNodes)
}

func canonical(value any, nodeLimit int) ([]byte, error) {
	var out bytes.Buffer
	nodes := 0
	if err := writeJCS(&out, value, 0, &nodes, nodeLimit); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func Digest(value any) (string, error) {
	return digest(value, MaxNodes)
}

func DigestCatalog(value any) (string, error) {
	return digest(value, MaxCatalogNodes)
}

func digest(value any, nodeLimit int) (string, error) {
	data, err := canonical(value, nodeLimit)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func writeJCS(out *bytes.Buffer, value any, depth int, nodes *int, nodeLimit int) error {
	*nodes++
	if depth > MaxDepth || *nodes > nodeLimit || out.Len() > MaxBytes {
		return errors.New("jcs: structural limit exceeded")
	}
	switch v := value.(type) {
	case nil:
		out.WriteString("null")
	case bool:
		out.WriteString(strconv.FormatBool(v))
	case string:
		if err := writeString(out, v); err != nil {
			return err
		}
	case json.Number:
		// Exact integral JSON lexemes cannot silently lose precision. Contract
		// integer fields are checked with SafeInteger before this step.
		if !strings.ContainsAny(string(v), ".eE") {
			if _, err := SafeInteger(v); err != nil {
				return err
			}
		}
		number, err := strconv.ParseFloat(string(v), 64)
		if err != nil {
			return errors.New("jcs: number outside IEEE 754 domain")
		}
		if err := writeNumber(out, number); err != nil {
			return err
		}
	case float64:
		if err := writeNumber(out, v); err != nil {
			return err
		}
	case int:
		return writeJCS(out, json.Number(strconv.FormatInt(int64(v), 10)), depth, nodes, nodeLimit)
	case int64:
		return writeJCS(out, json.Number(strconv.FormatInt(v, 10)), depth, nodes, nodeLimit)
	case []any:
		out.WriteByte('[')
		for i, child := range v {
			if i > 0 {
				out.WriteByte(',')
			}
			if err := writeJCS(out, child, depth+1, nodes, nodeLimit); err != nil {
				return err
			}
		}
		out.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(v))
		for key := range v {
			if !utf8.ValidString(key) {
				return errors.New("jcs: invalid object key")
			}
			keys = append(keys, key)
		}
		sort.Slice(keys, func(i, j int) bool { return utf16Less(keys[i], keys[j]) })
		out.WriteByte('{')
		for i, key := range keys {
			if i > 0 {
				out.WriteByte(',')
			}
			if err := writeString(out, key); err != nil {
				return err
			}
			out.WriteByte(':')
			if err := writeJCS(out, v[key], depth+1, nodes, nodeLimit); err != nil {
				return err
			}
		}
		out.WriteByte('}')
	default:
		return errors.New("jcs: unsupported host value")
	}
	if out.Len() > MaxBytes {
		return errors.New("jcs: output size exceeded")
	}
	return nil
}

func utf16Less(a, b string) bool {
	x, y := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	for i := 0; i < len(x) && i < len(y); i++ {
		if x[i] != y[i] {
			return x[i] < y[i]
		}
	}
	return len(x) < len(y)
}

func writeString(out *bytes.Buffer, value string) error {
	if !utf8.ValidString(value) {
		return errors.New("jcs: invalid Unicode")
	}
	out.WriteByte('"')
	for _, char := range value {
		switch char {
		case '"', '\\':
			out.WriteByte('\\')
			out.WriteRune(char)
		case '\b':
			out.WriteString(`\b`)
		case '\t':
			out.WriteString(`\t`)
		case '\n':
			out.WriteString(`\n`)
		case '\f':
			out.WriteString(`\f`)
		case '\r':
			out.WriteString(`\r`)
		default:
			if char < 0x20 {
				out.WriteString(`\u00`)
				out.WriteByte("0123456789abcdef"[byte(char)>>4])
				out.WriteByte("0123456789abcdef"[byte(char)&15])
			} else {
				out.WriteRune(char)
			}
		}
	}
	out.WriteByte('"')
	return nil
}

func writeNumber(out *bytes.Buffer, value float64) error {
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return errors.New("jcs: nonfinite number")
	}
	if value == 0 {
		out.WriteByte('0')
		return nil
	}
	format := byte('f')
	if math.Abs(value) < 1e-6 || math.Abs(value) >= 1e21 {
		format = 'e'
	}
	text := strconv.FormatFloat(value, format, -1, 64)
	if at := strings.IndexByte(text, 'e'); at >= 0 {
		exponent, err := strconv.Atoi(text[at+1:])
		if err != nil {
			return err
		}
		sign := ""
		if exponent >= 0 {
			sign = "+"
		}
		text = text[:at+1] + sign + strconv.Itoa(exponent)
	}
	out.WriteString(text)
	return nil
}
