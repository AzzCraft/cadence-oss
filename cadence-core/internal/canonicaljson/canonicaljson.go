// Package canonicaljson — deterministic JSON encoding.
//
// DAS-04-003: Two semantically-equal objects must produce byte-identical
// canonical JSON. This package sorts object keys, compacts whitespace,
// and uses canonical number formatting.
package canonicaljson

import (
	"bytes"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
)

// Marshal returns the canonical JSON encoding of v. v must be one of:
// nil, bool, string, int/int64, float64, []any, or map[string]any.
func Marshal(v any) ([]byte, error) {
	var buf bytes.Buffer
	if err := write(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func write(buf *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if x {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case string:
		b, _ := json.Marshal(x)
		buf.Write(b)
	case int:
		buf.WriteString(strconv.FormatInt(int64(x), 10))
	case int64:
		buf.WriteString(strconv.FormatInt(x, 10))
	case float64:
		// Reject NaN/Inf — they are not valid JSON and break determinism.
		if x != x || x-x != 0 { // NaN or Inf
			return errors.New("canonicaljson: NaN/Inf not allowed")
		}
		buf.WriteString(strconv.FormatFloat(x, 'g', -1, 64))
	case []any:
		buf.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := write(buf, e); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			b, _ := json.Marshal(k)
			buf.Write(b)
			buf.WriteByte(':')
			if err := write(buf, x[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return errors.New("canonicaljson: unsupported type")
	}
	return nil
}

// Hash returns the SHA-256 of Marshal(v).
func Hash(v any) ([]byte, error) {
	enc, err := Marshal(v)
	if err != nil {
		return nil, err
	}
	return sha256Sum(enc), nil
}
