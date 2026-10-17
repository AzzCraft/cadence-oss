// Package exactjson implements the new DAS JSON boundary. It does not change
// the historical canonicaljson encoding or any existing protected digest.
package exactjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strconv"
	"unicode/utf8"
)

const MaxBytes = 4 * 1024 * 1024
const MaxDepth = 64
const MaxNodes = 100000

// Only explicit requirement-catalog exchanges use this fixed larger budget.
// Other contracts keep MaxNodes, MaxBytes, MaxDepth and numeric limits.
const MaxCatalogNodes = 262144
const MaxNumberBytes = 512
const MaxSafeInteger int64 = 9007199254740991

// Parse preserves number lexemes until the application validates their domain.
// No case folding, defaults, Unicode repair, or duplicate-key overwrite occurs.
func Parse(data []byte) (any, error) {
	return parse(data, MaxNodes)
}

func ParseCatalog(data []byte) (any, error) {
	return parse(data, MaxCatalogNodes)
}

func parse(data []byte, nodeLimit int) (any, error) {
	if len(data) > MaxBytes || !utf8.Valid(data) || bytes.HasPrefix(data, []byte{0xef, 0xbb, 0xbf}) {
		return nil, errors.New("exactjson: invalid input encoding or size")
	}
	if err := validateStrings(data); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	nodes := 0
	v, err := read(dec, 0, &nodes, nodeLimit)
	if err != nil {
		return nil, err
	}
	if _, err = dec.Token(); err != io.EOF {
		return nil, errors.New("exactjson: trailing value or invalid JSON")
	}
	return v, nil
}

func read(dec *json.Decoder, depth int, nodes *int, nodeLimit int) (any, error) {
	*nodes++
	if depth > MaxDepth || *nodes > nodeLimit {
		return nil, errors.New("exactjson: structural limit exceeded")
	}
	token, err := dec.Token()
	if err != nil {
		return nil, errors.New("exactjson: malformed JSON")
	}
	if number, ok := token.(json.Number); ok {
		if len(number) > MaxNumberBytes || !boundedExponent(string(number)) {
			return nil, errors.New("exactjson: number limit exceeded")
		}
		return number, nil
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return token, nil
	}
	switch delim {
	case '{':
		object := map[string]any{}
		for dec.More() {
			*nodes++
			if *nodes > nodeLimit {
				return nil, errors.New("exactjson: structural limit exceeded")
			}
			keyToken, err := dec.Token()
			if err != nil {
				return nil, errors.New("exactjson: malformed object key")
			}
			key, ok := keyToken.(string)
			if !ok {
				return nil, errors.New("exactjson: object key is not a string")
			}
			if _, present := object[key]; present {
				return nil, errors.New("exactjson: duplicate decoded object key")
			}
			value, err := read(dec, depth+1, nodes, nodeLimit)
			if err != nil {
				return nil, err
			}
			object[key] = value
		}
		end, err := dec.Token()
		if err != nil || end != json.Delim('}') {
			return nil, errors.New("exactjson: incomplete object")
		}
		return object, nil
	case '[':
		array := []any{}
		for dec.More() {
			value, err := read(dec, depth+1, nodes, nodeLimit)
			if err != nil {
				return nil, err
			}
			array = append(array, value)
		}
		end, err := dec.Token()
		if err != nil || end != json.Delim(']') {
			return nil, errors.New("exactjson: incomplete array")
		}
		return array, nil
	default:
		return nil, errors.New("exactjson: unexpected delimiter")
	}
}

func boundedExponent(text string) bool {
	for i, char := range text {
		if char == 'e' || char == 'E' {
			exponent, err := strconv.ParseInt(text[i+1:], 10, 16)
			return err == nil && exponent >= -512 && exponent <= 512
		}
	}
	return true
}

// encoding/json replaces lone surrogate escapes. Inspect raw strings first so
// invalid input cannot become indistinguishable from a legitimate U+FFFD.
func validateStrings(data []byte) error {
	for i := 0; i < len(data); i++ {
		if data[i] != '"' {
			continue
		}
		i++
		for ; i < len(data) && data[i] != '"'; i++ {
			if data[i] != '\\' {
				continue
			}
			i++
			if i >= len(data) {
				return errors.New("exactjson: truncated escape")
			}
			if data[i] != 'u' {
				continue
			}
			unit, err := hexUnit(data, i+1)
			if err != nil {
				return err
			}
			i += 4
			if unit >= 0xdc00 && unit <= 0xdfff {
				return errors.New("exactjson: lone low surrogate")
			}
			if unit >= 0xd800 && unit <= 0xdbff {
				if i+6 >= len(data) || data[i+1] != '\\' || data[i+2] != 'u' {
					return errors.New("exactjson: lone high surrogate")
				}
				low, err := hexUnit(data, i+3)
				if err != nil || low < 0xdc00 || low > 0xdfff {
					return errors.New("exactjson: invalid surrogate pair")
				}
				i += 6
			}
		}
	}
	return nil
}

func hexUnit(data []byte, start int) (uint64, error) {
	if start+4 > len(data) {
		return 0, errors.New("exactjson: truncated Unicode escape")
	}
	value, err := strconv.ParseUint(string(data[start:start+4]), 16, 16)
	if err != nil {
		return 0, errors.New("exactjson: invalid Unicode escape")
	}
	return value, nil
}

// SafeInteger accepts mathematically integral numeric lexemes, including 1e0,
// while rejecting rounding and overflow. It must be used for counters/budgets.
func SafeInteger(value any) (int64, error) {
	text, ok := value.(json.Number)
	if !ok || len(text) > MaxNumberBytes {
		return 0, errors.New("exactjson: expected exact number")
	}
	// Bound the exponent before big.Rat allocates an enormous power of ten.
	for i, char := range string(text) {
		if char == 'e' || char == 'E' {
			exponent, err := strconv.ParseInt(string(text)[i+1:], 10, 16)
			if err != nil || exponent < -512 || exponent > 512 {
				return 0, errors.New("exactjson: numeric exponent limit")
			}
			break
		}
	}
	rat, ok := new(big.Rat).SetString(string(text))
	if !ok || !rat.IsInt() || !rat.Num().IsInt64() {
		return 0, errors.New("exactjson: number is not an exact safe integer")
	}
	result := rat.Num().Int64()
	if result < -MaxSafeInteger || result > MaxSafeInteger {
		return 0, errors.New("exactjson: integer outside safe range")
	}
	return result, nil
}

// Object requires an exact closed key set; optional keys are explicitly named.
func Object(value any, required, optional []string) (map[string]any, error) {
	object, ok := value.(map[string]any)
	if !ok {
		return nil, errors.New("exactjson: expected object")
	}
	allowed := map[string]bool{}
	for _, key := range optional {
		allowed[key] = true
	}
	for _, key := range required {
		allowed[key] = true
		if _, ok := object[key]; !ok {
			return nil, fmt.Errorf("exactjson: missing field %s", key)
		}
	}
	for key := range object {
		if !allowed[key] {
			return nil, errors.New("exactjson: unknown or incorrectly cased field")
		}
	}
	return object, nil
}
