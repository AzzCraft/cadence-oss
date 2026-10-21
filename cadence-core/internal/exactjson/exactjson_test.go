package exactjson

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestCatalogBudgetDoesNotChangeGenericBoundsOrDigestBytes(t *testing.T) {
	raw := []byte("[" + strings.Repeat("null,", MaxNodes-1) + "null]")
	if _, err := Parse(raw); err == nil {
		t.Fatal("default parser accepted more than its original node limit")
	}
	value, err := ParseCatalog(raw)
	if err != nil {
		t.Fatal("explicit catalog profile rejected bounded input", err)
	}
	if _, err := Canonical(value); err == nil {
		t.Fatal("default canonicalizer lost its original bound")
	}
	encoded, err := CanonicalCatalog(value)
	if err != nil || string(encoded) != string(raw) {
		t.Fatal("catalog profile changed JCS bytes", err)
	}
	tooMany := []byte("[" + strings.Repeat("null,", MaxCatalogNodes-1) + "null]")
	if _, err := ParseCatalog(tooMany); err == nil {
		t.Fatal("catalog profile is unbounded")
	}
	if _, err := CanonicalCatalog(make([]any, MaxCatalogNodes)); err == nil {
		t.Fatal("catalog encoding is unbounded")
	}
	sample, _ := Parse([]byte(`{"a":["<value>",1,true,null]}`))
	first, _ := Digest(sample)
	second, err := DigestCatalog(sample)
	if err != nil || first != second {
		t.Fatal("catalog budget altered a semantic digest", err)
	}
	for _, invalid := range []string{`{"a":1,"a":2}`, `"\ud800"`, `1e10000`,
		strings.Repeat("[", 65) + "0" + strings.Repeat("]", 65), strings.Repeat(" ", MaxBytes+1)} {
		if _, err := ParseCatalog([]byte(invalid)); err == nil {
			t.Fatal("catalog profile relaxed another boundary")
		}
	}
}

func TestIndependentKnownAnswerVectors(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "cadence-protocol", "fixtures", "das_v1_5", "exact_json_vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Cases []struct {
			ID, Input, Canonical string
			Reject               bool
		}
	}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors.Cases) < 20 {
		t.Fatal("missing governed vectors")
	}
	for _, vector := range vectors.Cases {
		t.Run(vector.ID, func(t *testing.T) {
			value, err := Parse([]byte(vector.Input))
			var actual []byte
			if err == nil {
				actual, err = Canonical(value)
			}
			if vector.Reject {
				if err == nil {
					t.Fatal("invalid vector accepted")
				}
				return
			}
			if err != nil || string(actual) != vector.Canonical {
				t.Fatalf("got %q, %v; want %q", actual, err, vector.Canonical)
			}
		})
	}
}

func TestExactIntegerLexemes(t *testing.T) {
	for _, text := range []string{"1", "1.0", "1e0", "-0", "9007199254740991.0"} {
		value, err := Parse([]byte(text))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := SafeInteger(value); err != nil {
			t.Fatalf("legal integer %s: %v", text, err)
		}
	}
	for _, text := range []string{"0.00000000000000000001", "9007199254740991.1", "9007199254740993", "1e10000", "true", "null", "\"1\""} {
		value, err := Parse([]byte(text))
		if err != nil {
			continue
		}
		if _, err := SafeInteger(value); err == nil {
			t.Fatalf("inexact integer accepted: %s", text)
		}
	}
}

func TestStructuralAndUnicodeLimits(t *testing.T) {
	for _, data := range [][]byte{[]byte(strings.Repeat("[", 65) + "0" + strings.Repeat("]", 65)), []byte{0xef, 0xbb, 0xbf, '0'}, []byte{'"', 0xff, '"'}, []byte(strings.Repeat(" ", MaxBytes+1))} {
		if _, err := Parse(data); err == nil {
			t.Fatal("invalid input accepted")
		}
	}
	if _, err := Canonical(math.NaN()); err == nil {
		t.Fatal("NaN accepted")
	}
	if _, err := Canonical(math.Inf(1)); err == nil {
		t.Fatal("Infinity accepted")
	}
}

func TestRFC8785AppendixB(t *testing.T) {
	// Independent IEEE 754 known answers from RFC 8785 Appendix B.
	vectors := map[string]string{
		"0000000000000000": "0", "8000000000000000": "0", "0000000000000001": "5e-324", "8000000000000001": "-5e-324",
		"7fefffffffffffff": "1.7976931348623157e+308", "ffefffffffffffff": "-1.7976931348623157e+308",
		"4340000000000000": "9007199254740992", "c340000000000000": "-9007199254740992", "4430000000000000": "295147905179352830000",
		"44b52d02c7e14af5": "9.999999999999997e+22", "44b52d02c7e14af6": "1e+23", "44b52d02c7e14af7": "1.0000000000000001e+23",
		"444b1ae4d6e2ef4e": "999999999999999700000", "444b1ae4d6e2ef4f": "999999999999999900000", "444b1ae4d6e2ef50": "1e+21",
		"3eb0c6f7a0b5ed8c": "9.999999999999997e-7", "3eb0c6f7a0b5ed8d": "0.000001",
		"41b3de4355555553": "333333333.3333332", "41b3de4355555554": "333333333.33333325", "41b3de4355555555": "333333333.3333333",
		"41b3de4355555556": "333333333.3333334", "41b3de4355555557": "333333333.33333343", "becbf647612f3696": "-0.0000033333333333333333", "43143ff3c1cb0959": "1424953923781206.2",
	}
	for bits, want := range vectors {
		parsed, err := strconv.ParseUint(bits, 16, 64)
		if err != nil {
			t.Fatal(err)
		}
		out, err := Canonical(math.Float64frombits(parsed))
		if err != nil || string(out) != want {
			t.Fatalf("%s: %s %v want %s", bits, out, err, want)
		}
	}
}

func TestCanonicalNumberRoundTrip(t *testing.T) {
	for _, input := range []string{"1e3", "1e16", "9007199254740992.0", "1e21", "-1e16", "-9007199254740992", "9007199254740991", "295147905179352830000"} {
		value, err := Parse([]byte(input))
		if err != nil {
			t.Fatal(err)
		}
		first, err := Canonical(value)
		if err != nil {
			t.Fatalf("%s: %v", input, err)
		}
		reread, err := Parse(first)
		if err != nil {
			t.Fatal(err)
		}
		second, err := Canonical(reread)
		if err != nil || string(first) != string(second) {
			t.Fatalf("%s: %s -> %s (%v)", input, first, second, err)
		}
	}
	for _, input := range []string{"9007199254740993", "-9007199254740993"} {
		value, _ := Parse([]byte(input))
		if _, err := Canonical(value); err == nil {
			t.Fatal("rounded", input)
		}
	}
}
