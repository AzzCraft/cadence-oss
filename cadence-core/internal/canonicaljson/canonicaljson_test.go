package canonicaljson

import (
	"bytes"
	"testing"
)

func TestKeysAreSorted(t *testing.T) {
	a, _ := Marshal(map[string]any{"b": 1, "a": 2})
	if string(a) != `{"a":2,"b":1}` {
		t.Fatalf("not sorted: %s", a)
	}
}

func TestSemanticallyEqualMapsHashEqual(t *testing.T) {
	o1 := map[string]any{"a": 1, "b": []any{int64(2), "x"}}
	o2 := map[string]any{"b": []any{int64(2), "x"}, "a": 1}
	h1, err := Hash(o1)
	if err != nil {
		t.Fatal(err)
	}
	h2, err := Hash(o2)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(h1, h2) {
		t.Fatal("equivalent maps produced different hashes")
	}
}

func TestStringEscaping(t *testing.T) {
	out, _ := Marshal("a\"b")
	if string(out) != `"a\"b"` {
		t.Fatalf("escape wrong: %s", out)
	}
}

func TestRejectsNaN(t *testing.T) {
	nan := 0.0
	nan = nan / nan
	_, err := Marshal(nan)
	if err == nil {
		t.Fatal("expected error for NaN")
	}
}

func TestNestedDeterministic(t *testing.T) {
	v := map[string]any{
		"outer": map[string]any{"z": 1, "a": 2, "m": map[string]any{"y": "y", "x": "x"}},
	}
	a, _ := Marshal(v)
	b, _ := Marshal(v)
	if !bytes.Equal(a, b) {
		t.Fatal("non-deterministic across calls")
	}
	expect := `{"outer":{"a":2,"m":{"x":"x","y":"y"},"z":1}}`
	if string(a) != expect {
		t.Fatalf("got %s want %s", a, expect)
	}
}
