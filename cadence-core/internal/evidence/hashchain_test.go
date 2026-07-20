package evidence

import (
	"strings"
	"testing"
)

func TestAppendAndVerifyChain(t *testing.T) {
	e0, err := Append(nil, map[string]any{"event": "init"})
	if err != nil {
		t.Fatal(err)
	}
	if e0.Index != 0 || e0.PrevHash != Genesis {
		t.Fatalf("genesis fields wrong: %+v", e0)
	}
	e1, err := Append(&e0, map[string]any{"event": "claim", "task": "T-001"})
	if err != nil {
		t.Fatal(err)
	}
	if e1.PrevHash != e0.Hash {
		t.Fatalf("prevHash not chained")
	}
	e2, err := Append(&e1, map[string]any{"event": "verify"})
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyChain([]Entry{e0, e1, e2}); err != nil {
		t.Fatalf("intact chain failed verify: %v", err)
	}
}

func TestVerifyChainDetectsTamper(t *testing.T) {
	e0, _ := Append(nil, map[string]any{"event": "init"})
	e1, _ := Append(&e0, map[string]any{"event": "x"})
	e1.Payload["event"] = "tampered"
	err := VerifyChain([]Entry{e0, e1})
	if err == nil {
		t.Fatal("expected tamper detection, got nil")
	}
	if !strings.Contains(err.Error(), "hash mismatch") {
		t.Fatalf("wrong error: %v", err)
	}
}

func TestVerifyChainDetectsReorder(t *testing.T) {
	e0, _ := Append(nil, map[string]any{"event": "a"})
	e1, _ := Append(&e0, map[string]any{"event": "b"})
	err := VerifyChain([]Entry{e1, e0}) // reversed
	if err == nil {
		t.Fatal("expected reorder detection")
	}
}

func TestCanonicalSortsKeys(t *testing.T) {
	a, _ := canonical(map[string]any{"b": 1, "a": 2})
	expect := `{"a":2,"b":1}`
	if string(a) != expect {
		t.Fatalf("canonical not stable: got %s want %s", string(a), expect)
	}
}
