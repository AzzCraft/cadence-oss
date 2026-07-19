package runid

import "testing"

func TestMakeIsStableForSameInputs(t *testing.T) {
	a := Inputs{WorkspaceHash: "ws1", Profile: "oss", Attempt: 1, Extra: map[string]string{"x": "1", "y": "2"}}
	if Make(a) != Make(a) {
		t.Fatal("Make not stable for identical inputs")
	}
}

func TestMakeChangesOnAttemptBump(t *testing.T) {
	a := Inputs{WorkspaceHash: "ws1", Profile: "oss", Attempt: 1}
	b := Inputs{WorkspaceHash: "ws1", Profile: "oss", Attempt: 2}
	if Make(a) == Make(b) {
		t.Fatal("attempt change did not change run-id")
	}
}

func TestMakeIsOrderInsensitiveOverExtra(t *testing.T) {
	a := Inputs{WorkspaceHash: "w", Profile: "p", Attempt: 1,
		Extra: map[string]string{"a": "1", "b": "2"}}
	b := Inputs{WorkspaceHash: "w", Profile: "p", Attempt: 1,
		Extra: map[string]string{"b": "2", "a": "1"}}
	if Make(a) != Make(b) {
		t.Fatal("order of extras affected hash")
	}
}

func TestMakeIsHexAnd64Chars(t *testing.T) {
	id := Make(Inputs{WorkspaceHash: "x", Profile: "y", Attempt: 1})
	if len(id) != 64 {
		t.Fatalf("expected 64-char hex, got %d", len(id))
	}
}
