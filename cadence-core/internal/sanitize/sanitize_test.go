package sanitize

import (
	"strings"
	"testing"
)

func TestStringScrubs(t *testing.T) {
	in := "user alice@example.com Bearer abcd1234efgh5678 path /Users/username/work id 550e8400-e29b-41d4-a716-446655440000"
	out := String(in)
	for _, banned := range []string{"alice@example.com", "abcd1234efgh5678", "/Users/username", "550e8400-e29b-41d4-a716-446655440000"} {
		if strings.Contains(out, banned) {
			t.Fatalf("output still contains %q: %s", banned, out)
		}
	}
	for _, expected := range []string{"<email>", "<token>", "<home>", "<uuid>"} {
		if !strings.Contains(out, expected) {
			t.Fatalf("output missing %q: %s", expected, out)
		}
	}
}

func TestMapRedactsSecretKeys(t *testing.T) {
	in := map[string]any{
		"user":     "alice@example.com",
		"password": "hunter2",
		"meta": map[string]any{
			"apiKey": "deadbeef",
			"note":   "contact bob@x.com",
		},
		"items": []any{"hi", map[string]any{"token": "leak", "ok": 1}},
	}
	out := Map(in).(map[string]any)
	if out["password"] != "<redacted>" {
		t.Fatal("password not redacted")
	}
	if out["user"] != "<email>" {
		t.Fatalf("email not scrubbed: %v", out["user"])
	}
	meta := out["meta"].(map[string]any)
	if meta["apiKey"] != "<redacted>" {
		t.Fatal("apiKey not redacted")
	}
	if !strings.Contains(meta["note"].(string), "<email>") {
		t.Fatal("nested email not scrubbed")
	}
	items := out["items"].([]any)
	first := items[1].(map[string]any)
	if first["token"] != "<redacted>" {
		t.Fatal("nested token not redacted")
	}
}

func TestMapPreservesNonStrings(t *testing.T) {
	in := map[string]any{"n": 42, "b": true, "n2": nil}
	out := Map(in).(map[string]any)
	if out["n"] != 42 || out["b"] != true || out["n2"] != nil {
		t.Fatalf("non-string types altered: %v", out)
	}
}
