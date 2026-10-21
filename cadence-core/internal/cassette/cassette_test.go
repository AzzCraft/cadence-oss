package cassette

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestRecordReplayRoundTrip(t *testing.T) {
	c := &Cassette{}
	c.Record(Interaction{Method: "GET", URL: "https://x/y", Status: 200, RespBody: "hi"})
	c.Record(Interaction{Method: "POST", URL: "https://x/z", Body: "p", Status: 201})

	got, err := c.Next("GET", "https://x/y")
	if err != nil || got.RespBody != "hi" {
		t.Fatalf("first replay: %v %+v", err, got)
	}
	got, err = c.Next("POST", "https://x/z")
	if err != nil || got.Status != 201 {
		t.Fatalf("second replay: %v %+v", err, got)
	}
}

func TestNextNoMatch(t *testing.T) {
	c := &Cassette{}
	c.Record(Interaction{Method: "GET", URL: "https://a"})
	if _, err := c.Next("POST", "https://a"); !errors.Is(err, ErrNoMatch) {
		t.Fatal("expected no-match")
	}
}

func TestSaveAndLoad(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "c.json")
	orig := &Cassette{}
	orig.Record(Interaction{Method: "GET", URL: "https://x", Status: 200})
	if err := orig.Save(p); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Interactions) != 1 || loaded.Interactions[0].URL != "https://x" {
		t.Fatalf("round-trip lost data: %+v", loaded)
	}
}

func TestHashIsStable(t *testing.T) {
	c1 := &Cassette{}
	c1.Record(Interaction{Method: "GET", URL: "https://b"})
	c1.Record(Interaction{Method: "GET", URL: "https://a"})
	c2 := &Cassette{}
	c2.Record(Interaction{Method: "GET", URL: "https://a"})
	c2.Record(Interaction{Method: "GET", URL: "https://b"})
	if c1.Hash() == c2.Hash() {
		t.Fatal("different replay order must have different versioned identities")
	}
}

func TestOrderedIdentityMatchesReplaySemantics(t *testing.T) {
	a := Interaction{Method: "GET", URL: "https://example.invalid/a", RespBody: "a", Headers: map[string]string{"B": "2", "A": "1"}}
	b := Interaction{Method: "GET", URL: "https://example.invalid/b", RespBody: "b"}
	first, second := &Cassette{}, &Cassette{}
	first.Record(a)
	first.Record(b)
	second.Record(b)
	second.Record(a)
	if first.Hash() == second.Hash() {
		t.Fatal("different replay order has same identity")
	}
	if first.Hash() != first.Hash() {
		t.Fatal("unstable ordered hash")
	}
	if _, err := first.Next(a.Method, a.URL); err != nil {
		t.Fatal(err)
	}
	if _, err := second.Next(a.Method, a.URL); err != nil {
		t.Fatal(err)
	}
	if _, err := first.Next(b.Method, b.URL); err != nil {
		t.Fatal(err)
	}
	if _, err := second.Next(b.Method, b.URL); err != ErrNoMatch {
		t.Fatal("expected ordered consumption difference", err)
	}
	path := filepath.Join(t.TempDir(), "cassette.json")
	if err := first.Save(path); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil || loaded.Hash() != first.Hash() {
		t.Fatal("save/load identity changed", err)
	}
	duplicate := &Cassette{}
	duplicate.Record(a)
	a.RespBody = "second"
	duplicate.Record(a)
	one, _ := duplicate.Next(a.Method, a.URL)
	two, _ := duplicate.Next(a.Method, a.URL)
	if one.RespBody != "a" || two.RespBody != "second" {
		t.Fatal("duplicate request order changed")
	}
}
