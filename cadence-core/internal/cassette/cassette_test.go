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
	if c1.Hash() != c2.Hash() {
		t.Fatal("hash should be insertion-order independent (sorted)")
	}
}
