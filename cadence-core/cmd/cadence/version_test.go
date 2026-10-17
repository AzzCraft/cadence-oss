package main

import (
	"os"
	"strings"
	"testing"
)

func TestEmbeddedVersionMatchesItsSingleAuthor(t *testing.T) {
	source, err := os.ReadFile("../../../VERSION")
	if err != nil {
		t.Fatal(err)
	}
	if releaseVersion() != strings.TrimSpace(string(source)) {
		t.Fatal("stale embedded VERSION; run tools/generate_build_identity.py")
	}
}

func TestVersionIdentityIsIndependentOfWorkingDirectory(t *testing.T) {
	before := versionIdentity()
	dir := t.TempDir()
	if err := os.WriteFile(dir+"/VERSION", []byte("999.0.0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(old)
	after := versionIdentity()
	if after["releaseVersion"] != before["releaseVersion"] || after["binarySha256"] != before["binarySha256"] {
		t.Fatal("identity depends on caller cwd")
	}
	if after["binarySha256"] == "" {
		t.Fatal("binary digest missing")
	}
}
