package canonicaljson

import (
	"crypto/sha256"
	"encoding/hex"
)

const TaskCAD002 = "CAD-002"

func sha256Sum(b []byte) []byte {
	s := sha256.Sum256(b)
	return s[:]
}

// CanonicalHash returns a sha256-prefixed digest of canonical JSON.
func CanonicalHash(v any) (string, error) {
	b, err := Marshal(v)
	if err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(sha256Sum(b)), nil
}
