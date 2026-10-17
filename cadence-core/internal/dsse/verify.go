// Package dsse verifies protocol bytes. Signature validity alone grants no
// application authority. Trust configuration is supplied by the control plane.
package dsse

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/AzzCraft/cadence-oss/cadence-core/internal/exactjson"
)

const MaxPayload = 1024 * 1024
const MaxKeys = 32
const MaxSignatures = 32

type Key struct {
	Public    ed25519.PublicKey
	Principal string
	Issuer    string
	Roles     []string
}

type Result struct {
	Payload         []byte
	Principals      []string
	KeyFingerprints []string
	Issuer          string
}

// PAE operates on exact payload bytes, including whitespace and trailing LF.
func PAE(payloadType string, payload []byte) ([]byte, error) {
	if !utf8.ValidString(payloadType) || payloadType == "" || len(payloadType) > 256 || len(payload) > MaxPayload {
		return nil, errors.New("dsse: type/payload bounds")
	}
	prefix := fmt.Sprintf("DSSEv1 %d %s %d ", len([]byte(payloadType)), payloadType, len(payload))
	return append([]byte(prefix), payload...), nil
}

func Fingerprint(key ed25519.PublicKey) string {
	digest := sha256.Sum256(key)
	return fmt.Sprintf("sha256:%x", digest)
}

// Decode accepts both protocol base64 alphabets. Whitespace, mixed alphabets,
// padding errors and noncanonical unused bits fail; keyid is never authority.
func Decode(value string, max int) ([]byte, error) {
	if len(value) > (max+2)/3*4 || strings.ContainsAny(value, " \r\n\t") ||
		(strings.ContainsAny(value, "+/") && strings.ContainsAny(value, "-_")) {
		return nil, errors.New("dsse: invalid base64")
	}
	encoding := base64.StdEncoding.Strict()
	if strings.ContainsAny(value, "-_") {
		encoding = base64.URLEncoding.Strict()
	}
	if !strings.Contains(value, "=") {
		encoding = encoding.WithPadding(base64.NoPadding)
	}
	data, err := encoding.DecodeString(value)
	if err != nil || len(data) > max {
		return nil, errors.New("dsse: invalid base64")
	}
	return data, nil
}

// Verify implements unique-key threshold verification and additionally enforces
// distinct approved principals. Envelope extensions are ignored as DSSE defines;
// the application payload has its own closed contract. Parsing happens once.
func Verify(data []byte, payloadType, issuer, role string, keys []Key, threshold int) (Result, error) {
	var empty Result
	if len(keys) == 0 || len(keys) > MaxKeys || threshold < 1 || threshold > len(keys) || issuer == "" || role == "" {
		return empty, errors.New("dsse: invalid trust policy")
	}
	seen := map[string]bool{}
	eligible := []Key{}
	for _, key := range keys {
		if len(key.Public) != ed25519.PublicKeySize || key.Principal == "" || key.Issuer == "" {
			return empty, errors.New("dsse: invalid trusted key")
		}
		fingerprint := Fingerprint(key.Public)
		if seen[fingerprint] {
			return empty, errors.New("dsse: duplicate trusted key identity")
		}
		seen[fingerprint] = true
		allowedRole := false
		for _, value := range key.Roles {
			if value == role {
				allowedRole = true
			}
		}
		if key.Issuer == issuer && allowedRole {
			eligible = append(eligible, key)
		}
	}
	value, err := exactjson.Parse(data)
	if err != nil {
		return empty, err
	}
	envelope, ok := value.(map[string]any)
	if !ok {
		return empty, errors.New("dsse: envelope must be object")
	}
	actualType, ok := envelope["payloadType"].(string)
	if !ok || actualType != payloadType {
		return empty, errors.New("dsse: wrong payload type")
	}
	encoded, ok := envelope["payload"].(string)
	if !ok {
		return empty, errors.New("dsse: missing payload")
	}
	payload, err := Decode(encoded, MaxPayload)
	if err != nil {
		return empty, err
	}
	pae, err := PAE(actualType, payload)
	if err != nil {
		return empty, err
	}
	signatures, ok := envelope["signatures"].([]any)
	if !ok || len(signatures) == 0 || len(signatures) > MaxSignatures {
		return empty, errors.New("dsse: signature bounds")
	}
	acceptedKeys, principals := map[string]bool{}, map[string]bool{}
	for _, entry := range signatures {
		signature, ok := entry.(map[string]any)
		if !ok {
			return empty, errors.New("dsse: signature must be object")
		}
		if hint, exists := signature["keyid"]; exists {
			text, valid := hint.(string)
			if !valid || len(text) > 256 {
				return empty, errors.New("dsse: invalid keyid hint")
			}
		}
		encoded, ok := signature["sig"].(string)
		if !ok {
			return empty, errors.New("dsse: missing signature")
		}
		raw, err := Decode(encoded, ed25519.SignatureSize)
		if err != nil {
			return empty, err
		}
		for _, key := range eligible {
			if ed25519.Verify(key.Public, pae, raw) {
				acceptedKeys[Fingerprint(key.Public)] = true
				principals[key.Principal] = true
			}
		}
	}
	if len(acceptedKeys) < threshold || len(principals) < threshold {
		return empty, errors.New("dsse: independent approval threshold not met")
	}
	result := Result{Payload: append([]byte(nil), payload...), Issuer: issuer}
	for key := range acceptedKeys {
		result.KeyFingerprints = append(result.KeyFingerprints, key)
	}
	for principal := range principals {
		result.Principals = append(result.Principals, principal)
	}
	sort.Strings(result.KeyFingerprints)
	sort.Strings(result.Principals)
	return result, nil
}
