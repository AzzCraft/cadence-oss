package dsse

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func signEnvelope(payload []byte, payloadType string, private ed25519.PrivateKey) map[string]any {
	pae, _ := PAE(payloadType, payload)
	return map[string]any{"payloadType": payloadType, "payload": base64.StdEncoding.EncodeToString(payload), "signatures": []any{map[string]any{"sig": base64.StdEncoding.EncodeToString(ed25519.Sign(private, pae)), "keyid": "untrusted hint"}}}
}
func verifyValue(value map[string]any, keys []Key, threshold int) (Result, error) {
	data, _ := json.Marshal(value)
	return Verify(data, "application/vnd.das.test.v1+json", "issuer", "action_authorizer", keys, threshold)
}
func TestPAEIndependentKnownAnswerAndUTF8ByteLength(t *testing.T) {
	actual, err := PAE("http://example.com/HelloWorld", []byte("hello world"))
	if err != nil || string(actual) != "DSSEv1 29 http://example.com/HelloWorld 11 hello world" {
		t.Fatal(err, string(actual))
	}
	actual, err = PAE("é", []byte("汉"))
	if err != nil || string(actual) != "DSSEv1 2 é 3 汉" {
		t.Fatal(err, string(actual))
	}
}
func TestExactPayloadAndNativeExtensionRules(t *testing.T) {
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32))
	public := private.Public().(ed25519.PublicKey)
	payload := []byte(" {\"b\":2,\"a\":1}\n")
	envelope := signEnvelope(payload, "application/vnd.das.test.v1+json", private)
	envelope["futureExtension"] = true
	envelope["signatures"].([]any)[0].(map[string]any)["futureExtension"] = true
	keys := []Key{{public, "approver", "issuer", []string{"action_authorizer"}}}
	result, err := verifyValue(envelope, keys, 1)
	if err != nil || !bytes.Equal(result.Payload, payload) {
		t.Fatal(err)
	}
	envelope["payload"] = base64.URLEncoding.EncodeToString(payload)
	if _, err = verifyValue(envelope, keys, 1); err != nil {
		t.Fatal(err)
	}
	envelope["payload"] = base64.StdEncoding.EncodeToString([]byte("{\"a\":1,\"b\":2}"))
	if _, err = verifyValue(envelope, keys, 1); err == nil {
		t.Fatal("verified rearranged payload bytes")
	}
}
func TestUniqueKeysAndIndependentPrincipals(t *testing.T) {
	p1 := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32))
	p2 := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, 32))
	keys := []Key{{p1.Public().(ed25519.PublicKey), "one", "issuer", []string{"action_authorizer"}}, {p2.Public().(ed25519.PublicKey), "two", "issuer", []string{"action_authorizer"}}}
	envelope := signEnvelope([]byte("payload"), "application/vnd.das.test.v1+json", p1)
	signature := envelope["signatures"].([]any)[0]
	envelope["signatures"] = []any{signature, signature}
	if _, err := verifyValue(envelope, keys, 2); err == nil {
		t.Fatal("counted duplicate signature twice")
	}
	second := signEnvelope([]byte("payload"), "application/vnd.das.test.v1+json", p2)
	envelope["signatures"] = []any{signature, second["signatures"].([]any)[0]}
	if _, err := verifyValue(envelope, keys, 2); err != nil {
		t.Fatal(err)
	}
	keys[1].Principal = "one"
	if _, err := verifyValue(envelope, keys, 2); err == nil {
		t.Fatal("counted one principal as two independent approvals")
	}
	keys[1].Principal = "two"
	keys[1].Issuer = "other"
	if _, err := verifyValue(envelope, keys, 2); err == nil {
		t.Fatal("wrong issuer approved")
	}
	keys[1].Issuer = "issuer"
	keys[1].Roles = []string{"evidence_signer"}
	if _, err := verifyValue(envelope, keys, 2); err == nil {
		t.Fatal("wrong role approved")
	}
}
func TestMalformedBoundaries(t *testing.T) {
	p := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32))
	keys := []Key{{p.Public().(ed25519.PublicKey), "one", "issuer", []string{"action_authorizer"}}}
	for _, kind := range []string{"type", "signature", "base64", "missing", "empty", "too-many", "wrong-key"} {
		t.Run(kind, func(t *testing.T) {
			envelope := signEnvelope([]byte("payload"), "application/vnd.das.test.v1+json", p)
			switch kind {
			case "type":
				envelope["payloadType"] = "application/vnd.das.verification-evidence.v1+json"
			case "signature":
				envelope["signatures"].([]any)[0].(map[string]any)["sig"] = base64.StdEncoding.EncodeToString(make([]byte, 64))
			case "base64":
				envelope["payload"] = "YQ==\n"
			case "missing":
				delete(envelope, "payload")
			case "empty":
				envelope["signatures"] = []any{}
			case "too-many":
				envelope["signatures"] = make([]any, 33)
			case "wrong-key":
				other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, 32))
				envelope = signEnvelope([]byte("payload"), "application/vnd.das.test.v1+json", other)
			}
			if _, err := verifyValue(envelope, keys, 1); err == nil {
				t.Fatal("malformed envelope accepted")
			}
		})
	}
	data := []byte(`{"payloadType":"a","payloadType":"b","payload":"","signatures":[]}`)
	if _, err := Verify(data, "a", "issuer", "action_authorizer", keys, 1); err == nil {
		t.Fatal("duplicate key accepted")
	}
	if _, err := Decode(strings.Repeat("a", 100), 10); err == nil {
		t.Fatal("base64 size bypass")
	}
}

func TestUntrustedKeyHintsNeverRetrieveOrChangeProtocolTrust(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Write([]byte(`{"TEST":"unapproved remote key"}`))
	}))
	defer server.Close()
	// Establish that this harmless endpoint is genuinely reachable on the host.
	response, err := http.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32))
	keys := []Key{{private.Public().(ed25519.PublicKey), "TEST-fixed-approver", "issuer", []string{"action_authorizer"}}}
	for _, fault := range []string{"none", "foreign-key", "other-purpose", "wrong-role", "wrong-key-type", "jwt-is-not-dsse"} {
		t.Run(fault, func(t *testing.T) {
			envelope := signEnvelope([]byte("TEST exact native payload"), "application/vnd.das.test.v1+json", private)
			if fault == "foreign-key" {
				envelope = signEnvelope([]byte("TEST exact native payload"), "application/vnd.das.test.v1+json", ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32)))
			}
			envelope["jku"], envelope["x5u"], envelope["alg"] = server.URL+"/key", server.URL+"/certificate", "none"
			envelope["signatures"].([]any)[0].(map[string]any)["keyid"] = "../../TEST-control?" + server.URL
			selected := append([]Key(nil), keys...)
			if fault == "other-purpose" {
				envelope["payloadType"] = "application/vnd.das.verification-evidence.v1+json"
			} else if fault == "wrong-role" {
				selected[0].Roles = []string{"evidence_issuer"}
			} else if fault == "wrong-key-type" {
				selected[0].Public = []byte("TEST not an Ed25519 public key")
			}
			var result Result
			var err error
			if fault == "jwt-is-not-dsse" {
				result, err = Verify([]byte("eyJhbGciOiJub25lIn0.e30."), "application/vnd.das.test.v1+json", "issuer", "action_authorizer", selected, 1)
			} else {
				result, err = verifyValue(envelope, selected, 1)
			}
			if (fault == "none") != (err == nil) {
				t.Fatal("native protocol/purpose/trust mismatch", result, err)
			}
			if fault == "none" && (len(result.Principals) != 1 || result.Principals[0] != "TEST-fixed-approver") {
				t.Fatal("untrusted hints selected another principal", result)
			}
			if requests.Load() != 1 {
				t.Fatal("untrusted key hint caused external retrieval")
			}
		})
	}
}
