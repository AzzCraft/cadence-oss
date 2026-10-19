package signing

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestHashPayload(t *testing.T) {
	hash := HashPayload([]byte("hello"))
	if hash[:7] != "sha256:" {
		t.Fatalf("expected sha256: prefix, got %s", hash)
	}
	if len(hash) != 7+64 {
		t.Fatalf("expected 71 char hash, got %d", len(hash))
	}
}

func TestSignVerify(t *testing.T) {
	key := []byte("test-key-12345")
	payload := "sha256:abcdef1234567890"
	sig := Sign(payload, key)
	if !Verify(payload, sig, key) {
		t.Fatal("expected verification to pass")
	}
	if Verify(payload, sig, []byte("wrong-key")) {
		t.Fatal("expected verification to fail with wrong key")
	}
	if Verify("sha256:different", sig, key) {
		t.Fatal("expected verification to fail with different payload")
	}
}

func TestEnvelopeCreateVerify(t *testing.T) {
	key := []byte("my-signing-key")
	payload := []byte(`{"runId": "test-123"}`)
	env := NewEnvelope("sig-001", "tester", payload, key)

	if env.Algorithm != "hmac-sha256" {
		t.Fatalf("expected hmac-sha256, got %s", env.Algorithm)
	}
	if env.PayloadHash[:7] != "sha256:" {
		t.Fatalf("expected sha256: prefix, got %s", env.PayloadHash)
	}
	if err := VerifyEnvelope(env, key); err != nil {
		t.Fatalf("expected envelope to verify: %v", err)
	}
	if err := VerifyEnvelope(env, []byte("wrong-key")); err == nil {
		t.Fatal("expected verification to fail with wrong key")
	}
}

func TestBundleSignatureVerify(t *testing.T) {
	key := []byte("my-signing-key")
	entries := map[string]string{
		"run-manifest.json":    "sha256:111",
		"pipeline-result.json": "sha256:222",
	}
	sig := NewBundleSignature("bundle-001", "tester", entries, key)
	if err := VerifyBundleSignature(sig, key); err != nil {
		t.Fatalf("expected bundle signature to verify: %v", err)
	}
	sig.Entries["pipeline-result.json"] = "sha256:tampered"
	if err := VerifyBundleSignature(sig, key); err == nil {
		t.Fatal("expected bundle signature verification to fail after tamper")
	}
}

func TestChainAppendVerify(t *testing.T) {
	chain := NewChain()
	s1 := chain.Append("step-1", "sha256:input1", "sha256:output1")
	s2 := chain.Append("step-2", "sha256:input2", "sha256:output2")

	if s1.StepIndex != 0 {
		t.Fatalf("expected step index 0, got %d", s1.StepIndex)
	}
	if s2.StepIndex != 1 {
		t.Fatalf("expected step index 1, got %d", s2.StepIndex)
	}
	if s2.PreviousHash != s1.ChainHash {
		t.Fatal("step 2 previousHash should equal step 1 chainHash")
	}

	err := VerifyChain(chain)
	if err != nil {
		t.Fatalf("chain verification failed: %v", err)
	}

	// Tamper with a step
	chain.Steps[0].ChainHash = "sha256:tampered"
	err = VerifyChain(chain)
	if err == nil {
		t.Fatal("expected tampered chain to fail verification")
	}
}

func TestEmptyChainVerifies(t *testing.T) {
	chain := NewChain()
	if err := VerifyChain(chain); err != nil {
		t.Fatalf("empty chain should verify: %v", err)
	}
}

func TestBuildKeyHierarchyFlat(t *testing.T) {
	kh := BuildKeyHierarchy("operator-local", "key-001")
	if kh.Depth != 1 {
		t.Fatalf("expected depth 1, got %d", kh.Depth)
	}
	if kh.LeafKeyID != "key-001" {
		t.Fatalf("expected leaf key-001, got %s", kh.LeafKeyID)
	}
	if kh.RootAnchor != "operator-local" {
		t.Fatalf("expected operator-local anchor, got %s", kh.RootAnchor)
	}
	if err := ValidateKeyHierarchy(kh); err != nil {
		t.Fatalf("flat hierarchy should validate: %v", err)
	}
}

func TestValidateKeyHierarchyRejectsEmpty(t *testing.T) {
	kh := KeyHierarchy{SchemaVersion: "1.0.0", Depth: 0}
	if err := ValidateKeyHierarchy(kh); err == nil {
		t.Fatal("expected error for empty hierarchy")
	}
}

func TestValidateKeyHierarchyDepthMismatch(t *testing.T) {
	kh := BuildKeyHierarchy("operator-local", "k")
	kh.Depth = 2
	if err := ValidateKeyHierarchy(kh); err == nil {
		t.Fatal("expected error for depth/level mismatch")
	}
}

func TestValidateKeyHierarchyLeafMismatch(t *testing.T) {
	kh := BuildKeyHierarchy("operator-local", "k")
	kh.LeafKeyID = "wrong"
	if err := ValidateKeyHierarchy(kh); err == nil {
		t.Fatal("expected error for leaf keyId mismatch")
	}
}

func TestPlanRotationValid(t *testing.T) {
	c, err := PlanRotation("key-old", "key-new", "ops-admin", "scheduled rotation")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.Status != "planned" {
		t.Fatalf("expected planned, got %s", c.Status)
	}
}

func TestPlanRotationRejectsSameKey(t *testing.T) {
	_, err := PlanRotation("key-a", "key-a", "admin", "test")
	if err == nil {
		t.Fatal("expected error for same key IDs")
	}
}

func TestExecuteRotationUpdatesLeaf(t *testing.T) {
	kh := BuildKeyHierarchy("operator-local", "leaf-key-1")
	oldLeaf := kh.LeafKeyID
	c, _ := PlanRotation(oldLeaf, "new-leaf-key", "admin", "rotate")
	kh2, err := ExecuteRotation(kh, c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if kh2.LeafKeyID != "new-leaf-key" {
		t.Fatal("leaf should be updated")
	}
	if c.Status != "completed" {
		t.Fatal("ceremony should be completed")
	}
}

func TestExecuteRotationRejectsWrongLeaf(t *testing.T) {
	kh := BuildKeyHierarchy("operator-local", "leaf-key-1")
	c, _ := PlanRotation("wrong-old", "new-key", "admin", "rotate")
	_, err := ExecuteRotation(kh, c)
	if err == nil {
		t.Fatal("expected error for mismatched leaf")
	}
}

func TestBuildKeyHierarchyUsesConfiguredAnchor(t *testing.T) {
	kh := BuildKeyHierarchy("hsm://tenant/root", "key-001")
	if kh.RootAnchor != "hsm://tenant/root" {
		t.Fatalf("expected configured anchor, got %s", kh.RootAnchor)
	}
	if kh.Levels[0].Anchor != "hsm://tenant/root" {
		t.Fatalf("expected level anchor to match root anchor, got %+v", kh.Levels[0])
	}
}

func TestBuildHSMAnchorDefaultSoftwareAnchor(t *testing.T) {
	anchor := BuildHSMAnchor("operator-local")
	if anchor.Provider != "software-hmac" {
		t.Fatalf("expected software-hmac provider, got %s", anchor.Provider)
	}
	if anchor.HardwareBacked {
		t.Fatal("expected local software anchor to be non-hardware-backed")
	}
	if anchor.Status != "active" {
		t.Fatalf("expected active anchor, got %s", anchor.Status)
	}
	if err := ValidateHSMAnchor(anchor); err != nil {
		t.Fatalf("expected valid anchor: %v", err)
	}
}

func TestConfiguredHSMURIProducesNoActiveAnchor(t *testing.T) {
	anchor := BuildHSMAnchor("hsm://synthetic/no-device")
	if anchor.Status != "" || anchor.HardwareBacked || anchor.Provider != "" {
		t.Fatal("configuration must not produce an active hardware claim")
	}
}

func TestValidateHSMAnchorRejectsMissingProvider(t *testing.T) {
	anchor := HSMAnchor{
		SchemaVersion: "1.0.0",
		AnchorID:      "operator-local",
		KeyURI:        "env:CADENCE_SIGNING_KEY",
		Attestation:   "software-hmac-active",
		Status:        "active",
	}
	if err := ValidateHSMAnchor(anchor); err == nil {
		t.Fatal("expected error for missing provider")
	}
}

// --- Governed signing tests ---

func TestEd25519SignerSignVerify(t *testing.T) {
	signer, err := NewEd25519Signer("key-ed25519-001", "cadence-core-team")
	if err != nil {
		t.Fatalf("NewEd25519Signer: %v", err)
	}
	if signer.Algorithm() != "ed25519" {
		t.Fatalf("expected ed25519, got %s", signer.Algorithm())
	}
	if signer.KeyID() != "key-ed25519-001" {
		t.Fatalf("expected key-ed25519-001, got %s", signer.KeyID())
	}
	if signer.Issuer() != "cadence-core-team" {
		t.Fatalf("expected cadence-core-team, got %s", signer.Issuer())
	}

	payload := "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
	sig, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !signer.Verify(payload, sig) {
		t.Fatal("expected verification to pass")
	}
	if signer.Verify("sha256:different", sig) {
		t.Fatal("expected verification to fail with different payload")
	}
}

func TestEd25519VerifierOnlyCannotSign(t *testing.T) {
	signer, _ := NewEd25519Signer("k1", "issuer")
	verifier := &Ed25519VerifierOnly{
		PublicKey: signer.PublicKey,
		ID:        "k1",
		IssuerID:  "issuer",
	}
	_, err := verifier.Sign("sha256:test")
	if err == nil {
		t.Fatal("expected error from verifier-only Sign")
	}

	payload := "sha256:abcdef1234567890"
	sig, _ := signer.Sign(payload)
	if !verifier.Verify(payload, sig) {
		t.Fatal("verifier should accept valid sig from matching key")
	}
}

func TestHMACSignerInterface(t *testing.T) {
	signer := &HMACSigner{Key: []byte("test-key"), ID: "hmac-001", IssuerID: "dev-team"}
	if signer.Algorithm() != "hmac-sha256" {
		t.Fatalf("expected hmac-sha256, got %s", signer.Algorithm())
	}
	if signer.KeyID() != "hmac-001" {
		t.Fatalf("expected hmac-001, got %s", signer.KeyID())
	}
	if signer.Issuer() != "dev-team" {
		t.Fatalf("expected dev-team, got %s", signer.Issuer())
	}

	payload := "sha256:testpayload"
	sig, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !signer.Verify(payload, sig) {
		t.Fatal("expected HMAC signer verify to pass")
	}
}

func TestGovernedEnvelopeEd25519(t *testing.T) {
	signer, _ := NewEd25519Signer("leaf-key-1", "cadence-oss-team")
	payload := []byte(`{"runId": "governed-001"}`)
	env, err := NewGovernedEnvelope("gov-sig-001", signer, "evidence", payload)
	if err != nil {
		t.Fatalf("NewGovernedEnvelope: %v", err)
	}
	if env.Algorithm != "ed25519" {
		t.Fatalf("expected ed25519, got %s", env.Algorithm)
	}
	if env.KeyID != "leaf-key-1" {
		t.Fatalf("expected leaf-key-1, got %s", env.KeyID)
	}
	if env.Issuer != "cadence-oss-team" {
		t.Fatalf("expected cadence-oss-team, got %s", env.Issuer)
	}
	if err := VerifyGovernedEnvelope(env, signer); err != nil {
		t.Fatalf("verification failed: %v", err)
	}

	// Wrong signer should fail
	other, _ := NewEd25519Signer("other-key", "other-issuer")
	if err := VerifyGovernedEnvelope(env, other); err == nil {
		t.Fatal("expected verification to fail with wrong signer")
	}
}

func TestGovernedEnvelopeHMAC(t *testing.T) {
	signer := &HMACSigner{Key: []byte("dev-key"), ID: "dev-001", IssuerID: "dev-team"}
	payload := []byte(`{"runId": "dev-001"}`)
	env, err := NewGovernedEnvelope("dev-sig-001", signer, "", payload)
	if err != nil {
		t.Fatalf("NewGovernedEnvelope: %v", err)
	}
	if env.Algorithm != "hmac-sha256" {
		t.Fatalf("expected hmac-sha256, got %s", env.Algorithm)
	}
	if err := VerifyGovernedEnvelope(env, signer); err != nil {
		t.Fatalf("verification failed: %v", err)
	}
}

func TestDetachedSignature(t *testing.T) {
	signer, _ := NewEd25519Signer("detach-key-1", "cadence-oss-team")
	payload := []byte(`{"manifest": "run-001"}`)
	sig, err := NewDetachedSignature("detach-sig-001", signer, "run-manifest.json", payload)
	if err != nil {
		t.Fatalf("NewDetachedSignature: %v", err)
	}
	if sig.PayloadRef != "run-manifest.json" {
		t.Fatalf("expected run-manifest.json, got %s", sig.PayloadRef)
	}
	if sig.KeyID != "detach-key-1" {
		t.Fatalf("expected detach-key-1, got %s", sig.KeyID)
	}

	if err := VerifyDetachedSignature(sig, signer, payload); err != nil {
		t.Fatalf("verification failed: %v", err)
	}

	// Tampered payload should fail
	if err := VerifyDetachedSignature(sig, signer, []byte("tampered")); err == nil {
		t.Fatal("expected failure on tampered payload")
	}
}

func TestDualLayerSignature(t *testing.T) {
	signer, _ := NewEd25519Signer("dual-key-1", "cadence-oss-team")
	manifest := []byte(`{"runId": "dual-001", "steps": ["build","test"]}`)
	entries := map[string]string{
		"run-manifest.json":    "sha256:aaa",
		"pipeline-result.json": "sha256:bbb",
	}
	dl, err := NewDualLayerSignature("dual-sig-001", signer, manifest, entries)
	if err != nil {
		t.Fatalf("NewDualLayerSignature: %v", err)
	}
	if dl.ManifestLayer.PayloadRole != "manifest" {
		t.Fatalf("expected manifest role, got %s", dl.ManifestLayer.PayloadRole)
	}
	if dl.BundleLayer.PayloadRole != "bundle" {
		t.Fatalf("expected bundle role, got %s", dl.BundleLayer.PayloadRole)
	}
	if err := VerifyDualLayerSignature(dl, signer); err != nil {
		t.Fatalf("verification failed: %v", err)
	}

	// Tamper with manifest layer
	dl2 := dl
	dl2.ManifestLayer.PayloadHash = "sha256:tampered"
	if err := VerifyDualLayerSignature(dl2, signer); err == nil {
		t.Fatal("expected failure on tampered manifest layer")
	}
}

func TestBuildGovernedKeyHierarchy(t *testing.T) {
	kh := BuildGovernedKeyHierarchy("hsm://tenant/root", "root-key", "intermediate-key", "leaf-key", "ed25519")
	if kh.Depth != 3 {
		t.Fatalf("expected depth 3, got %d", kh.Depth)
	}
	if kh.LeafKeyID != "leaf-key" {
		t.Fatalf("expected leaf-key, got %s", kh.LeafKeyID)
	}
	if kh.RootAnchor != "hsm://tenant/root" {
		t.Fatalf("expected hsm://tenant/root, got %s", kh.RootAnchor)
	}
	if kh.Levels[0].Role != "root" {
		t.Fatalf("expected root role, got %s", kh.Levels[0].Role)
	}
	if kh.Levels[1].Role != "intermediate" {
		t.Fatalf("expected intermediate role, got %s", kh.Levels[1].Role)
	}
	if kh.Levels[2].Role != "leaf" {
		t.Fatalf("expected leaf role, got %s", kh.Levels[2].Role)
	}
	if kh.Levels[1].IssuerKeyID != "root-key" {
		t.Fatalf("expected intermediate issuer = root-key, got %s", kh.Levels[1].IssuerKeyID)
	}
	if kh.Levels[2].IssuerKeyID != "intermediate-key" {
		t.Fatalf("expected leaf issuer = intermediate-key, got %s", kh.Levels[2].IssuerKeyID)
	}
	if err := ValidateKeyHierarchy(kh); err != nil {
		t.Fatalf("governed hierarchy should validate: %v", err)
	}
}

func TestConfiguredGovernedURIProducesNoActiveAnchor(t *testing.T) {
	anchor := BuildGovernedAnchor("hsm://synthetic/no-device")
	if anchor.Status != "" || anchor.HardwareBacked || anchor.Provider != "" {
		t.Fatal("configuration must not produce an active hardware claim")
	}
}

func TestBuildGovernedAnchorSoftware(t *testing.T) {
	anchor := BuildGovernedAnchor("")
	if anchor.Status != "active" {
		t.Fatalf("expected active, got %s", anchor.Status)
	}
	if anchor.Provider != "software-ed25519" {
		t.Fatalf("expected software-ed25519, got %s", anchor.Provider)
	}
	if anchor.HardwareBacked {
		t.Fatal("expected non-hardware-backed for software anchor")
	}
	if err := ValidateHSMAnchor(anchor); err != nil {
		t.Fatalf("software governed anchor should validate: %v", err)
	}
}

func TestSelectSignerDev(t *testing.T) {
	t.Setenv("CADENCE_SIGNING_MODE", "dev")
	signer, err := SelectSigner("k1", "issuer", []byte("key"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if signer.Algorithm() != "hmac-sha256" {
		t.Fatalf("expected hmac-sha256, got %s", signer.Algorithm())
	}
}

func TestDecodeKeyMaterialPreservesRawFileWhitespaceBytes(t *testing.T) {
	raw := make([]byte, ed25519.PrivateKeySize)
	for i := range raw {
		raw[i] = byte(i + 1)
	}
	raw[0] = '\n'
	raw[len(raw)-1] = ' '

	decoded, err := decodeKeyMaterial(raw, true)
	if err != nil {
		t.Fatalf("decodeKeyMaterial returned error: %v", err)
	}
	if !bytes.Equal(decoded, raw) {
		t.Fatal("raw key file bytes were trimmed or changed")
	}
}

func TestSelectSignerGoverned(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	keyPath := filepath.Join(t.TempDir(), "governed.key")
	if err := os.WriteFile(keyPath, priv, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	t.Setenv("CADENCE_SIGNING_MODE", "governed")
	t.Setenv("CADENCE_GOVERNED_SIGNING_PRIVATE_KEY_FILE", keyPath)
	signer, err := SelectSigner("k1", "issuer", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if signer.Algorithm() != "ed25519" {
		t.Fatalf("expected ed25519, got %s", signer.Algorithm())
	}
	payloadHash := HashPayload([]byte("governed-mode"))
	signature, err := signer.Sign(payloadHash)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	verifier := NewEd25519SignerFromKeys(pub, priv, "k1", "issuer")
	if !verifier.Verify(payloadHash, signature) {
		t.Fatal("expected governed signer output to verify")
	}
}

func TestSelectSignerInvalid(t *testing.T) {
	t.Setenv("CADENCE_SIGNING_MODE", "invalid")
	_, err := SelectSigner("k1", "issuer", nil)
	if err == nil {
		t.Fatal("expected error for invalid signing mode")
	}
}

func TestSelectSignerGovernedExternalCommand(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	payloadHash := HashPayload([]byte("external-command-payload"))
	signature := hex.EncodeToString(ed25519.Sign(priv, []byte(payloadHash)))
	scriptPath := filepath.Join(t.TempDir(), "signer.sh")
	script := "#!/bin/sh\nif [ \"$1\" = \"" + payloadHash + "\" ]; then\n  printf '%s\\n' '" + signature + "'\n  exit 0\nfi\nexit 1\n"
	if err := os.WriteFile(scriptPath, []byte(script), 0o755); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	t.Setenv("CADENCE_SIGNING_MODE", "governed")
	t.Setenv("CADENCE_GOVERNED_SIGNER_COMMAND", scriptPath)
	t.Setenv("CADENCE_GOVERNED_SIGNING_PUBLIC_KEY", hex.EncodeToString(pub))

	signer, err := SelectSigner("k1", "issuer", nil)
	if err != nil {
		t.Fatalf("SelectSigner: %v", err)
	}
	got, err := signer.Sign(payloadHash)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if got != signature {
		t.Fatalf("signature = %q, want %q", got, signature)
	}
	if !signer.Verify(payloadHash, got) {
		t.Fatal("expected external-command signature to verify")
	}
}
