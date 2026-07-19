package signing

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"
)

// Signer abstracts signing operations. HMAC signers are used in dev mode;
// Ed25519 signers are used in governed/production mode.
type Signer interface {
	// Sign produces a hex-encoded signature for the given payload hash.
	Sign(payloadHash string) (string, error)
	// Verify checks a hex-encoded signature against the payload hash.
	Verify(payloadHash string, signature string) bool
	// Algorithm returns the signing algorithm identifier.
	Algorithm() string
	// KeyID returns the key identifier for this signer.
	KeyID() string
	// Issuer returns the issuer identity for this signer.
	Issuer() string
}

// HMACSigner implements the Signer interface using HMAC-SHA256 (dev mode).
type HMACSigner struct {
	Key      []byte
	ID       string
	IssuerID string
}

func (s *HMACSigner) Sign(payloadHash string) (string, error) {
	mac := hmac.New(sha256.New, s.Key)
	mac.Write([]byte(payloadHash))
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func (s *HMACSigner) Verify(payloadHash string, signature string) bool {
	expected, _ := s.Sign(payloadHash)
	return hmac.Equal([]byte(expected), []byte(signature))
}

func (s *HMACSigner) Algorithm() string { return "hmac-sha256" }
func (s *HMACSigner) KeyID() string     { return s.ID }
func (s *HMACSigner) Issuer() string    { return s.IssuerID }

// Ed25519Signer implements the Signer interface using Ed25519 (governed mode).
type Ed25519Signer struct {
	PrivateKey ed25519.PrivateKey
	PublicKey  ed25519.PublicKey
	ID         string
	IssuerID   string
}

func NewEd25519Signer(keyID, issuer string) (*Ed25519Signer, error) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, fmt.Errorf("ed25519: key generation failed: %w", err)
	}
	return &Ed25519Signer{
		PrivateKey: priv,
		PublicKey:  pub,
		ID:         keyID,
		IssuerID:   issuer,
	}, nil
}

func NewEd25519SignerFromKeys(pub ed25519.PublicKey, priv ed25519.PrivateKey, keyID, issuer string) *Ed25519Signer {
	return &Ed25519Signer{
		PrivateKey: priv,
		PublicKey:  pub,
		ID:         keyID,
		IssuerID:   issuer,
	}
}

func (s *Ed25519Signer) Sign(payloadHash string) (string, error) {
	sig := ed25519.Sign(s.PrivateKey, []byte(payloadHash))
	return hex.EncodeToString(sig), nil
}

func (s *Ed25519Signer) Verify(payloadHash string, signature string) bool {
	sigBytes, err := hex.DecodeString(signature)
	if err != nil {
		return false
	}
	return ed25519.Verify(s.PublicKey, []byte(payloadHash), sigBytes)
}

func (s *Ed25519Signer) Algorithm() string { return "ed25519" }
func (s *Ed25519Signer) KeyID() string     { return s.ID }
func (s *Ed25519Signer) Issuer() string    { return s.IssuerID }

// Ed25519VerifierOnly wraps only a public key for verification without signing.
type Ed25519VerifierOnly struct {
	PublicKey ed25519.PublicKey
	ID        string
	IssuerID  string
}

func (v *Ed25519VerifierOnly) Sign(_ string) (string, error) {
	return "", errors.New("ed25519: verifier-only cannot sign")
}

func (v *Ed25519VerifierOnly) Verify(payloadHash string, signature string) bool {
	sigBytes, err := hex.DecodeString(signature)
	if err != nil {
		return false
	}
	return ed25519.Verify(v.PublicKey, []byte(payloadHash), sigBytes)
}

func (v *Ed25519VerifierOnly) Algorithm() string { return "ed25519" }
func (v *Ed25519VerifierOnly) KeyID() string     { return v.ID }
func (v *Ed25519VerifierOnly) Issuer() string    { return v.IssuerID }

// ExternalCommandSigner delegates signing to an operator-provided command while
// retaining local verification against a configured Ed25519 public key. This is
// the concrete integration path for HSM/KMS wrapper binaries.
type ExternalCommandSigner struct {
	Command     []string
	Verifier    *Ed25519VerifierOnly
	ID          string
	IssuerID    string
	AlgorithmID string
}

func NewExternalCommandSigner(command []string, verifier *Ed25519VerifierOnly, keyID, issuer string) (*ExternalCommandSigner, error) {
	if len(command) == 0 {
		return nil, errors.New("external signer: command is required")
	}
	if verifier == nil || len(verifier.PublicKey) == 0 {
		return nil, errors.New("external signer: verifier/public key is required")
	}
	return &ExternalCommandSigner{
		Command:     append([]string(nil), command...),
		Verifier:    verifier,
		ID:          keyID,
		IssuerID:    issuer,
		AlgorithmID: verifier.Algorithm(),
	}, nil
}

func (s *ExternalCommandSigner) Sign(payloadHash string) (string, error) {
	cmd := exec.Command(s.Command[0], append(s.Command[1:], payloadHash)...)
	cmd.Env = append(
		os.Environ(),
		"CADENCE_PAYLOAD_HASH="+payloadHash,
		"CADENCE_KEY_ID="+s.ID,
		"CADENCE_ISSUER="+s.IssuerID,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("external signer command failed: %w: %s", err, strings.TrimSpace(string(out)))
	}
	signature := strings.TrimSpace(string(out))
	if signature == "" {
		return "", errors.New("external signer command returned empty signature")
	}
	return signature, nil
}

func (s *ExternalCommandSigner) Verify(payloadHash string, signature string) bool {
	if s.Verifier == nil {
		return false
	}
	return s.Verifier.Verify(payloadHash, signature)
}

func (s *ExternalCommandSigner) Algorithm() string { return s.AlgorithmID }
func (s *ExternalCommandSigner) KeyID() string     { return s.ID }
func (s *ExternalCommandSigner) Issuer() string    { return s.IssuerID }

// GovernedEnvelope is a signing envelope with full key identity and issuer
// metadata. It supports both HMAC (dev) and Ed25519 (governed) algorithms.
type GovernedEnvelope struct {
	SchemaVersion string `json:"schemaVersion"`
	SignatureID   string `json:"signatureId"`
	Algorithm     string `json:"algorithm"`
	KeyID         string `json:"keyId"`
	Issuer        string `json:"issuer"`
	PayloadHash   string `json:"payloadHash"`
	PayloadRole   string `json:"payloadRole,omitempty"`
	Signature     string `json:"signature"`
}

// NewGovernedEnvelope creates a signed envelope using the given Signer.
func NewGovernedEnvelope(signatureID string, signer Signer, payloadRole string, payload []byte) (GovernedEnvelope, error) {
	return NewGovernedEnvelopeForHash(signatureID, signer, payloadRole, HashPayload(payload))
}

// NewGovernedEnvelopeForHash creates a signed envelope from a pre-computed hash.
func NewGovernedEnvelopeForHash(signatureID string, signer Signer, payloadRole string, payloadHash string) (GovernedEnvelope, error) {
	sig, err := signer.Sign(payloadHash)
	if err != nil {
		return GovernedEnvelope{}, err
	}
	return GovernedEnvelope{
		SchemaVersion: "1.0.0",
		SignatureID:   signatureID,
		Algorithm:     signer.Algorithm(),
		KeyID:         signer.KeyID(),
		Issuer:        signer.Issuer(),
		PayloadHash:   payloadHash,
		PayloadRole:   payloadRole,
		Signature:     sig,
	}, nil
}

// VerifyGovernedEnvelope checks that the governed envelope signature is valid.
func VerifyGovernedEnvelope(env GovernedEnvelope, signer Signer) error {
	if env.Algorithm != signer.Algorithm() {
		return fmt.Errorf("algorithm mismatch: envelope has %s, signer uses %s", env.Algorithm, signer.Algorithm())
	}
	if !signer.Verify(env.PayloadHash, env.Signature) {
		return errors.New("governed envelope: signature verification failed")
	}
	return nil
}

// DetachedSignature represents a signature stored separately from its payload,
// supporting offline verification of evidence artifacts.
type DetachedSignature struct {
	SchemaVersion string `json:"schemaVersion"`
	SignatureID   string `json:"signatureId"`
	Algorithm     string `json:"algorithm"`
	KeyID         string `json:"keyId"`
	Issuer        string `json:"issuer"`
	PayloadHash   string `json:"payloadHash"`
	PayloadRef    string `json:"payloadRef"`
	Signature     string `json:"signature"`
}

// NewDetachedSignature creates a detached signature for a payload file.
func NewDetachedSignature(signatureID string, signer Signer, payloadRef string, payload []byte) (DetachedSignature, error) {
	payloadHash := HashPayload(payload)
	sig, err := signer.Sign(payloadHash)
	if err != nil {
		return DetachedSignature{}, err
	}
	return DetachedSignature{
		SchemaVersion: "1.0.0",
		SignatureID:   signatureID,
		Algorithm:     signer.Algorithm(),
		KeyID:         signer.KeyID(),
		Issuer:        signer.Issuer(),
		PayloadHash:   payloadHash,
		PayloadRef:    payloadRef,
		Signature:     sig,
	}, nil
}

// VerifyDetachedSignature checks a detached signature against payload data.
func VerifyDetachedSignature(sig DetachedSignature, signer Signer, payload []byte) error {
	if sig.Algorithm != signer.Algorithm() {
		return fmt.Errorf("algorithm mismatch: signature has %s, signer uses %s", sig.Algorithm, signer.Algorithm())
	}
	actualHash := HashPayload(payload)
	if actualHash != sig.PayloadHash {
		return fmt.Errorf("payload hash mismatch: expected %s, got %s", sig.PayloadHash, actualHash)
	}
	if !signer.Verify(sig.PayloadHash, sig.Signature) {
		return errors.New("detached signature: verification failed")
	}
	return nil
}

// DualLayerSignature provides two-layer signing: a manifest-level envelope
// and a bundle-level envelope, supporting independent verification of each layer.
type DualLayerSignature struct {
	SchemaVersion string           `json:"schemaVersion"`
	ManifestLayer GovernedEnvelope `json:"manifestLayer"`
	BundleLayer   GovernedEnvelope `json:"bundleLayer"`
	DualHash      string           `json:"dualHash"`
	DualSignature string           `json:"dualSignature"`
}

// NewDualLayerSignature creates a two-layer signature. The manifest layer signs
// the manifest payload; the bundle layer signs the bundle hash of all entries;
// and the dual signature covers the concatenation of both.
func NewDualLayerSignature(signatureID string, signer Signer, manifest []byte, entries map[string]string) (DualLayerSignature, error) {
	manifestEnv, err := NewGovernedEnvelope(signatureID+"-manifest", signer, "manifest", manifest)
	if err != nil {
		return DualLayerSignature{}, err
	}
	bundleHash := BundleHash(entries)
	bundleEnv, err := NewGovernedEnvelopeForHash(signatureID+"-bundle", signer, "bundle", bundleHash)
	if err != nil {
		return DualLayerSignature{}, err
	}
	dualHash := HashPayload([]byte(manifestEnv.PayloadHash + ":" + bundleEnv.PayloadHash))
	dualSig, err := signer.Sign(dualHash)
	if err != nil {
		return DualLayerSignature{}, err
	}
	return DualLayerSignature{
		SchemaVersion: "1.0.0",
		ManifestLayer: manifestEnv,
		BundleLayer:   bundleEnv,
		DualHash:      dualHash,
		DualSignature: dualSig,
	}, nil
}

// VerifyDualLayerSignature verifies both layers and the dual binding signature.
func VerifyDualLayerSignature(dl DualLayerSignature, signer Signer) error {
	if err := VerifyGovernedEnvelope(dl.ManifestLayer, signer); err != nil {
		return fmt.Errorf("manifest layer: %w", err)
	}
	if err := VerifyGovernedEnvelope(dl.BundleLayer, signer); err != nil {
		return fmt.Errorf("bundle layer: %w", err)
	}
	expectedDualHash := HashPayload([]byte(dl.ManifestLayer.PayloadHash + ":" + dl.BundleLayer.PayloadHash))
	if expectedDualHash != dl.DualHash {
		return errors.New("dual layer: dualHash mismatch")
	}
	if !signer.Verify(dl.DualHash, dl.DualSignature) {
		return errors.New("dual layer: dual signature verification failed")
	}
	return nil
}

// SelectSigner returns an HMAC signer for dev mode and an Ed25519 signer for
// governed/production mode. The mode is determined by the CADENCE_SIGNING_MODE
// environment variable ("dev" or "governed").
func SelectSigner(keyID, issuer string, hmacKey []byte) (Signer, error) {
	mode := strings.TrimSpace(os.Getenv("CADENCE_SIGNING_MODE"))
	if mode == "" {
		mode = "dev"
	}
	switch mode {
	case "dev":
		return &HMACSigner{Key: hmacKey, ID: keyID, IssuerID: issuer}, nil
	case "governed":
		return loadConfiguredGovernedSigner(keyID, issuer)
	default:
		return nil, fmt.Errorf("unsupported signing mode %q (expected dev or governed)", mode)
	}
}

func loadConfiguredGovernedSigner(keyID, issuer string) (Signer, error) {
	if commandText := strings.TrimSpace(os.Getenv("CADENCE_GOVERNED_SIGNER_COMMAND")); commandText != "" {
		verifier, err := loadConfiguredGovernedVerifier(keyID, issuer)
		if err != nil {
			return nil, fmt.Errorf("governed signer command requires configured verifier/public key: %w", err)
		}
		return NewExternalCommandSigner(strings.Fields(commandText), verifier, keyID, issuer)
	}
	publicKey, privateKey, err := loadConfiguredEd25519Keys()
	if err != nil {
		return nil, err
	}
	if len(privateKey) == 0 {
		return nil, errors.New("governed signing private key is required unless CADENCE_GOVERNED_SIGNER_COMMAND is configured")
	}
	return NewEd25519SignerFromKeys(publicKey, privateKey, keyID, issuer), nil
}

func loadConfiguredGovernedVerifier(keyID, issuer string) (*Ed25519VerifierOnly, error) {
	publicKey, _, err := loadConfiguredEd25519Keys()
	if err != nil {
		return nil, err
	}
	return &Ed25519VerifierOnly{PublicKey: publicKey, ID: keyID, IssuerID: issuer}, nil
}

func loadConfiguredEd25519Keys() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	privateKey, privateErr := loadConfiguredEd25519PrivateKey()
	publicKey, publicErr := loadConfiguredEd25519PublicKey()

	if privateErr != nil && publicErr != nil {
		return nil, nil, fmt.Errorf(
			"governed signing requires either CADENCE_GOVERNED_SIGNING_PRIVATE_KEY(_FILE) or CADENCE_GOVERNED_SIGNING_PUBLIC_KEY(_FILE): %v; %v",
			privateErr,
			publicErr,
		)
	}
	if privateErr == nil && len(publicKey) == 0 {
		publicKey = privateKey.Public().(ed25519.PublicKey)
	}
	if len(publicKey) == 0 {
		return nil, nil, fmt.Errorf("governed signing public key unavailable: %w", publicErr)
	}
	if privateErr != nil {
		return publicKey, nil, nil
	}
	return publicKey, privateKey, nil
}

func loadConfiguredEd25519PrivateKey() (ed25519.PrivateKey, error) {
	material, fromFile, err := loadKeyMaterial(
		strings.TrimSpace(os.Getenv("CADENCE_GOVERNED_SIGNING_PRIVATE_KEY")),
		strings.TrimSpace(os.Getenv("CADENCE_GOVERNED_SIGNING_PRIVATE_KEY_FILE")),
	)
	if err != nil {
		return nil, err
	}
	decoded, err := decodeKeyMaterial(material, fromFile)
	if err != nil {
		return nil, err
	}
	switch len(decoded) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(decoded), nil
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(decoded), nil
	default:
		return nil, fmt.Errorf("governed signing private key must decode to %d-byte seed or %d-byte private key, got %d bytes", ed25519.SeedSize, ed25519.PrivateKeySize, len(decoded))
	}
}

func loadConfiguredEd25519PublicKey() (ed25519.PublicKey, error) {
	material, fromFile, err := loadKeyMaterial(
		strings.TrimSpace(os.Getenv("CADENCE_GOVERNED_SIGNING_PUBLIC_KEY")),
		strings.TrimSpace(os.Getenv("CADENCE_GOVERNED_SIGNING_PUBLIC_KEY_FILE")),
	)
	if err != nil {
		return nil, err
	}
	decoded, err := decodeKeyMaterial(material, fromFile)
	if err != nil {
		return nil, err
	}
	if len(decoded) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("governed signing public key must decode to %d bytes, got %d bytes", ed25519.PublicKeySize, len(decoded))
	}
	return ed25519.PublicKey(decoded), nil
}

func loadKeyMaterial(inlineValue string, filePath string) ([]byte, bool, error) {
	if filePath != "" {
		data, err := os.ReadFile(filePath)
		if err != nil {
			return nil, false, fmt.Errorf("read key file %q: %w", filePath, err)
		}
		return data, true, nil
	}
	if inlineValue != "" {
		return []byte(inlineValue), false, nil
	}
	return nil, false, errors.New("key material not configured")
}

func decodeKeyMaterial(raw []byte, preferRaw bool) ([]byte, error) {
	if preferRaw && (len(raw) == ed25519.PublicKeySize || len(raw) == ed25519.PrivateKeySize || len(raw) == ed25519.SeedSize) {
		return append([]byte(nil), raw...), nil
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil, errors.New("key material is empty")
	}
	if preferRaw && (len(trimmed) == ed25519.PublicKeySize || len(trimmed) == ed25519.PrivateKeySize || len(trimmed) == ed25519.SeedSize) {
		return append([]byte(nil), trimmed...), nil
	}
	if decoded, err := hex.DecodeString(string(trimmed)); err == nil {
		return decoded, nil
	}
	if decoded, err := base64.StdEncoding.DecodeString(string(trimmed)); err == nil {
		return decoded, nil
	}
	if decoded, err := base64.RawStdEncoding.DecodeString(string(trimmed)); err == nil {
		return decoded, nil
	}
	if len(trimmed) == ed25519.PublicKeySize || len(trimmed) == ed25519.PrivateKeySize || len(trimmed) == ed25519.SeedSize {
		return append([]byte(nil), trimmed...), nil
	}
	return nil, errors.New("key material must be raw 32/64-byte data, hex, or base64")
}

type Envelope struct {
	SchemaVersion string `json:"schemaVersion"`
	SignatureID   string `json:"signatureId"`
	Algorithm     string `json:"algorithm"`
	Signer        string `json:"signer"`
	PayloadHash   string `json:"payloadHash"`
	PayloadRole   string `json:"payloadRole,omitempty"`
	Signature     string `json:"signature,omitempty"`
}

type BundleSignature struct {
	SchemaVersion string            `json:"schemaVersion"`
	SignatureID   string            `json:"signatureId"`
	Algorithm     string            `json:"algorithm"`
	Signer        string            `json:"signer"`
	BundleHash    string            `json:"bundleHash"`
	Entries       map[string]string `json:"entries"`
	Signature     string            `json:"signature"`
}

// StepHash represents one link in the step hash chain.
type StepHash struct {
	StepIndex    int    `json:"stepIndex"`
	StepID       string `json:"stepId"`
	InputHash    string `json:"inputHash"`
	OutputHash   string `json:"outputHash"`
	PreviousHash string `json:"previousHash"`
	ChainHash    string `json:"chainHash"`
}

// Chain accumulates step hashes into a verifiable chain.
type Chain struct {
	Steps []StepHash `json:"steps"`
}

func Load(path string) (Envelope, error) {
	var envelope Envelope
	data, err := os.ReadFile(path)
	if err != nil {
		return envelope, err
	}
	err = json.Unmarshal(data, &envelope)
	return envelope, err
}

// HashPayload returns "sha256:<hex>" for the given bytes.
func HashPayload(data []byte) string {
	h := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(h[:])
}

// Sign creates an HMAC-SHA256 signature of payloadHash using the given key.
func Sign(payloadHash string, key []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(payloadHash))
	return hex.EncodeToString(mac.Sum(nil))
}

// Verify checks that the HMAC-SHA256 signature matches the payloadHash.
func Verify(payloadHash string, signature string, key []byte) bool {
	expected := Sign(payloadHash, key)
	return hmac.Equal([]byte(expected), []byte(signature))
}

// NewEnvelope creates a signed envelope for the given payload.
func NewEnvelope(signatureID, signer string, payload []byte, key []byte) Envelope {
	return NewEnvelopeForHash(signatureID, signer, "", HashPayload(payload), key)
}

func NewEnvelopeForHash(signatureID, signer, payloadRole, payloadHash string, key []byte) Envelope {
	sig := Sign(payloadHash, key)
	return Envelope{
		SchemaVersion: "1.0.0",
		SignatureID:   signatureID,
		Algorithm:     "hmac-sha256",
		Signer:        signer,
		PayloadHash:   payloadHash,
		PayloadRole:   payloadRole,
		Signature:     sig,
	}
}

func BundleHash(entries map[string]string) string {
	keys := make([]string, 0, len(entries))
	for key := range entries {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	h := sha256.New()
	for _, key := range keys {
		h.Write([]byte(key))
		h.Write([]byte{0})
		h.Write([]byte(entries[key]))
		h.Write([]byte{'\n'})
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

func NewBundleSignature(signatureID, signer string, entries map[string]string, key []byte) BundleSignature {
	bundleHash := BundleHash(entries)
	return BundleSignature{
		SchemaVersion: "1.0.0",
		SignatureID:   signatureID,
		Algorithm:     "hmac-sha256",
		Signer:        signer,
		BundleHash:    bundleHash,
		Entries:       entries,
		Signature:     Sign(bundleHash, key),
	}
}

func VerifyBundleSignature(sig BundleSignature, key []byte) error {
	if sig.Algorithm != "hmac-sha256" {
		return fmt.Errorf("unsupported algorithm: %s", sig.Algorithm)
	}
	expectedHash := BundleHash(sig.Entries)
	if expectedHash != sig.BundleHash {
		return errors.New("bundle hash verification failed")
	}
	if !Verify(sig.BundleHash, sig.Signature, key) {
		return errors.New("bundle signature verification failed")
	}
	return nil
}

// VerifyEnvelope checks that the envelope signature is valid against the given key.
func VerifyEnvelope(env Envelope, key []byte) error {
	if env.Algorithm != "hmac-sha256" {
		return fmt.Errorf("unsupported algorithm: %s", env.Algorithm)
	}
	if !Verify(env.PayloadHash, env.Signature, key) {
		return errors.New("signature verification failed")
	}
	return nil
}

// NewChain creates an empty step hash chain.
func NewChain() *Chain {
	return &Chain{}
}

// Append adds a step to the chain, computing the chained hash from the
// previous chain hash concatenated with the step's input and output hashes.
func (c *Chain) Append(stepID string, inputHash, outputHash string) StepHash {
	prevHash := "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	if len(c.Steps) > 0 {
		prevHash = c.Steps[len(c.Steps)-1].ChainHash
	}
	combined := prevHash + ":" + inputHash + ":" + outputHash
	h := sha256.Sum256([]byte(combined))
	chainHash := "sha256:" + hex.EncodeToString(h[:])

	step := StepHash{
		StepIndex:    len(c.Steps),
		StepID:       stepID,
		InputHash:    inputHash,
		OutputHash:   outputHash,
		PreviousHash: prevHash,
		ChainHash:    chainHash,
	}
	c.Steps = append(c.Steps, step)
	return step
}

// VerifyChain validates the integrity of the step hash chain.
func VerifyChain(chain *Chain) error {
	for i, step := range chain.Steps {
		expectedPrev := "sha256:0000000000000000000000000000000000000000000000000000000000000000"
		if i > 0 {
			expectedPrev = chain.Steps[i-1].ChainHash
		}
		if step.PreviousHash != expectedPrev {
			return fmt.Errorf("step %d: previousHash mismatch", i)
		}
		combined := step.PreviousHash + ":" + step.InputHash + ":" + step.OutputHash
		h := sha256.Sum256([]byte(combined))
		expected := "sha256:" + hex.EncodeToString(h[:])
		if step.ChainHash != expected {
			return fmt.Errorf("step %d: chainHash mismatch", i)
		}
	}
	return nil
}

// Save writes an envelope to disk as JSON.
func Save(path string, env Envelope) error {
	data, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

func SaveBundle(path string, sig BundleSignature) error {
	data, err := json.MarshalIndent(sig, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

// KeyHierarchyLevel describes one level in a signing key chain-of-trust.
type KeyHierarchyLevel struct {
	Level       int    `json:"level"`
	Role        string `json:"role"`
	Algorithm   string `json:"algorithm"`
	KeyID       string `json:"keyId"`
	IssuerKeyID string `json:"issuerKeyId,omitempty"`
	Anchor      string `json:"anchor"`
}

// KeyHierarchy represents the full signing key chain-of-trust from root anchor
// to leaf signing key.
type KeyHierarchy struct {
	SchemaVersion string              `json:"schemaVersion"`
	Depth         int                 `json:"depth"`
	Levels        []KeyHierarchyLevel `json:"levels"`
	LeafKeyID     string              `json:"leafKeyId"`
	RootAnchor    string              `json:"rootAnchor"`
}

// HSMAnchor records the declared root-anchor path for current signing
// operations. Emitted anchors are active evidence records for software, HSM,
// or KMS providers.
type HSMAnchor struct {
	SchemaVersion  string `json:"schemaVersion"`
	AnchorID       string `json:"anchorId"`
	Provider       string `json:"provider"`
	KeyURI         string `json:"keyUri"`
	Attestation    string `json:"attestation"`
	HardwareBacked bool   `json:"hardwareBacked"`
	Status         string `json:"status"`
}

// BuildKeyHierarchy constructs a signing key hierarchy evidence structure.
// In the current HMAC-based signing model, the hierarchy is flat (depth 1):
// a single operator-managed key serves as both root and leaf. As the platform
// evolves toward HSM-backed or PKI-based signing, this depth will grow.
func BuildKeyHierarchy(rootAnchor, keyID string) KeyHierarchy {
	anchor := strings.TrimSpace(rootAnchor)
	if anchor == "" {
		anchor = "operator-local"
	}
	return KeyHierarchy{
		SchemaVersion: "1.0.0",
		Depth:         1,
		Levels: []KeyHierarchyLevel{
			{
				Level:     0,
				Role:      "root-and-leaf",
				Algorithm: "hmac-sha256",
				KeyID:     keyID,
				Anchor:    anchor,
			},
		},
		LeafKeyID:  keyID,
		RootAnchor: anchor,
	}
}

// BuildGovernedKeyHierarchy constructs a multi-depth key hierarchy with
// root → intermediate → leaf levels. This is the production/governed signing
// model supporting Ed25519 or HSM-backed keys.
func BuildGovernedKeyHierarchy(rootAnchor string, rootKeyID string, intermediateKeyID string, leafKeyID string, algorithm string) KeyHierarchy {
	anchor := strings.TrimSpace(rootAnchor)
	if anchor == "" {
		anchor = "operator-local"
	}
	if algorithm == "" {
		algorithm = "ed25519"
	}
	return KeyHierarchy{
		SchemaVersion: "1.0.0",
		Depth:         3,
		Levels: []KeyHierarchyLevel{
			{
				Level:     0,
				Role:      "root",
				Algorithm: algorithm,
				KeyID:     rootKeyID,
				Anchor:    anchor,
			},
			{
				Level:       1,
				Role:        "intermediate",
				Algorithm:   algorithm,
				KeyID:       intermediateKeyID,
				IssuerKeyID: rootKeyID,
				Anchor:      anchor,
			},
			{
				Level:       2,
				Role:        "leaf",
				Algorithm:   algorithm,
				KeyID:       leafKeyID,
				IssuerKeyID: intermediateKeyID,
				Anchor:      anchor,
			},
		},
		LeafKeyID:  leafKeyID,
		RootAnchor: anchor,
	}
}

// BuildHSMAnchor creates the current root-anchor evidence record.
func BuildHSMAnchor(rootAnchor string) HSMAnchor {
	anchorID := strings.TrimSpace(rootAnchor)
	if anchorID == "" {
		anchorID = "operator-local"
	}
	anchor := HSMAnchor{
		SchemaVersion: "1.0.0",
		AnchorID:      anchorID,
		Status:        "active",
	}
	switch {
	case strings.HasPrefix(anchorID, "hsm://"):
		anchor.Provider = "hsm"
		anchor.KeyURI = anchorID
		anchor.Attestation = "external-hsm-anchor-active"
		anchor.HardwareBacked = true
	case strings.HasPrefix(anchorID, "kms://"):
		anchor.Provider = "kms"
		anchor.KeyURI = anchorID
		anchor.Attestation = "external-kms-anchor-active"
		anchor.HardwareBacked = true
	default:
		anchor.Provider = "software-hmac"
		anchor.KeyURI = "env:CADENCE_SIGNING_KEY"
		anchor.Attestation = "software-hmac-active"
		anchor.HardwareBacked = false
	}
	return anchor
}

// BuildGovernedAnchor creates an active anchor for governed signing mode.
func BuildGovernedAnchor(rootAnchor string) HSMAnchor {
	anchorID := strings.TrimSpace(rootAnchor)
	if anchorID == "" {
		anchorID = "software-ed25519"
	}
	anchor := HSMAnchor{
		SchemaVersion: "1.0.0",
		AnchorID:      anchorID,
		Status:        "active",
	}
	switch {
	case strings.HasPrefix(anchorID, "hsm://"):
		anchor.Provider = "hsm"
		anchor.KeyURI = anchorID
		anchor.Attestation = "external-hsm-anchor-active"
		anchor.HardwareBacked = true
	case strings.HasPrefix(anchorID, "kms://"):
		anchor.Provider = "kms"
		anchor.KeyURI = anchorID
		anchor.Attestation = "external-kms-anchor-active"
		anchor.HardwareBacked = true
	default:
		anchor.Provider = "software-ed25519"
		anchor.KeyURI = "env:CADENCE_SIGNING_KEY"
		anchor.Attestation = "software-ed25519-active"
		anchor.HardwareBacked = false
	}
	return anchor
}

// ValidateHSMAnchor checks that the anchor evidence record is internally
// consistent and has enough information for downstream audit tools.
func ValidateHSMAnchor(anchor HSMAnchor) error {
	if anchor.SchemaVersion == "" {
		return errors.New("hsm anchor: schemaVersion is required")
	}
	if strings.TrimSpace(anchor.AnchorID) == "" {
		return errors.New("hsm anchor: anchorId is required")
	}
	if strings.TrimSpace(anchor.Provider) == "" {
		return errors.New("hsm anchor: provider is required")
	}
	if strings.TrimSpace(anchor.KeyURI) == "" {
		return errors.New("hsm anchor: keyUri is required")
	}
	if strings.TrimSpace(anchor.Attestation) == "" {
		return errors.New("hsm anchor: attestation is required")
	}
	if anchor.Status != "active" {
		return fmt.Errorf("hsm anchor: unsupported status %q", anchor.Status)
	}
	if anchor.HardwareBacked && anchor.Provider == "software-hmac" {
		return errors.New("hsm anchor: hardware-backed anchors cannot use software-hmac provider")
	}
	return nil
}

// ValidateKeyHierarchy checks that a key hierarchy is well-formed: depth
// matches level count, levels are in order, and leaf/root references are
// consistent.
func ValidateKeyHierarchy(kh KeyHierarchy) error {
	if kh.Depth != len(kh.Levels) {
		return fmt.Errorf("depth %d does not match level count %d", kh.Depth, len(kh.Levels))
	}
	if kh.Depth == 0 {
		return errors.New("key hierarchy must have at least one level")
	}
	for i, level := range kh.Levels {
		if level.Level != i {
			return fmt.Errorf("level %d: expected index %d", level.Level, i)
		}
		if i > 0 && level.IssuerKeyID == "" {
			return fmt.Errorf("level %d: non-root level must have issuerKeyId", i)
		}
	}
	if kh.Levels[0].KeyID != kh.Levels[0].KeyID {
		return errors.New("root level keyId inconsistent")
	}
	if kh.Levels[kh.Depth-1].KeyID != kh.LeafKeyID {
		return errors.New("leaf keyId does not match last level")
	}
	if kh.Levels[0].Anchor != kh.RootAnchor {
		return errors.New("root anchor does not match first level")
	}
	return nil
}

// RotationCeremony describes a planned key rotation.
type RotationCeremony struct {
	OldKeyID    string `json:"oldKeyId"`
	NewKeyID    string `json:"newKeyId"`
	InitiatedBy string `json:"initiatedBy"`
	InitiatedAt string `json:"initiatedAt"`
	Status      string `json:"status"` // "planned", "in-progress", "completed", "rolled-back"
	Reason      string `json:"reason"`
}

// PlanRotation creates a rotation ceremony in the "planned" state. It validates
// that old and new key IDs differ and that required fields are present.
func PlanRotation(oldKeyID, newKeyID, initiator, reason string) (*RotationCeremony, error) {
	if oldKeyID == "" || newKeyID == "" {
		return nil, errors.New("rotation: both oldKeyId and newKeyId are required")
	}
	if oldKeyID == newKeyID {
		return nil, errors.New("rotation: oldKeyId and newKeyId must differ")
	}
	if initiator == "" {
		return nil, errors.New("rotation: initiator is required")
	}
	return &RotationCeremony{
		OldKeyID:    oldKeyID,
		NewKeyID:    newKeyID,
		InitiatedBy: initiator,
		InitiatedAt: time.Now().UTC().Format(time.RFC3339),
		Status:      "planned",
		Reason:      reason,
	}, nil
}

// ExecuteRotation advances a planned ceremony to "completed" and returns an
// updated KeyHierarchy with the leaf key replaced. The ceremony must be in
// "planned" status.
func ExecuteRotation(kh KeyHierarchy, ceremony *RotationCeremony) (KeyHierarchy, error) {
	if ceremony.Status != "planned" {
		return kh, fmt.Errorf("rotation: cannot execute ceremony in status %q", ceremony.Status)
	}
	if kh.LeafKeyID != ceremony.OldKeyID {
		return kh, fmt.Errorf("rotation: current leaf %q does not match ceremony oldKeyId %q", kh.LeafKeyID, ceremony.OldKeyID)
	}
	// Replace the leaf level key.
	kh.Levels[kh.Depth-1].KeyID = ceremony.NewKeyID
	kh.LeafKeyID = ceremony.NewKeyID
	ceremony.Status = "completed"
	return kh, nil
}
