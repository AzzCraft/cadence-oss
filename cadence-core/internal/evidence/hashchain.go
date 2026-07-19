// Package evidence — append-only hash-chained event log.
//
// Each entry's
// hash includes the previous entry's hash, so any tampering breaks the
// chain. Verify with VerifyChain.
package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/AzzCraft/cadence-oss/cadence-core/internal/canonicaljson"
)

const TaskCAD002 = "CAD-002"

// Entry is a single hash-chained record.
type Entry struct {
	Index    int            `json:"index"`
	PrevHash string         `json:"prevHash"`
	Payload  map[string]any `json:"payload"`
	Hash     string         `json:"hash"`
}

// Genesis hash for the first entry.
const Genesis = "0000000000000000000000000000000000000000000000000000000000000000"

// Step is a CAD-002 canonical evidence-chain step.
type Step struct {
	StepIndex    int    `json:"stepIndex"`
	StepID       string `json:"stepId"`
	InputHash    string `json:"inputHash"`
	OutputHash   string `json:"outputHash"`
	PolicyRef    string `json:"policyRef"`
	PluginRef    string `json:"pluginRef"`
	PreviousHash string `json:"previousHash"`
	ChainHash    string `json:"chainHash"`
	EvidencePath string `json:"evidencePath,omitempty"`
}

// StepChainError is the stable CAD-002 verifier diagnostic.
type StepChainError struct {
	Task         string `json:"task"`
	Code         string `json:"code"`
	StepIndex    int    `json:"stepIndex"`
	EvidencePath string `json:"evidencePath"`
	Message      string `json:"message"`
}

func (e *StepChainError) Error() string {
	return e.Message
}

// canonical produces a deterministic JSON encoding.
func canonical(v any) ([]byte, error) {
	switch m := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf := []byte{'{'}
		for i, k := range keys {
			if i > 0 {
				buf = append(buf, ',')
			}
			kj, _ := json.Marshal(k)
			vj, err := canonical(m[k])
			if err != nil {
				return nil, err
			}
			buf = append(buf, kj...)
			buf = append(buf, ':')
			buf = append(buf, vj...)
		}
		buf = append(buf, '}')
		return buf, nil
	default:
		return json.Marshal(v)
	}
}

// Append builds a new Entry chained from prev.
func Append(prev *Entry, payload map[string]any) (Entry, error) {
	idx := 0
	prevHash := Genesis
	if prev != nil {
		idx = prev.Index + 1
		prevHash = prev.Hash
	}
	body := map[string]any{"index": idx, "prevHash": prevHash, "payload": payload}
	enc, err := canonical(body)
	if err != nil {
		return Entry{}, err
	}
	sum := sha256.Sum256(enc)
	return Entry{Index: idx, PrevHash: prevHash, Payload: payload, Hash: hex.EncodeToString(sum[:])}, nil
}

// CanonicalStepHash returns the CAD-002 digest for the fields chained by a step.
func CanonicalStepHash(step Step) (string, error) {
	return canonicaljson.CanonicalHash(map[string]any{
		"inputHash":    step.InputHash,
		"outputHash":   step.OutputHash,
		"pluginRef":    step.PluginRef,
		"policyRef":    step.PolicyRef,
		"previousHash": step.PreviousHash,
		"stepId":       step.StepID,
		"stepIndex":    step.StepIndex,
	})
}

// VerifyStepChain checks CAD-002 step linkage and canonical hashes.
func VerifyStepChain(steps []Step, evidencePath string) error {
	previousHash := "sha256:" + Genesis
	for i, step := range steps {
		path := stepEvidencePath(evidencePath, step, i)
		if step.StepIndex != i {
			return cad002Error(i, path, "expected stepIndex=%d, got stepIndex=%d", i, step.StepIndex)
		}
		if step.PreviousHash != previousHash {
			return cad002Error(i, path, "previousHash mismatch: expected %s, got %s", previousHash, step.PreviousHash)
		}
		expected, err := CanonicalStepHash(step)
		if err != nil {
			return fmt.Errorf("CAD-002 canonical step hash failed at stepIndex=%d evidencePath=%s: %w", i, path, err)
		}
		if step.ChainHash != expected {
			return cad002Error(i, path, "chainHash mismatch: expected %s, got %s", expected, step.ChainHash)
		}
		previousHash = step.ChainHash
	}
	return nil
}

func stepEvidencePath(chainPath string, step Step, index int) string {
	if chainPath != "" {
		return fmt.Sprintf("%s#/steps/%d", chainPath, index)
	}
	if step.EvidencePath != "" {
		return step.EvidencePath
	}
	return fmt.Sprintf("step-hash-chain.json#/steps/%d", index)
}

func cad002Error(stepIndex int, evidencePath string, format string, args ...any) *StepChainError {
	message := fmt.Sprintf("CAD-002 evidence hash-chain verification failed: stepIndex=%d evidencePath=%s", stepIndex, evidencePath)
	if format != "" {
		message += ": " + fmt.Sprintf(format, args...)
	}
	return &StepChainError{
		Task:         TaskCAD002,
		Code:         "HASH_CHAIN_TAMPERED",
		StepIndex:    stepIndex,
		EvidencePath: evidencePath,
		Message:      message,
	}
}

// VerifyChain returns nil if the chain is intact, else an error.
func VerifyChain(entries []Entry) error {
	prevHash := Genesis
	for i, e := range entries {
		if e.Index != i {
			return errors.New("index gap or reorder at " + itoa(i))
		}
		if e.PrevHash != prevHash {
			return errors.New("prevHash mismatch at index " + itoa(i))
		}
		body := map[string]any{"index": e.Index, "prevHash": e.PrevHash, "payload": e.Payload}
		enc, err := canonical(body)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(enc)
		if hex.EncodeToString(sum[:]) != e.Hash {
			return errors.New("hash mismatch at index " + itoa(i))
		}
		prevHash = e.Hash
	}
	return nil
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	s := []byte{}
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		s = append([]byte{byte('0' + n%10)}, s...)
		n /= 10
	}
	if neg {
		s = append([]byte{'-'}, s...)
	}
	return string(s)
}
