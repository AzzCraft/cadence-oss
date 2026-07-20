package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/AzzCraft/cadence-oss/cadence-core/internal/evidence"
)

const taskID = "CAD-002"
const tamperCode = "HASH_CHAIN_TAMPERED"

type evidenceBundleFile struct {
	Task     string `json:"task"`
	ChainRef string `json:"chainRef"`
}

type stepChainFile struct {
	Task  string          `json:"task"`
	Steps []evidence.Step `json:"steps"`
}

type verifyResult struct {
	SchemaVersion int    `json:"schemaVersion"`
	Task          string `json:"task"`
	Command       string `json:"command"`
	OK            bool   `json:"ok"`
	Code          string `json:"code,omitempty"`
	StepIndex     *int   `json:"stepIndex,omitempty"`
	EvidencePath  string `json:"evidencePath,omitempty"`
	Message       string `json:"message,omitempty"`
}

func main() {
	bundlePath := flag.String("bundle", "", "path to an evidence-bundle.json file")
	_ = flag.Bool("json", true, "emit machine-readable JSON")
	flag.Parse()

	if *bundlePath == "" {
		emit(verifyResult{
			SchemaVersion: 1,
			Task:          taskID,
			Command:       "evidence-verify",
			OK:            false,
			Code:          "MISSING_BUNDLE",
			Message:       "CAD-002 evidence-verify requires --bundle",
		})
		os.Exit(2)
	}

	result, exitCode := verifyBundle(*bundlePath)
	emit(result)
	if exitCode != 0 {
		os.Exit(exitCode)
	}
}

func verifyBundle(bundlePath string) (verifyResult, int) {
	result := verifyResult{
		SchemaVersion: 1,
		Task:          taskID,
		Command:       "evidence-verify",
	}
	var bundle evidenceBundleFile
	if err := readJSON(bundlePath, &bundle); err != nil {
		result.OK = false
		result.Code = "BUNDLE_READ_FAILED"
		result.Message = fmt.Sprintf("CAD-002 evidence bundle read failed: %v", err)
		return result, 1
	}
	chainRef := bundle.ChainRef
	if chainRef == "" {
		chainRef = "step-hash-chain.json"
	}
	chainPath := filepath.ToSlash(filepath.Join(filepath.Dir(bundlePath), chainRef))

	var chain stepChainFile
	if err := readJSON(chainPath, &chain); err != nil {
		result.OK = false
		result.Code = "CHAIN_READ_FAILED"
		result.EvidencePath = chainPath
		result.Message = fmt.Sprintf("CAD-002 evidence hash-chain read failed: evidencePath=%s: %v", chainPath, err)
		return result, 1
	}
	if err := evidence.VerifyStepChain(chain.Steps, chainPath); err != nil {
		result.OK = false
		result.Code = tamperCode
		result.Message = err.Error()
		if chainErr, ok := err.(*evidence.StepChainError); ok {
			result.StepIndex = &chainErr.StepIndex
			result.EvidencePath = chainErr.EvidencePath
			result.Code = chainErr.Code
		}
		return result, 1
	}
	result.OK = true
	return result, 0
}

func readJSON(path string, out any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, out)
}

func emit(result verifyResult) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(result); err != nil {
		fmt.Fprintf(os.Stderr, "CAD-002 evidence-verify encode failed: %v\n", err)
	}
}
