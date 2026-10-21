package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/AzzCraft/cadence-oss/cadence-core/internal/evidence"
	"github.com/AzzCraft/cadence-oss/cadence-core/internal/exactjson"
	"github.com/AzzCraft/cadence-oss/cadence-core/internal/signing"
)

const taskID = "CAD-002"
const tamperCode = "HASH_CHAIN_TAMPERED"

type evidenceBundleFile struct {
	Task          string   `json:"task"`
	ChainRef      string   `json:"chainRef"`
	SchemaVersion string   `json:"schemaVersion"`
	ArtifactPaths []string `json:"artifactPaths"`
}

type stepChainFile struct {
	Task              string          `json:"task"`
	Steps             []evidence.Step `json:"steps"`
	HashAlgorithm     string          `json:"hashAlgorithm"`
	CanonicalEncoding string          `json:"canonicalEncoding"`
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
	Profile       string `json:"profile"`
	Guarantee     string `json:"guarantee"`
}

func main() {
	bundlePath := flag.String("bundle", "", "path to an evidence-bundle.json file")
	profile := flag.String("profile", "cad002/v1", "required format: cad002/v1, cadence-run/v1 (historical), cadence-run/v2 (current)")
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

	result, exitCode := verifyProfile(*bundlePath, *profile)
	emit(result)
	if exitCode != 0 {
		os.Exit(exitCode)
	}
}

func verifyBundle(bundlePath string) (verifyResult, int) {
	return verifyProfile(bundlePath, "cad002/v1")
}

func verifyProfile(bundlePath, profile string) (verifyResult, int) {
	result := verifyResult{
		SchemaVersion: 1,
		Task:          taskID,
		Command:       "evidence-verify",
		Profile:       profile,
		Guarantee:     "integrity-only; no signer authentication, execution qualification or authorization",
	}
	if profile == "cad002/v1" {
		result.Guarantee = "CAD-002 chain-only diagnostic; does not verify artifact inventory, authenticate signers or authorize execution"
	}
	fail := func(err error) (verifyResult, int) {
		result.Code = "INVALID_EVIDENCE"
		result.Message = err.Error()
		return result, 1
	}
	if profile != "cad002/v1" && profile != "cadence-run/v1" && profile != "cadence-run/v2" {
		return fail(errors.New("unsupported evidence profile"))
	}
	if profile != "cad002/v1" {
		if err := verifyNative(bundlePath, profile); err != nil {
			return fail(err)
		}
		result.OK = true
		return result, 0
	}
	var bundle evidenceBundleFile
	if err := readJSON(bundlePath, &bundle); err != nil {
		result.OK = false
		result.Code = "BUNDLE_READ_FAILED"
		result.Message = fmt.Sprintf("CAD-002 evidence bundle read failed: %v", err)
		return result, 1
	}
	if bundle.Task != taskID || bundle.SchemaVersion != "1.0.0" || !evidence.ValidArtifactPath(bundle.ChainRef) {
		return fail(errors.New("CAD-002 requires version, task and a confined chainRef"))
	}
	seen := map[string]bool{}
	if len(bundle.ArtifactPaths) == 0 || len(bundle.ArtifactPaths) > evidence.MaxArtifacts {
		return fail(errors.New("invalid CAD-002 artifact references"))
	}
	for _, name := range bundle.ArtifactPaths {
		if !evidence.ValidArtifactPath(name) || seen[name] {
			return fail(errors.New("invalid or duplicate artifact reference"))
		}
		seen[name] = true
	}
	if !seen[bundle.ChainRef] {
		return fail(errors.New("chainRef is absent from declared artifact paths"))
	}
	chainPath := filepath.Join(filepath.Dir(bundlePath), bundle.ChainRef)

	var chain stepChainFile
	chainRoot, err := os.OpenRoot(filepath.Dir(bundlePath))
	if err != nil {
		return fail(err)
	}
	defer chainRoot.Close()
	if err := readRootJSON(chainRoot, bundle.ChainRef, &chain); err != nil {
		result.OK = false
		result.Code = "CHAIN_READ_FAILED"
		result.EvidencePath = chainPath
		result.Message = fmt.Sprintf("CAD-002 evidence hash-chain read failed: evidencePath=%s: %v", chainPath, err)
		return result, 1
	}
	if chain.Task != taskID || len(chain.Steps) == 0 || chain.HashAlgorithm != "sha256" || chain.CanonicalEncoding != "json/sorted-keys/no-whitespace" {
		return fail(errors.New("CAD-002 requires a nonempty task-bound chain"))
	}
	for _, step := range chain.Steps {
		if strings.TrimSpace(step.StepID) == "" || strings.TrimSpace(step.PolicyRef) == "" || strings.TrimSpace(step.PluginRef) == "" || !evidence.ValidDigest(step.InputHash) || !evidence.ValidDigest(step.OutputHash) || !evidence.ValidDigest(step.ChainHash) {
			return fail(errors.New("invalid step identity or digest"))
		}
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
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer root.Close()
	return readRootJSON(root, filepath.Base(path), out)
}

func readRootJSON(root *os.Root, name string, out any) error {
	data, err := evidence.ReadArtifact(root, name, exactjson.MaxBytes)
	if err != nil {
		return err
	}
	value, err := exactjson.Parse(data)
	if err != nil {
		return err
	}
	var required, optional []string
	switch out.(type) {
	case *evidenceBundleFile:
		required = []string{"task", "schemaVersion", "chainRef", "artifactPaths"}
		optional = []string{"expectedResult", "expectedFailure"}
	case *stepChainFile:
		required = []string{"task", "hashAlgorithm", "canonicalEncoding", "steps"}
	case *signing.Chain:
		required = []string{"steps"}
	}
	if required != nil {
		object, err := exactjson.Object(value, required, optional)
		if err != nil {
			return err
		}
		if steps, ok := object["steps"].([]any); ok {
			fields := []string{"stepIndex", "stepId", "inputHash", "outputHash", "previousHash", "chainHash"}
			if _, cad := out.(*stepChainFile); cad {
				fields = append(fields, "policyRef", "pluginRef")
			}
			for _, step := range steps {
				object, err := exactjson.Object(step, fields, []string{"evidencePath"})
				if err != nil {
					return err
				}
				// json.Unmarshal silently maps null to zero/empty scalar values.
				if index, err := exactjson.SafeInteger(object["stepIndex"]); err != nil || index < 0 {
					return errors.New("invalid step index type or value")
				}
				for name, value := range object {
					if name != "stepIndex" {
						if _, ok := value.(string); !ok {
							return fmt.Errorf("step %s must be a string", name)
						}
					}
				}
			}
		}
	}
	return json.Unmarshal(data, out)
}

func verifyNative(bundlePath, profile string) error {
	root, err := os.OpenRoot(filepath.Dir(bundlePath))
	if err != nil {
		return err
	}
	defer root.Close()
	data, err := evidence.ReadArtifact(root, filepath.Base(bundlePath), exactjson.MaxBytes)
	if err != nil {
		return err
	}
	value, err := exactjson.Parse(data)
	if err != nil {
		return err
	}
	required := []string{"schemaVersion", "audit", "runManifestRef", "pipelineResultRef", "artifactPaths", "bundleHash"}
	if profile == "cadence-run/v2" {
		required = append(required, "chainProfile", "artifactHashes")
	}
	object, err := exactjson.Object(value, required, []string{"jobEnvelopeRef", "signature"})
	if err != nil {
		return err
	}
	for _, key := range []string{"schemaVersion", "runManifestRef", "pipelineResultRef", "bundleHash", "chainProfile", "jobEnvelopeRef", "signature"} {
		if item, exists := object[key]; exists {
			if _, ok := item.(string); !ok {
				return fmt.Errorf("inventory %s must be a string", key)
			}
		}
	}
	var bundle evidence.EvidenceBundle
	if err = json.Unmarshal(data, &bundle); err != nil {
		return err
	}
	audit, err := exactjson.Object(object["audit"], []string{"bundleId", "timestamp"}, []string{"operator", "host"})
	if err != nil {
		return err
	}
	for key, item := range audit {
		if _, ok := item.(string); !ok {
			return fmt.Errorf("audit %s must be a string", key)
		}
	}
	if strings.TrimSpace(bundle.Audit.BundleID) == "" {
		return errors.New("missing audit identity")
	}
	if _, err := time.Parse(time.RFC3339, bundle.Audit.Timestamp); err != nil {
		return errors.New("invalid audit timestamp")
	}
	want := evidence.SchemaVersionV1
	if profile == "cadence-run/v2" {
		want = evidence.InventoryV2
	}
	if bundle.SchemaVersion != want || len(bundle.ArtifactPaths) == 0 || bundle.RunManifestRef != "run-manifest.json" || bundle.PipelineResultRef != "pipeline-result.json" {
		return errors.New("inventory identity/profile or required run references mismatch")
	}
	if profile == "cadence-run/v2" && bundle.JobEnvelopeRef != "job-envelope.json" {
		return errors.New("native v2 job envelope reference mismatch")
	}
	if err = evidence.VerifyBundleIntegrity(bundle, filepath.Dir(bundlePath)); err != nil {
		return err
	}
	listed := map[string]bool{}
	for _, name := range bundle.ArtifactPaths {
		listed[name] = true
	}
	for _, name := range evidence.RequiredRunArtifacts {
		if !listed[name] {
			return fmt.Errorf("profile requires artifact %s", name)
		}
	}
	var chain signing.Chain
	if err = readRootJSON(root, "step-hash-chain.json", &chain); err != nil {
		return err
	}
	wantSteps := []string{"checks", "dependencies", "manifest", "run-manifest-canonical", "pipeline-result", "pipeline-result-canonical", "job-envelope", "job-envelope-canonical", "input-identity", "audit-telemetry", "deterministic-evidence"}
	if len(chain.Steps) != len(wantSteps) {
		return errors.New("native profile requires complete step set")
	}
	for i, step := range chain.Steps {
		if step.StepIndex != i || step.StepID != wantSteps[i] || !evidence.ValidDigest(step.InputHash) || !evidence.ValidDigest(step.OutputHash) {
			return errors.New("invalid native step identity/index/digest")
		}
	}
	if err = signing.VerifyChain(&chain); err != nil {
		return err
	}
	if profile == "cadence-run/v2" {
		artifacts := map[string]string{
			"manifest": "run-manifest.json", "run-manifest-canonical": "run-manifest.canonical.json",
			"pipeline-result": "pipeline-result.json", "pipeline-result-canonical": "pipeline-result.canonical.json",
			"job-envelope": "job-envelope.json", "job-envelope-canonical": "job-envelope.canonical.json",
			"input-identity": "input-identity.json", "audit-telemetry": "audit-telemetry.json",
			"deterministic-evidence": "deterministic-evidence.json",
		}
		for _, step := range chain.Steps {
			if name, ok := artifacts[step.StepID]; ok {
				data, err := evidence.ReadArtifact(root, name, exactjson.MaxBytes)
				if err != nil {
					return err
				}
				if step.OutputHash != signing.HashPayload(data) {
					return fmt.Errorf("step %s does not bind artifact %s", step.StepID, name)
				}
			}
		}
	}
	var manifest evidence.RunManifest
	var result evidence.PipelineResult
	var job evidence.JobEnvelope
	if err = readRootJSON(root, "run-manifest.json", &manifest); err != nil {
		return err
	}
	if err = readRootJSON(root, "pipeline-result.json", &result); err != nil {
		return err
	}
	if err = readRootJSON(root, "job-envelope.json", &job); err != nil {
		return err
	}
	if err = evidence.ValidateRunManifest(manifest); err != nil {
		return err
	}
	if err = evidence.ValidatePipelineResult(result); err != nil {
		return err
	}
	if err = evidence.ValidateJobEnvelope(job); err != nil {
		return err
	}
	if manifest.RunID == "" || result.RunID != manifest.RunID || result.ManifestRef.RunID != manifest.RunID || len(job.Runs) == 0 {
		return errors.New("missing run identity")
	}
	manifestBytes, err := evidence.ReadArtifact(root, "run-manifest.json", exactjson.MaxBytes)
	if err != nil {
		return err
	}
	manifestHash := signing.HashPayload(manifestBytes)
	if profile == "cadence-run/v2" {
		hashes := map[string]string{}
		for _, name := range []string{"pipeline-result.json", "job-envelope.json", "input-identity.json", "audit-telemetry.json", "deterministic-evidence.json"} {
			data, err := evidence.ReadArtifact(root, name, exactjson.MaxBytes)
			if err != nil {
				return err
			}
			hashes[name] = signing.HashPayload(data)
		}
		inputs := map[string]string{"checks": manifest.InputRef.InputHash, "dependencies": manifest.InputRef.InputHash,
			"manifest": manifestHash, "run-manifest-canonical": manifestHash, "pipeline-result": manifestHash,
			"pipeline-result-canonical": hashes["pipeline-result.json"], "job-envelope": manifestHash,
			"job-envelope-canonical": hashes["job-envelope.json"], "input-identity": hashes["input-identity.json"],
			"audit-telemetry": hashes["audit-telemetry.json"], "deterministic-evidence": hashes["deterministic-evidence.json"]}

		if manifest.Diagnostics == nil {
			return errors.New("missing native dependency metadata")
		}
		dependencyHash, ok := manifest.Diagnostics.KV["dependencyHash"].(string)
		if !ok || !evidence.ValidDigest(dependencyHash) {
			return errors.New("invalid native dependency hash")
		}
		for _, step := range chain.Steps {
			if step.StepID == "dependencies" && step.OutputHash != signing.HashPayload([]byte(dependencyHash)) {
				return errors.New("dependencies binding mismatch")
			}
			if step.InputHash != inputs[step.StepID] {
				return fmt.Errorf("step %s input binding mismatch", step.StepID)
			}
			if step.StepID == "checks" && step.OutputHash != signing.HashPayload([]byte(manifest.Config.ConfigHash)) {
				return errors.New("checks config binding mismatch")
			}
		}
	}
	if result.ManifestRef.ManifestHash != manifestHash {
		return errors.New("result manifest hash mismatch")
	}
	for _, run := range job.Runs {
		if run.ManifestRef.RunID != manifest.RunID || run.Result.RunID != manifest.RunID || run.ManifestRef.ManifestHash != manifestHash {
			return errors.New("job/manifest run identity mismatch")
		}
	}
	return nil
}

func emit(result verifyResult) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(result); err != nil {
		fmt.Fprintf(os.Stderr, "CAD-002 evidence-verify encode failed: %v\n", err)
	}
}
