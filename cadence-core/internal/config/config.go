package config

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/AzzCraft/cadence-oss/cadence-core/internal/exactjson"
	"github.com/santhosh-tekuri/jsonschema/v5"
	"gopkg.in/yaml.v3"
)

//go:embed config.schema.json
var embeddedConfigSchema []byte

//go:embed suite_version_closure.schema.json
var closureSchema []byte

//go:embed suite_lock.schema.json
var suiteLockSchema []byte

func validateStandardSchema(data map[string]any, raw []byte, context string) error {
	compiler := jsonschema.NewCompiler()
	compiler.Draft = jsonschema.Draft2020
	compiler.AssertFormat = true
	compiler.LoadURL = func(string) (io.ReadCloser, error) {
		return nil, errors.New("external Standard schema loading forbidden")
	}
	if err := compiler.AddResource("embedded://standard.json", bytes.NewReader(raw)); err != nil {
		return err
	}
	schema, err := compiler.Compile("embedded://standard.json")
	if err != nil {
		return err
	}
	if err := schema.Validate(data); err != nil {
		return fmt.Errorf("%s: Standard schema: %w", context, err)
	}
	return nil
}

const embeddedConfigSchemaID = "embedded://config.schema.json"

// projectIDPattern enforces lowercase alphanumeric with hyphens, 3-64 chars.
var projectIDPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{1,62}[a-z0-9]$`)

// ValidateProjectID checks that a project ID conforms to the allowed format.
func ValidateProjectID(id string) error {
	if !projectIDPattern.MatchString(id) {
		return fmt.Errorf("config: projectId %q must be 3-64 chars, lowercase alphanumeric+hyphens, start with letter, end alphanumeric", id)
	}
	return nil
}

// Config mirrors config.schema.json and then applies semantic validation for
// referenced closure, tooling, registry, runtime, and sandbox artifacts.
type Config struct {
	ProjectID string
	Mode      string

	ClosureRef  string
	ToolingLock string
	RuntimeRef  string
	RegistryRef string
	SandboxRef  string
	RootAnchor  string

	Policies []string
	// Plugins is an explicit execution allowlist.  A registry advertises
	// available plugin manifests; it does not grant permission to execute
	// every registered plugin in each repository.
	Plugins []string

	UIEnabled bool
	UIProfile string

	BaselinePath     string
	BaselineExplicit bool
}

type configDocument struct {
	ProjectID    string           `json:"projectId"`
	Mode         string           `json:"mode"`
	ClosureRef   string           `json:"closureRef"`
	ToolingLock  string           `json:"toolingLock"`
	RuntimeRef   string           `json:"runtimeRef"`
	RegistryRef  string           `json:"registryRef"`
	SandboxRef   string           `json:"sandboxRef"`
	RootAnchor   string           `json:"rootAnchor"`
	Policies     []string         `json:"policies"`
	Plugins      []string         `json:"plugins"`
	UI           *uiConfigSection `json:"ui"`
	BaselinePath string           `json:"baselinePath"`
}

type uiConfigSection struct {
	Enabled bool   `json:"enabled"`
	Profile string `json:"profile"`
}

func Default() Config {
	return Config{
		ProjectID:    "unknown",
		Mode:         "strict_offline",
		Policies:     nil,
		UIEnabled:    false,
		UIProfile:    "pr",
		BaselinePath: filepath.Join(".cadence", "baseline.json"),
		ToolingLock:  "tooling_lock.json",
		RootAnchor:   "operator-local",
	}
}

// Load searches for cadence.yaml or cadence.yml in the provided root.
// The config must declare explicit closure/lock/policy/runtime refs.
func Load(repoRoot string) (Config, error) {
	cfg := Default()

	cand := []string{
		filepath.Join(repoRoot, "cadence.yaml"),
		filepath.Join(repoRoot, "cadence.yml"),
	}
	path := ""
	for _, c := range cand {
		if _, err := os.Stat(c); err == nil {
			path = c
			break
		}
	}
	if path == "" {
		return cfg, errors.New("missing cadence.yaml (or cadence.yml)")
	}

	file, err := os.Open(path)
	if err != nil {
		return cfg, err
	}
	data, err := io.ReadAll(io.LimitReader(file, exactjson.MaxBytes+1))
	file.Close()
	if err != nil {
		return cfg, err
	}

	rawDoc, err := decodeCadenceConfigDocument(data)
	if err != nil {
		return cfg, err
	}
	if err := validateCadenceConfigDocument(rawDoc); err != nil {
		return cfg, err
	}
	doc, err := configDocumentFromMap(rawDoc)
	if err != nil {
		return cfg, err
	}

	cfg.ProjectID = doc.ProjectID
	if doc.Mode != "" {
		cfg.Mode = doc.Mode
	}
	cfg.ClosureRef = doc.ClosureRef
	if doc.ToolingLock != "" {
		cfg.ToolingLock = doc.ToolingLock
	}
	cfg.RuntimeRef = doc.RuntimeRef
	cfg.RegistryRef = doc.RegistryRef
	cfg.SandboxRef = doc.SandboxRef
	if doc.RootAnchor != "" {
		cfg.RootAnchor = doc.RootAnchor
	}
	if doc.BaselinePath != "" {
		cfg.BaselineExplicit = true
		cfg.BaselinePath = doc.BaselinePath
	}
	cfg.Policies = doc.Policies
	cfg.Plugins = doc.Plugins
	if doc.UI != nil {
		cfg.UIEnabled = doc.UI.Enabled
		if doc.UI.Profile != "" {
			cfg.UIProfile = doc.UI.Profile
		}
	}

	if cfg.ProjectID == "" {
		return cfg, errors.New("cadence.yaml missing projectId")
	}
	if err := ValidateProjectID(cfg.ProjectID); err != nil {
		return cfg, err
	}
	if len(cfg.Policies) == 0 {
		return cfg, errors.New("cadence.yaml missing policies")
	}
	requiredRefs := map[string]string{
		"closureRef":  cfg.ClosureRef,
		"toolingLock": cfg.ToolingLock,
		"runtimeRef":  cfg.RuntimeRef,
		"registryRef": cfg.RegistryRef,
		"sandboxRef":  cfg.SandboxRef,
	}
	for name, rel := range requiredRefs {
		if strings.TrimSpace(rel) == "" {
			return cfg, fmt.Errorf("cadence.yaml missing %s", name)
		}
		resolved := filepath.Join(repoRoot, rel)
		if _, err := os.Stat(resolved); err != nil {
			return cfg, fmt.Errorf("%s does not resolve: %s", name, rel)
		}
	}

	if err := ValidateClosureRef(repoRoot, cfg.ClosureRef); err != nil {
		return cfg, err
	}
	if err := ValidateToolingLock(repoRoot, cfg.ToolingLock, cfg.ClosureRef, cfg.RegistryRef); err != nil {
		return cfg, err
	}
	if err := ValidateClosureToolingAlignment(repoRoot, cfg.ClosureRef, cfg.ToolingLock); err != nil {
		return cfg, err
	}

	return cfg, nil
}

// LoadStrict loads config and additionally rejects floating/implicit refs.
// Unlike Load, it fails if any configured ref looks like a bare filename
// without an SHA or version pin.
func LoadStrict(repoRoot string) (Config, error) {
	cfg, err := Load(repoRoot)
	if err != nil {
		return cfg, err
	}
	refs := map[string]string{
		"closureRef":  cfg.ClosureRef,
		"toolingLock": cfg.ToolingLock,
		"runtimeRef":  cfg.RuntimeRef,
		"registryRef": cfg.RegistryRef,
		"sandboxRef":  cfg.SandboxRef,
	}
	for name, val := range refs {
		if val == "" {
			continue
		}
		if !strings.Contains(val, "@") && !strings.Contains(val, "sha256:") && !strings.Contains(val, ".json") {
			return cfg, fmt.Errorf("LoadStrict: %s=%q looks like a floating ref (missing pin)", name, val)
		}
	}
	return cfg, nil
}

func decodeCadenceConfigDocument(data []byte) (map[string]any, error) {
	if len(data) > exactjson.MaxBytes {
		return nil, errors.New("cadence.yaml exceeds configuration byte limit")
	}
	var document yaml.Node
	dec := yaml.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&document); err != nil {
		return nil, fmt.Errorf("cadence.yaml is not valid YAML: %w", err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, errors.New("cadence.yaml requires exactly one YAML document")
	}
	if len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return nil, errors.New("cadence.yaml must be a mapping")
	}
	remaining := exactjson.MaxNodes
	if err := checkYAMLSource(document.Content[0], 0, &remaining, map[*yaml.Node]bool{}); err != nil {
		return nil, err
	}
	var raw map[string]any
	if err := document.Decode(&raw); err != nil {
		return nil, fmt.Errorf("cadence.yaml cannot be mapped: %w", err)
	}
	return raw, nil
}

// Check original nodes before native construction can lose tags or key types.
// The legacy yaml.v3 alias/merge mapping remains supported, within the same
// operation's bounds; it cannot extend the JSON-only protected wire contracts.
func checkYAMLSource(node *yaml.Node, depth int, remaining *int, active map[*yaml.Node]bool) error {
	if node == nil || depth > exactjson.MaxDepth || *remaining <= 0 || active[node] {
		return errors.New("cadence.yaml exceeds node/depth limits or contains a cyclic alias")
	}
	*remaining--
	active[node] = true
	defer delete(active, node)
	if node.Kind == yaml.AliasNode {
		return checkYAMLSource(node.Alias, depth+1, remaining, active)
	}
	switch node.Kind {
	case yaml.MappingNode:
		if node.Tag != "!!map" || len(node.Content)%2 != 0 {
			return errors.New("cadence.yaml has an unsupported mapping tag")
		}
		seen := map[string]bool{}
		for index := 0; index < len(node.Content); index += 2 {
			key := node.Content[index]
			merge := key.Kind == yaml.ScalarNode && key.Tag == "!!merge" && key.Value == "<<"
			if merge {
				*remaining--
			} else {
				if err := checkYAMLSource(key, depth+1, remaining, active); err != nil {
					return err
				}
				for key.Kind == yaml.AliasNode {
					key = key.Alias
				}
			}
			if key.Kind != yaml.ScalarNode || (!merge && key.Tag != "!!str") || seen[key.Value] {
				return errors.New("cadence.yaml requires unique string keys or one explicit legacy merge")
			}
			seen[key.Value] = true
			if err := checkYAMLSource(node.Content[index+1], depth+1, remaining, active); err != nil {
				return err
			}
		}
	case yaml.SequenceNode:
		if node.Tag != "!!seq" {
			return errors.New("cadence.yaml has an unsupported sequence tag")
		}
		for _, child := range node.Content {
			if err := checkYAMLSource(child, depth+1, remaining, active); err != nil {
				return err
			}
		}
	case yaml.ScalarNode:
		switch node.Tag {
		case "!!str", "!!bool", "!!int", "!!float", "!!null":
		default:
			return errors.New("cadence.yaml has an unapproved scalar tag; quote string values explicitly")
		}
	default:
		return errors.New("cadence.yaml has an unsupported node")
	}
	return nil
}

func configDocumentFromMap(raw map[string]any) (configDocument, error) {
	data, err := json.Marshal(raw)
	if err != nil {
		return configDocument{}, err
	}
	var doc configDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return configDocument{}, fmt.Errorf("cadence.yaml did not match config.schema.json DTO: %w", err)
	}
	return doc, nil
}

func validateCadenceConfigDocument(raw map[string]any) error {
	schemaData, schemaID, err := loadConfigSchemaData()
	if err != nil {
		return err
	}
	compiler := jsonschema.NewCompiler()
	if err := compiler.AddResource(schemaID, bytes.NewReader(schemaData)); err != nil {
		return fmt.Errorf("config.schema.json could not be loaded: %w", err)
	}
	schema, err := compiler.Compile(schemaID)
	if err != nil {
		return fmt.Errorf("config.schema.json could not be compiled: %w", err)
	}

	var normalized any
	data, err := json.Marshal(raw)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, &normalized); err != nil {
		return err
	}
	if err := schema.Validate(normalized); err != nil {
		if extra := schemaExtraTopLevelKey(schemaData, raw); extra != "" {
			return fmt.Errorf("config.schema.json: unknown top-level key %s: %w", extra, err)
		}
		return fmt.Errorf("config.schema.json validation failed: %w", err)
	}
	return nil
}

func loadConfigSchemaData() ([]byte, string, error) {
	if len(embeddedConfigSchema) == 0 {
		return nil, "", errors.New("embedded config.schema.json is empty")
	}
	return embeddedConfigSchema, embeddedConfigSchemaID, nil
}

func schemaExtraTopLevelKey(schemaData []byte, raw map[string]any) string {
	var schemaDoc struct {
		Properties map[string]any `json:"properties"`
	}
	if err := json.Unmarshal(schemaData, &schemaDoc); err != nil {
		return ""
	}
	for key := range raw {
		if _, ok := schemaDoc.Properties[key]; !ok {
			return key
		}
	}
	return ""
}

type structuredRef struct {
	kind     string
	uri      string
	pinType  string
	pinValue string
}

func loadJSONObject(repoRoot string, rel string, label string) (map[string]any, error) {
	path := filepath.Join(repoRoot, rel)
	return loadJSONObjectAtPath(path, label)
}

func loadJSONObjectAtPath(path string, label string) (map[string]any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%s: cannot read %s: %w", label, path, err)
	}
	var dec map[string]any
	if err := json.Unmarshal(data, &dec); err != nil {
		return nil, fmt.Errorf("%s: %s is not valid JSON: %w", label, path, err)
	}
	return dec, nil
}

func rejectUnknownKeys(obj map[string]any, allowed map[string]struct{}, context string) error {
	for key := range obj {
		if _, ok := allowed[key]; !ok {
			return fmt.Errorf("%s: unknown key %s", context, key)
		}
	}
	return nil
}

func requireString(obj map[string]any, key string, context string) (string, error) {
	raw, ok := obj[key]
	if !ok {
		return "", fmt.Errorf("%s: missing %s", context, key)
	}
	value, ok := raw.(string)
	if !ok || strings.TrimSpace(value) == "" {
		return "", fmt.Errorf("%s: %s must be a non-empty string", context, key)
	}
	return value, nil
}

func requireObject(obj map[string]any, key string, context string) (map[string]any, error) {
	raw, ok := obj[key]
	if !ok {
		return nil, fmt.Errorf("%s: missing %s", context, key)
	}
	value, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s: %s must be an object", context, key)
	}
	return value, nil
}

func requireArray(obj map[string]any, key string, context string) ([]any, error) {
	raw, ok := obj[key]
	if !ok {
		return nil, fmt.Errorf("%s: missing %s", context, key)
	}
	value, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("%s: %s must be an array", context, key)
	}
	return value, nil
}

func validateStringArray(raw any, context string) error {
	items, ok := raw.([]any)
	if !ok {
		return fmt.Errorf("%s must be an array", context)
	}
	for i, item := range items {
		value, ok := item.(string)
		if !ok || strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s[%d] must be a non-empty string", context, i)
		}
	}
	return nil
}

func validateStructuredRef(raw any, context string) (structuredRef, error) {
	ref, ok := raw.(map[string]any)
	if !ok {
		return structuredRef{}, fmt.Errorf("%s must be an object", context)
	}
	if err := rejectUnknownKeys(ref, map[string]struct{}{
		"kind": {}, "uri": {}, "pinType": {}, "pinValue": {}, "floating": {}, "notes": {},
	}, context); err != nil {
		return structuredRef{}, err
	}

	kind, err := requireString(ref, "kind", context)
	if err != nil {
		return structuredRef{}, err
	}
	uri, err := requireString(ref, "uri", context)
	if err != nil {
		return structuredRef{}, err
	}
	pinType, err := requireString(ref, "pinType", context)
	if err != nil {
		return structuredRef{}, err
	}
	pinValue, err := requireString(ref, "pinValue", context)
	if err != nil {
		return structuredRef{}, err
	}

	switch kind {
	case "git", "container_image", "package", "file", "ci_workflow", "custom":
	default:
		return structuredRef{}, fmt.Errorf("%s.kind must be a supported structured ref kind", context)
	}

	switch pinType {
	case "commit", "tag", "digest", "version", "path", "manifest":
	default:
		return structuredRef{}, fmt.Errorf("%s.pinType must be a supported pin type", context)
	}

	switch kind {
	case "git":
		if pinType != "commit" && pinType != "tag" {
			return structuredRef{}, fmt.Errorf("%s.pinType must be commit or tag for git refs", context)
		}
	case "container_image":
		if pinType != "digest" {
			return structuredRef{}, fmt.Errorf("%s.pinType must be digest for container_image refs", context)
		}
	case "package":
		if pinType != "version" {
			return structuredRef{}, fmt.Errorf("%s.pinType must be version for package refs", context)
		}
	case "file", "ci_workflow":
		if pinType != "path" && pinType != "manifest" {
			return structuredRef{}, fmt.Errorf("%s.pinType must be path or manifest for %s refs", context, kind)
		}
	}

	if floating, ok := ref["floating"]; ok {
		b, ok := floating.(bool)
		if !ok || b {
			return structuredRef{}, fmt.Errorf("%s.floating must be false when present", context)
		}
	}
	if notes, ok := ref["notes"]; ok {
		if _, ok := notes.(string); !ok {
			return structuredRef{}, fmt.Errorf("%s.notes must be a string when present", context)
		}
	}

	return structuredRef{
		kind:     kind,
		uri:      uri,
		pinType:  pinType,
		pinValue: pinValue,
	}, nil
}

func validateFileRef(raw any, context string) error {
	ref, err := validateStructuredRef(raw, context)
	if err != nil {
		return err
	}
	if ref.kind != "file" {
		return fmt.Errorf("%s.kind must be file", context)
	}
	if ref.pinType != "path" && ref.pinType != "manifest" {
		return fmt.Errorf("%s.pinType must be path or manifest", context)
	}
	return nil
}

func requireLocalFileRef(
	repoRoot string,
	raw any,
	context string,
	expectedKeys []string,
) error {
	if err := validateFileRef(raw, context); err != nil {
		return err
	}
	resolved, ok := resolveLocalFileRefPath(repoRoot, raw)
	if !ok {
		return fmt.Errorf("%s must resolve to a local file path", context)
	}
	dec, err := loadJSONObjectAtPath(resolved, context)
	if err != nil {
		return err
	}
	if strings.HasSuffix(context, ".suiteLockRef") {
		if err := validateStandardSchema(dec, suiteLockSchema, context); err != nil {
			return err
		}
	}
	for _, key := range expectedKeys {
		if _, err := requireString(dec, key, context); err != nil {
			return err
		}
	}
	return nil
}

func validateToolchain(raw any, context string) error {
	items, ok := raw.([]any)
	if !ok || len(items) == 0 {
		return fmt.Errorf("%s must be a non-empty array", context)
	}
	for i, item := range items {
		entry, ok := item.(map[string]any)
		if !ok {
			return fmt.Errorf("%s[%d] must be an object", context, i)
		}
		scope := fmt.Sprintf("%s[%d]", context, i)
		if err := rejectUnknownKeys(entry, map[string]struct{}{
			"name": {}, "version": {}, "manager": {}, "sha256": {},
		}, scope); err != nil {
			return err
		}
		if _, err := requireString(entry, "name", scope); err != nil {
			return err
		}
		if _, err := requireString(entry, "version", scope); err != nil {
			return err
		}
		if manager, ok := entry["manager"]; ok {
			if _, ok := manager.(string); !ok {
				return fmt.Errorf("%s.manager must be a string", scope)
			}
		}
		if sha, ok := entry["sha256"]; ok {
			if _, ok := sha.(string); !ok {
				return fmt.Errorf("%s.sha256 must be a string", scope)
			}
		}
	}
	return nil
}

func validateClosureProfiles(raw any, context string) error {
	profiles, ok := raw.(map[string]any)
	if !ok {
		return fmt.Errorf("%s must be an object", context)
	}
	for name, rawProfile := range profiles {
		profile, ok := rawProfile.(map[string]any)
		if !ok {
			return fmt.Errorf("%s.%s must be an object", context, name)
		}
		scope := context + "." + name
		if err := rejectUnknownKeys(profile, map[string]struct{}{
			"description": {}, "requiredModules": {}, "optionalModules": {}, "constraints": {},
		}, scope); err != nil {
			return err
		}
		if _, err := requireString(profile, "description", scope); err != nil {
			return err
		}
		required, err := requireArray(profile, "requiredModules", scope)
		if err != nil {
			return err
		}
		if len(required) == 0 {
			return fmt.Errorf("%s.requiredModules must be non-empty", scope)
		}
		if err := validateStringArray(required, scope+".requiredModules"); err != nil {
			return err
		}
		if rawOptional, ok := profile["optionalModules"]; ok {
			if err := validateStringArray(rawOptional, scope+".optionalModules"); err != nil {
				return err
			}
		}
		if rawConstraints, ok := profile["constraints"]; ok {
			if err := validateStringArray(rawConstraints, scope+".constraints"); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateMirrors(raw any, context string) error {
	items, ok := raw.([]any)
	if !ok {
		return fmt.Errorf("%s must be an array", context)
	}
	for i, item := range items {
		entry, ok := item.(map[string]any)
		if !ok {
			return fmt.Errorf("%s[%d] must be an object", context, i)
		}
		scope := fmt.Sprintf("%s[%d]", context, i)
		if err := rejectUnknownKeys(entry, map[string]struct{}{
			"kind": {}, "path": {}, "sourceOfTruth": {}, "mirrorPurpose": {}, "localModificationsAllowed": {}, "snapshotRef": {},
		}, scope); err != nil {
			return err
		}
		kind, err := requireString(entry, "kind", scope)
		if err != nil {
			return err
		}
		switch kind {
		case "generated_contracts", "generated_clients", "generated_docs", "standard_local_copy", "policy_pack_copy", "other":
		default:
			return fmt.Errorf("%s.kind is unsupported: %s", scope, kind)
		}
		if kind == "standard_local_copy" || kind == "policy_pack_copy" {
			if _, ok := entry["snapshotRef"]; !ok {
				return fmt.Errorf("%s.snapshotRef is required for %s", scope, kind)
			}
		}
		if _, err := requireString(entry, "path", scope); err != nil {
			return err
		}
		if _, err := requireString(entry, "sourceOfTruth", scope); err != nil {
			return err
		}
		if _, err := requireString(entry, "mirrorPurpose", scope); err != nil {
			return err
		}
		allowed, ok := entry["localModificationsAllowed"].(bool)
		if !ok {
			return fmt.Errorf("%s.localModificationsAllowed must be boolean", scope)
		}
		if (kind == "standard_local_copy" || kind == "policy_pack_copy") && allowed {
			return fmt.Errorf("%s.localModificationsAllowed must be false for %s", scope, kind)
		}
		if snapshot, ok := entry["snapshotRef"]; ok {
			if _, err := validateStructuredRef(snapshot, scope+".snapshotRef"); err != nil {
				return err
			}
		}
	}
	return nil
}

func resolveLocalFileRefPath(repoRoot string, raw any) (string, bool) {
	ref, ok := raw.(map[string]any)
	if !ok {
		return "", false
	}
	uri, _ := ref["uri"].(string)
	if strings.TrimSpace(uri) == "" {
		return "", false
	}
	if strings.Contains(uri, "://") || strings.HasPrefix(uri, "git@") || strings.HasPrefix(uri, "pkg://") {
		return "", false
	}
	return filepath.Clean(filepath.Join(repoRoot, uri)), true
}

func sameStructuredRef(left any, right any) bool {
	lref, err := validateStructuredRef(left, "left")
	if err != nil {
		return false
	}
	rref, err := validateStructuredRef(right, "right")
	if err != nil {
		return false
	}
	return lref.kind == rref.kind &&
		lref.uri == rref.uri &&
		lref.pinType == rref.pinType &&
		lref.pinValue == rref.pinValue
}

// ValidateClosureRef loads the file at closureRef (relative to repoRoot) and
// validates the suite version closure shape expected by Cadence.
func ValidateClosureRef(repoRoot string, closureRef string) error {
	dec, err := loadJSONObject(repoRoot, closureRef, "closureRef")
	if err != nil {
		return err
	}
	if err := validateStandardSchema(dec, closureSchema, "closureRef"); err != nil {
		return err
	}
	if err := rejectUnknownKeys(dec, map[string]struct{}{
		"$schema": {}, "schemaVersion": {}, "standardVersion": {}, "standardManifestVersion": {}, "suiteVersion": {}, "factoryVersion": {}, "verifyRuntimeVersion": {}, "policyPackVersion": {}, "generatorTemplateVersion": {}, "closureUpdatedAt": {}, "suiteLockRef": {}, "lockRefs": {}, "refs": {}, "closureProfiles": {},
	}, "closureRef"); err != nil {
		return err
	}
	for _, key := range []string{
		"schemaVersion",
		"standardVersion",
		"standardManifestVersion",
		"suiteVersion",
		"factoryVersion",
		"verifyRuntimeVersion",
		"closureUpdatedAt",
	} {
		if _, err := requireString(dec, key, "closureRef"); err != nil {
			return err
		}
	}
	closureUpdatedAt, _ := dec["closureUpdatedAt"].(string)
	if _, err := time.Parse(time.RFC3339, closureUpdatedAt); err != nil {
		return fmt.Errorf("closureRef: closureUpdatedAt must be RFC3339: %w", err)
	}
	if err := requireLocalFileRef(repoRoot, dec["suiteLockRef"], "closureRef.suiteLockRef", []string{"schemaVersion"}); err != nil {
		return err
	}

	rawLockRefs, ok := dec["lockRefs"]
	if !ok {
		return fmt.Errorf("closureRef: missing lockRefs")
	}
	lockRefs, ok := rawLockRefs.(map[string]any)
	if !ok {
		return fmt.Errorf("closureRef.lockRefs must be an object")
	}
	if err := rejectUnknownKeys(lockRefs, map[string]struct{}{
		"suiteToolingLock": {}, "repoToolingLock": {},
	}, "closureRef.lockRefs"); err != nil {
		return err
	}
	if _, ok := lockRefs["suiteToolingLock"]; !ok {
		return fmt.Errorf("closureRef.lockRefs: missing suiteToolingLock")
	}
	for key, raw := range lockRefs {
		if err := requireLocalFileRef(repoRoot, raw, "closureRef.lockRefs."+key, []string{"schemaVersion"}); err != nil {
			return err
		}
	}

	refs, err := requireObject(dec, "refs", "closureRef")
	if err != nil {
		return err
	}
	if err := rejectUnknownKeys(refs, map[string]struct{}{
		"standard": {}, "suite": {}, "factory": {}, "verifyRuntime": {}, "policyPack": {}, "generatorTemplate": {}, "standardSnapshot": {}, "collaborationEnhancement": {}, "controlPlane": {}, "enterpriseBundle": {},
	}, "closureRef.refs"); err != nil {
		return err
	}
	for _, key := range []string{"standard", "suite", "factory", "verifyRuntime"} {
		ref, err := validateStructuredRef(refs[key], "closureRef.refs."+key)
		if err != nil {
			return err
		}
		if key == "verifyRuntime" && ref.kind == "file" {
			return fmt.Errorf("closureRef.refs.verifyRuntime.kind must not be file")
		}
	}
	for _, key := range []string{"policyPack", "generatorTemplate", "standardSnapshot", "collaborationEnhancement", "controlPlane", "enterpriseBundle"} {
		if raw, ok := refs[key]; ok {
			if _, err := validateStructuredRef(raw, "closureRef.refs."+key); err != nil {
				return err
			}
		}
	}
	if rawProfiles, ok := dec["closureProfiles"]; ok {
		if err := validateClosureProfiles(rawProfiles, "closureRef.closureProfiles"); err != nil {
			return err
		}
	}
	return nil
}

// ValidateToolingLock loads the file at toolingLock (relative to repoRoot) and
// performs fail-closed validation aligned with the tooling_lock schema.
func ValidateToolingLock(repoRoot string, toolingLock string, closureRef string, registryRef string) error {
	dec, err := loadJSONObject(repoRoot, toolingLock, "toolingLock")
	if err != nil {
		return err
	}
	if err := rejectUnknownKeys(dec, map[string]struct{}{
		"$schema": {}, "schemaVersion": {}, "standardManifestVersion": {}, "sourceOfTruth": {}, "verifyRuntime": {}, "standardSnapshotRef": {}, "suiteVersionClosureRef": {}, "suiteLockRef": {}, "verifyRegistryRef": {}, "generatorTemplateVersion": {}, "policyPackVersion": {}, "toolchain": {}, "mirrors": {},
	}, "toolingLock"); err != nil {
		return err
	}
	for _, key := range []string{"schemaVersion", "standardManifestVersion"} {
		if _, err := requireString(dec, key, "toolingLock"); err != nil {
			return err
		}
	}
	sourceOfTruth, err := validateStructuredRef(dec["sourceOfTruth"], "toolingLock.sourceOfTruth")
	if err != nil {
		return err
	}
	if sourceOfTruth.kind == "file" {
		return fmt.Errorf("toolingLock.sourceOfTruth.kind must not be file")
	}
	verifyRuntime, err := validateStructuredRef(dec["verifyRuntime"], "toolingLock.verifyRuntime")
	if err != nil {
		return err
	}
	if verifyRuntime.kind == "file" {
		return fmt.Errorf("toolingLock.verifyRuntime.kind must not be file")
	}
	for _, key := range []string{"suiteVersionClosureRef", "suiteLockRef", "verifyRegistryRef"} {
		if _, ok := dec[key]; !ok {
			return fmt.Errorf("toolingLock: missing %s", key)
		}
	}
	for _, key := range []string{"standardSnapshotRef", "suiteVersionClosureRef", "suiteLockRef", "verifyRegistryRef"} {
		if raw, ok := dec[key]; ok {
			expected := []string{"schemaVersion"}
			switch key {
			case "suiteVersionClosureRef":
				expected = []string{"schemaVersion", "standardVersion", "suiteVersion", "closureUpdatedAt"}
			case "verifyRegistryRef":
				expected = []string{"schemaVersion", "registryId"}
			}
			if err := requireLocalFileRef(repoRoot, raw, "toolingLock."+key, expected); err != nil {
				return err
			}
		}
	}
	if rawToolchain, ok := dec["toolchain"]; !ok {
		return fmt.Errorf("toolingLock: missing toolchain")
	} else if err := validateToolchain(rawToolchain, "toolingLock.toolchain"); err != nil {
		return err
	}
	if rawMirrors, ok := dec["mirrors"]; ok {
		if err := validateMirrors(rawMirrors, "toolingLock.mirrors"); err != nil {
			return err
		}
	}
	if rawClosureRef, ok := dec["suiteVersionClosureRef"]; ok && strings.TrimSpace(closureRef) != "" {
		if resolved, ok := resolveLocalFileRefPath(repoRoot, rawClosureRef); ok {
			expected := filepath.Clean(filepath.Join(repoRoot, closureRef))
			if resolved != expected {
				return fmt.Errorf("toolingLock: suiteVersionClosureRef must point to %s", closureRef)
			}
		}
	}
	if rawRegistryRef, ok := dec["verifyRegistryRef"]; ok && strings.TrimSpace(registryRef) != "" {
		if resolved, ok := resolveLocalFileRefPath(repoRoot, rawRegistryRef); ok {
			expected := filepath.Clean(filepath.Join(repoRoot, registryRef))
			if resolved != expected {
				return fmt.Errorf("toolingLock: verifyRegistryRef must point to %s", registryRef)
			}
		}
	}
	return nil
}

// ValidateClosureToolingAlignment ensures the configured closure and tooling
// lock artifacts describe the same Cadence contract surface.
func ValidateClosureToolingAlignment(repoRoot string, closureRef string, toolingLock string) error {
	closure, err := loadJSONObject(repoRoot, closureRef, "closureRef")
	if err != nil {
		return err
	}
	tooling, err := loadJSONObject(repoRoot, toolingLock, "toolingLock")
	if err != nil {
		return err
	}
	closureManifestVersion, err := requireString(closure, "standardManifestVersion", "closureRef")
	if err != nil {
		return err
	}
	toolingManifestVersion, err := requireString(tooling, "standardManifestVersion", "toolingLock")
	if err != nil {
		return err
	}
	if closureManifestVersion != toolingManifestVersion {
		return fmt.Errorf("closure/tooling mismatch: standardManifestVersion differs")
	}
	refs, err := requireObject(closure, "refs", "closureRef")
	if err != nil {
		return err
	}
	if rawVerifyRuntime, ok := refs["verifyRuntime"]; ok {
		if !sameStructuredRef(rawVerifyRuntime, tooling["verifyRuntime"]) {
			return fmt.Errorf("closure/tooling mismatch: verifyRuntime refs differ")
		}
	}
	if rawLockRefs, ok := closure["lockRefs"]; ok {
		lockRefs, ok := rawLockRefs.(map[string]any)
		if !ok {
			return fmt.Errorf("closureRef.lockRefs must be an object")
		}
		if rawToolingRef, ok := lockRefs["suiteToolingLock"]; ok {
			if resolved, ok := resolveLocalFileRefPath(repoRoot, rawToolingRef); ok {
				expected := filepath.Clean(filepath.Join(repoRoot, toolingLock))
				if resolved != expected {
					return fmt.Errorf("closure/tooling mismatch: lockRefs.suiteToolingLock must point to %s", toolingLock)
				}
			}
		}
	}
	return nil
}
