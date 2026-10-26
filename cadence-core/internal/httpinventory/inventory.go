// Package httpinventory projects declared HTTP operations from locked original
// JSON OpenAPI documents. It does not approve facts, validate request schemas,
// authenticate callers, fetch references or prove actual surface coverage.
package httpinventory

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/AzzCraft/cadence-oss/cadence-core/internal/exactjson"
	"github.com/santhosh-tekuri/jsonschema/v5"
)

//go:embed http_declaration.schema.json
var declarationSchema []byte

//go:embed http_inventory.schema.json
var inventorySchema []byte

// ValidOperationID matches the schema's Unicode character limit. Body and
// document limits remain byte budgets and must not use this function.
func ValidOperationID(id string) bool {
	return id != "" && utf8.ValidString(id) && utf8.RuneCountInString(id) <= 128
}

func rejected() error {
	return errors.New("http-inventory: unsupported, conflicting or incomplete declaration")
}
func digest(data []byte) string { return fmt.Sprintf("sha256:%x", sha256.Sum256(data)) }
func object(value any) (map[string]any, error) {
	v, ok := value.(map[string]any)
	if !ok {
		return nil, rejected()
	}
	return v, nil
}
func Validate(value any, identity string) error {
	data, ok := map[string][]byte{"das-http-declaration/v1": declarationSchema, "das-http-inventory/v1": inventorySchema}[identity]
	if !ok {
		return rejected()
	}
	compiler := jsonschema.NewCompiler()
	compiler.Draft = jsonschema.Draft2020
	compiler.AssertFormat = true
	compiler.LoadURL = func(string) (io.ReadCloser, error) { return nil, rejected() }
	const location = "https://cadence.das.dev/embedded/http-reference"
	if err := compiler.AddResource(location, bytes.NewReader(data)); err != nil {
		return err
	}
	schema, err := compiler.Compile(location)
	if err != nil {
		return err
	}
	return schema.Validate(value)
}

func sourceURI(text string) (*url.URL, error) {
	u, err := url.Parse(text)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" || u.String() != text {
		return nil, rejected()
	}
	return u, nil
}
func pointer(value any, fragment string) (any, error) {
	if fragment == "" {
		return value, nil
	}
	if !strings.HasPrefix(fragment, "/") {
		return nil, rejected()
	}
	for _, part := range strings.Split(fragment[1:], "/") {
		for i := 0; i < len(part); i++ {
			if part[i] == '~' && (i+1 == len(part) || (part[i+1] != '0' && part[i+1] != '1')) {
				return nil, rejected()
			}
			if part[i] == '~' {
				i++
			}
		}
		part = strings.ReplaceAll(strings.ReplaceAll(part, "~1", "/"), "~0", "~")
		switch v := value.(type) {
		case map[string]any:
			var ok bool
			value, ok = v[part]
			if !ok {
				return nil, rejected()
			}
		case []any:
			i, err := strconv.Atoi(part)
			if err != nil || i < 0 || i >= len(v) || strconv.Itoa(i) != part {
				return nil, rejected()
			}
			value = v[i]
		default:
			return nil, rejected()
		}
	}
	return value, nil
}

type documents struct {
	values    map[string]any
	resources map[string]any
	targets   map[string]bool
	visited   int
	indexed   int
}

func schemaBase(base string, value map[string]any) (string, error) {
	raw, exists := value["$id"]
	if !exists {
		return base, nil
	}
	id, ok := raw.(string)
	if !ok || id == "" {
		return "", rejected()
	}
	origin, err := sourceURI(base)
	if err != nil {
		return "", err
	}
	relative, err := url.Parse(id)
	if err != nil {
		return "", rejected()
	}
	result := origin.ResolveReference(relative).String()
	if _, err := sourceURI(result); err != nil {
		return "", err
	}
	return result, nil
}

func instanceData(key string) bool {
	return key == "example" || key == "examples" || key == "default" || key == "const" || key == "enum" || strings.HasPrefix(key, "x-")
}

func schemaContainer(key string) bool {
	return key == "$defs" || key == "definitions" || key == "properties" || key == "patternProperties" || key == "dependentSchemas" || key == "schemas"
}

// kind distinguishes structural maps from schema instance values. In
// particular responses.default is a Response, whereas schema.default is data.
func children(value map[string]any, base string, depth int, kind string, visit func(any, string, int, string) error) error {
	if kind == "auto" {
		kind = "structural"
		for _, key := range []string{"$schema", "$id", "$defs", "properties", "allOf", "anyOf", "oneOf", "default", "const", "enum"} {
			if _, ok := value[key]; ok {
				kind = "schema"
				break
			}
		}
	}
	for key, child := range value {
		if strings.HasPrefix(key, "x-") || kind == "schema" && instanceData(key) || kind == "example" && key == "value" || kind != "schema" && key == "example" {
			continue
		}
		childKind := "auto"
		if key == "components" {
			childKind = "components"
		}
		if kind == "schema" {
			childKind = "schema"
		}
		if key == "schema" {
			childKind = "schema"
		}
		// Mappings have literal names; their values are the structural authors.
		mappingKind := ""
		if kind == "schema" && schemaContainer(key) || key == "schemas" {
			mappingKind = "schema"
		}
		if kind != "schema" && key == "responses" {
			mappingKind = "response"
		}
		if kind != "schema" && key == "examples" {
			mappingKind = "example"
		}
		if kind == "components" {
			switch key {
			case "schemas":
				mappingKind = "schema"
			case "examples":
				mappingKind = "example"
			case "parameters", "headers", "requestBodies", "responses", "links", "callbacks", "securitySchemes", "pathItems":
				mappingKind = "structural"
			}
		}
		if mappingKind != "" {
			entries, err := object(child)
			if err != nil {
				return err
			}
			for _, node := range entries {
				if err := visit(node, base, depth+1, mappingKind); err != nil {
					return err
				}
			}
		} else if err := visit(child, base, depth+1, childKind); err != nil {
			return err
		}
	}
	return nil
}

// Embedded schema resource IDs are logical bases inside already locked bytes,
// not additional downloaded documents. Duplicate resource writers are refused.
func (d *documents) index(value any, base string, depth int, kind string) error {
	d.indexed++
	if d.indexed > 100000 || depth > 64 {
		return rejected()
	}
	switch v := value.(type) {
	case map[string]any:
		next, err := schemaBase(base, v)
		if err != nil {
			return err
		}
		if _, exists := v["$id"]; exists {
			if _, collision := d.resources[next]; collision && !(depth == 0 && next == base) {
				return rejected()
			}
			d.resources[next] = value
		}
		return children(v, next, depth, kind, d.index)
	case []any:
		for _, child := range v {
			if err := d.index(child, base, depth+1, kind); err != nil {
				return err
			}
		}
	}
	return nil
}

func (d *documents) resolve(base, reference string) (any, string, string, error) {
	b, err := sourceURI(base)
	if err != nil {
		return nil, "", "", err
	}
	r, err := url.Parse(reference)
	if err != nil {
		return nil, "", "", rejected()
	}
	absolute := b.ResolveReference(r)
	target := absolute.String()
	fragment := absolute.Fragment
	absolute.Fragment = ""
	original, ok := d.resources[absolute.String()]
	if !ok {
		return nil, "", "", rejected()
	}
	value, err := pointer(original, fragment)
	if err != nil {
		return nil, "", "", err
	}
	d.targets[target] = true
	if len(d.targets) > 4096 {
		return nil, "", "", rejected()
	}
	return value, absolute.String(), target, nil
}

// Walk original structural nodes, never recursively expand a schema reference.
// Self/mutual schema references are valid; absent locked targets are not.
func (d *documents) walk(value any, base string, depth int, kind string) error {
	d.visited++
	if d.visited > 100000 || depth > 64 {
		return rejected()
	}
	switch v := value.(type) {
	case map[string]any:
		for _, key := range []string{"$anchor", "$dynamicRef", "$dynamicAnchor"} {
			if _, ok := v[key]; ok {
				return rejected()
			}
		}
		var err error
		base, err = schemaBase(base, v)
		if err != nil {
			return err
		}
		if dialect, ok := v["$schema"]; ok && dialect != "https://json-schema.org/draft/2020-12/schema" && dialect != "https://spec.openapis.org/oas/3.1/dialect/base" {
			return rejected()
		}
		if ref, ok := v["$ref"]; ok {
			r, ok := ref.(string)
			if !ok {
				return rejected()
			}
			if _, _, _, err := d.resolve(base, r); err != nil {
				return err
			}
		}
		return children(v, base, depth, kind, d.walk)
	case []any:
		for _, child := range v {
			if err := d.walk(child, base, depth+1, kind); err != nil {
				return err
			}
		}
	}
	return nil
}
func (d *documents) referencedObject(value any, base string, referenceVersion string) (map[string]any, string, error) {
	seen := map[string]bool{}
	for i := 0; i < 32; i++ {
		v, err := object(value)
		if err != nil {
			return nil, "", err
		}
		raw, ok := v["$ref"]
		if !ok {
			return v, base, nil
		}
		ref, ok := raw.(string)
		if !ok {
			return nil, "", rejected()
		}
		// Path Item sibling precedence is undefined. Do not silently choose a writer.
		for key, sibling := range v {
			if key == "$ref" {
				continue
			}
			if referenceVersion == "3.0.3" {
				continue
			} // Reference siblings are ignored by OAS 3.0.
			if referenceVersion != "3.1.1" || (key != "summary" && key != "description") {
				return nil, "", rejected()
			}
			if _, ok := sibling.(string); !ok {
				return nil, "", rejected()
			}
		}
		var target string
		value, base, target, err = d.resolve(base, ref)
		if err != nil || seen[target] {
			return nil, "", rejected()
		}
		seen[target] = true
	}
	return nil, "", rejected()
}
func security(value any, schemes map[string]any, version string, docs *documents, rootURI string) ([]any, error) {
	if value == nil {
		return nil, rejected()
	}
	options, ok := value.([]any)
	if !ok || len(options) > 64 {
		return nil, rejected()
	}
	out := []any{}
	for _, option := range options {
		names, err := object(option)
		if err != nil || len(names) > 32 {
			return nil, rejected()
		}
		normalized := map[string]any{}
		for name, raw := range names {
			rawScheme, ok := schemes[name]
			if !ok {
				return nil, rejected()
			}
			scheme, _, err := docs.referencedObject(rawScheme, rootURI, version)
			if err != nil {
				return nil, err
			}
			kind, ok := scheme["type"].(string)
			if !ok {
				return nil, rejected()
			}
			switch kind {
			case "http", "apiKey", "oauth2", "openIdConnect", "mutualTLS":
			default:
				return nil, rejected()
			}
			if version == "3.0.3" && kind == "mutualTLS" {
				return nil, rejected()
			}
			scopes, ok := raw.([]any)
			if !ok || len(scopes) > 64 {
				return nil, rejected()
			}
			if version == "3.0.3" && kind != "oauth2" && kind != "openIdConnect" && len(scopes) != 0 {
				return nil, rejected()
			}
			texts := []string{}
			for _, scope := range scopes {
				s, ok := scope.(string)
				if !ok || s == "" || len(s) > 256 {
					return nil, rejected()
				}
				texts = append(texts, s)
			}
			sort.Strings(texts)
			items := []any{}
			for _, s := range texts {
				items = append(items, s)
			}
			normalized[name] = items
		}
		out = append(out, normalized)
	}
	// Options are OR; names inside one option remain AND, including legal {}.
	sort.SliceStable(out, func(i, j int) bool {
		a, _ := exactjson.Canonical(out[i])
		b, _ := exactjson.Canonical(out[j])
		return bytes.Compare(a, b) < 0
	})
	return out, nil
}

// Normalize is an OpenAPI-first reference projection. The declaration pins all
// original JSON bytes and base URIs. A caller cannot add an unpinned document.
func Normalize(declaration any, originals map[string][]byte) (map[string]any, error) {
	if err := Validate(declaration, "das-http-declaration/v1"); err != nil {
		return nil, rejected()
	}
	decl := declaration.(map[string]any)
	rootURI := decl["rootURI"].(string)
	docs := &documents{values: map[string]any{}, resources: map[string]any{}, targets: map[string]bool{}}
	total := 0
	for _, item := range decl["sources"].([]any) {
		source := item.(map[string]any)
		uri := source["uri"].(string)
		if _, err := sourceURI(uri); err != nil {
			return nil, err
		}
		if _, exists := docs.values[uri]; exists {
			return nil, rejected()
		}
		raw, ok := originals[uri]
		total += len(raw)
		if !ok || total > 1024*1024 || digest(raw) != source["sha256"] {
			return nil, rejected()
		}
		value, err := exactjson.Parse(raw)
		if err != nil {
			return nil, rejected()
		}
		docs.values[uri] = value
		docs.resources[uri] = value
	}
	if len(docs.values) != len(originals) {
		return nil, rejected()
	}
	rawRoot, ok := docs.values[rootURI]
	if !ok {
		return nil, rejected()
	}
	root, err := object(rawRoot)
	if err != nil {
		return nil, err
	}
	version, ok := root["openapi"].(string)
	if !ok || (version != "3.0.3" && version != "3.1.1") {
		return nil, rejected()
	}
	dialect := "oas-3.0.3-schema-object"
	if version == "3.1.1" {
		dialect = "https://spec.openapis.org/oas/3.1/dialect/base"
	}
	if explicit, exists := root["jsonSchemaDialect"]; exists {
		if version != "3.1.1" || (explicit != dialect && explicit != "https://json-schema.org/draft/2020-12/schema") {
			return nil, rejected()
		}
		dialect = explicit.(string)
	}
	if _, exists := root["webhooks"]; exists {
		return nil, rejected()
	}
	for uri, value := range docs.values {
		if err := docs.index(value, uri, 0, "auto"); err != nil {
			return nil, err
		}
	}
	for uri, value := range docs.values {
		if err := docs.walk(value, uri, 0, "auto"); err != nil {
			return nil, err
		}
	}
	paths, err := object(root["paths"])
	if err != nil {
		return nil, err
	}
	schemes := map[string]any{}
	if components, exists := root["components"]; exists {
		c, err := object(components)
		if err != nil {
			return nil, err
		}
		if raw, exists := c["securitySchemes"]; exists {
			schemes, err = object(raw)
			if err != nil {
				return nil, err
			}
		}
	}
	inherited := []any{}
	if raw, exists := root["security"]; exists {
		inherited, err = security(raw, schemes, version, docs, rootURI)
		if err != nil {
			return nil, err
		}
	}
	methods := map[string]bool{}
	for _, m := range []string{"get", "put", "post", "delete", "options", "head", "patch", "trace"} {
		methods[m] = true
	}
	ids := map[string]bool{}
	operations := []any{}
	for path, raw := range paths {
		if strings.HasPrefix(path, "x-") {
			continue
		}
		if !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "\r\n?#") || len(path) > 2048 {
			return nil, rejected()
		}
		item, base, err := docs.referencedObject(raw, rootURI, "")
		if err != nil {
			return nil, err
		}
		for method, rawOp := range item {
			if !methods[method] {
				if method == "summary" || method == "description" || method == "parameters" || method == "servers" || strings.HasPrefix(method, "x-") {
					continue
				}
				return nil, rejected()
			}
			op, err := object(rawOp)
			if err != nil {
				return nil, err
			}
			id, ok := op["operationId"].(string)
			if !ok || !ValidOperationID(id) || ids[id] {
				return nil, rejected()
			}
			ids[id] = true
			if _, exists := op["callbacks"]; exists {
				return nil, rejected()
			}
			origin := "root"
			selected := inherited
			if _, exists := root["security"]; !exists {
				origin = "absent"
			}
			if raw, exists := op["security"]; exists {
				origin = "operation"
				selected, err = security(raw, schemes, version, docs, rootURI)
				if err != nil {
					return nil, err
				}
			}
			operations = append(operations, map[string]any{"operationId": id, "method": strings.ToUpper(method), "path": path, "documentURI": base, "securityOrigin": origin, "security": selected})
			if len(operations) > 1024 {
				return nil, rejected()
			}
		}
	}
	sort.Slice(operations, func(i, j int) bool {
		return operations[i].(map[string]any)["operationId"].(string) < operations[j].(map[string]any)["operationId"].(string)
	})
	targets := []any{}
	sorted := []string{}
	for target := range docs.targets {
		sorted = append(sorted, target)
	}
	sort.Strings(sorted)
	for _, target := range sorted {
		targets = append(targets, target)
	}
	declBytes, err := exactjson.Canonical(declaration)
	if err != nil {
		return nil, rejected()
	}
	result := map[string]any{"contractIdentity": "das-http-inventory/v1", "declarationDigest": digest(declBytes), "scope": decl["scope"], "openapiVersion": version, "jsonSchemaDialect": dialect, "operations": operations, "referenceTargets": targets, "declaredCoverage": "unknown", "schemaValidation": false, "authority": false, "qualification": false}
	if err := Validate(result, "das-http-inventory/v1"); err != nil {
		return nil, rejected()
	}
	return result, nil
}

type Route struct{ Method, Path string }
type Identity struct {
	OperationID string
	Route       Route
}

// Independent registered routes and approved baseline are distinct inputs.
// A missing observation never proves absence. Removal/ID reuse needs a new
// separately approved baseline; changing a candidate declaration cannot do it.
func CheckCoverage(inventory map[string]any, baseline []Identity, observed []Route, observationComplete bool) (string, error) {
	if err := Validate(inventory, "das-http-inventory/v1"); err != nil {
		return "", rejected()
	}
	expected := map[Route]string{}
	ids := map[string]bool{}
	for _, entry := range baseline {
		if entry.OperationID == "" || ids[entry.OperationID] || expected[entry.Route] != "" {
			return "", rejected()
		}
		expected[entry.Route] = entry.OperationID
		ids[entry.OperationID] = true
	}
	declared := map[Route]string{}
	for _, raw := range inventory["operations"].([]any) {
		op := raw.(map[string]any)
		route := Route{op["method"].(string), op["path"].(string)}
		id := op["operationId"].(string)
		if declared[route] != "" || expected[route] != id {
			return "", rejected()
		}
		declared[route] = id
	}
	if len(declared) != len(expected) {
		return "", rejected()
	}
	seen := map[Route]bool{}
	for _, route := range observed {
		if seen[route] || declared[route] == "" {
			return "", rejected()
		}
		seen[route] = true
	}
	if !observationComplete || len(seen) != len(expected) {
		return "unknown", nil
	}
	return "matched", nil
}
