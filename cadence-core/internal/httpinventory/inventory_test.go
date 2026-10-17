package httpinventory

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"
)

const entry = "https://test.invalid/api/openapi.json"

func sample(t *testing.T, edit func(map[string]any)) (map[string]any, map[string][]byte) {
	t.Helper()
	raw := []byte(`{"openapi":"3.1.1","info":{"title":"TEST reference","version":"1"},"security":[{"bearer":[]}],"components":{"securitySchemes":{"bearer":{"type":"http","scheme":"bearer"},"key":{"type":"apiKey","in":"header","name":"X-Key"}},"schemas":{"Node":{"type":"object","properties":{"next":{"$ref":"#/components/schemas/Node"}}}}},"paths":{"/target":{"get":{"operationId":"readTarget","responses":{"200":{"description":"target"}}}},"/integrations":{"put":{"operationId":"integrateTarget","responses":{"200":{"description":"receipt"}}}}}}`)
	root := map[string]any{}
	if err := json.Unmarshal(raw, &root); err != nil {
		t.Fatal(err)
	}
	if edit != nil {
		edit(root)
	}
	raw, err := json.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	declaration := map[string]any{"contractIdentity": "das-http-declaration/v1", "scope": "TEST-only-surface", "sourceDirection": "openapi-first", "rootURI": entry, "sources": []any{map[string]any{"uri": entry, "sha256": digest(raw)}}}
	return declaration, map[string][]byte{entry: raw}
}
func get(t *testing.T, inventory map[string]any, id string) map[string]any {
	t.Helper()
	for _, op := range inventory["operations"].([]any) {
		v := op.(map[string]any)
		if v["operationId"] == id {
			return v
		}
	}
	t.Fatalf("independent expected operation absent: %s", id)
	return nil
}
func TestSecurityORANDInheritanceAndAnonymous(t *testing.T) {
	for _, options := range []any{[]any{}, []any{map[string]any{}}, []any{map[string]any{"bearer": []any{}, "key": []any{}}}, []any{map[string]any{"bearer": []any{}}, map[string]any{"key": []any{}}}} {
		declaration, raw := sample(t, func(root map[string]any) {
			root["paths"].(map[string]any)["/integrations"].(map[string]any)["put"].(map[string]any)["security"] = options
		})
		inventory, err := Normalize(declaration, raw)
		if err != nil {
			t.Fatal(err)
		}
		read := get(t, inventory, "readTarget")
		write := get(t, inventory, "integrateTarget")
		if read["securityOrigin"] != "root" || write["securityOrigin"] != "operation" || !reflect.DeepEqual(write["security"], options) {
			t.Fatalf("security grouping/override changed: %v", inventory)
		}
		if inventory["qualification"] != false || inventory["authority"] != false || inventory["declaredCoverage"] != "unknown" {
			t.Fatal("projection acquired authority")
		}
	}
}
func TestNativeDialectDifferenceAndBoundedSchemaRecursion(t *testing.T) {
	for _, version := range []string{"3.0.3", "3.1.1"} {
		declaration, raw := sample(t, func(root map[string]any) { root["openapi"] = version })
		inventory, err := Normalize(declaration, raw)
		if err != nil {
			t.Fatal(err)
		}
		if inventory["openapiVersion"] != version || len(inventory["referenceTargets"].([]any)) != 1 {
			t.Fatal("lost version or schema recursion")
		}
		declaration, raw = sample(t, func(root map[string]any) {
			root["openapi"] = version
			root["security"] = []any{map[string]any{"bearer": []any{"operator"}}}
		})
		_, err = Normalize(declaration, raw)
		if (err == nil) != (version == "3.1.1") {
			t.Fatal("native non-OAuth role-array distinction was erased")
		}
	}
}
func TestLockedExternalReferenceUsesItsOriginalBaseURI(t *testing.T) {
	declaration, raw := sample(t, func(root map[string]any) {
		root["paths"].(map[string]any)["/target"] = map[string]any{"$ref": "routes.json#/read"}
	})
	external := "https://test.invalid/api/routes.json"
	bytes := []byte(`{"read":{"get":{"operationId":"readTarget","responses":{"200":{"description":"read","content":{"application/json":{"schema":{"$ref":"#/Node"}}}}}}},"Node":{"type":"object","properties":{"child":{"$ref":"#/Node"}}}}`)
	declaration["sources"] = append(declaration["sources"].([]any), map[string]any{"uri": external, "sha256": digest(bytes)})
	raw[external] = bytes
	inventory, err := Normalize(declaration, raw)
	if err != nil {
		t.Fatal(err)
	}
	if get(t, inventory, "readTarget")["documentURI"] != external {
		t.Fatal("referenced operation lost original base URI")
	}
	if len(inventory["referenceTargets"].([]any)) != 3 {
		t.Fatal("reference closure incorrectly expanded recursion or lost a target")
	}
	delete(raw, external)
	if _, err = Normalize(declaration, raw); err == nil {
		t.Fatal("missing locked external bytes accepted")
	}
}
func TestConflictingAuthorsMalformedSecurityAndUnpinnedReferencesFail(t *testing.T) {
	edits := map[string]func(map[string]any){
		"unsupported-version": func(r map[string]any) { r["openapi"] = "3.2.1" },
		"unsupported-dialect": func(r map[string]any) { r["jsonSchemaDialect"] = "https://unapproved.invalid/dialect" },
		"missing-scheme":      func(r map[string]any) { r["security"] = []any{map[string]any{"missing": []any{}}} },
		"null-security":       func(r map[string]any) { r["security"] = nil },
		"flat-instead-of-OR":  func(r map[string]any) { r["security"] = map[string]any{"bearer": []any{}} },
		"reused-id": func(r map[string]any) {
			r["paths"].(map[string]any)["/integrations"].(map[string]any)["put"].(map[string]any)["operationId"] = "readTarget"
		},
		"unlocked-ref": func(r map[string]any) {
			r["components"].(map[string]any)["schemas"].(map[string]any)["Node"] = map[string]any{"$ref": "https://unapproved.invalid/Node"}
		},
		"missing-ref-target": func(r map[string]any) {
			r["components"].(map[string]any)["schemas"].(map[string]any)["Node"] = map[string]any{"$ref": "#/missing"}
		},
		"invalid-pointer": func(r map[string]any) {
			r["components"].(map[string]any)["schemas"].(map[string]any)["Node"] = map[string]any{"$ref": "#/a~2b"}
		},
		"unimplemented-dynamic-reference": func(r map[string]any) {
			r["components"].(map[string]any)["schemas"].(map[string]any)["Node"] = map[string]any{"$dynamicRef": "#node"}
		},
		"callbacks-unimplemented": func(r map[string]any) {
			r["paths"].(map[string]any)["/integrations"].(map[string]any)["put"].(map[string]any)["callbacks"] = map[string]any{}
		},
		"path-item-two-authors": func(r map[string]any) {
			r["paths"].(map[string]any)["/target"].(map[string]any)["$ref"] = "#/paths/~1integrations"
		},
	}
	for name, edit := range edits {
		t.Run(name, func(t *testing.T) {
			declaration, raw := sample(t, edit)
			if _, err := Normalize(declaration, raw); err == nil {
				t.Fatal("invalid declaration accepted")
			}
		})
	}
	declaration, raw := sample(t, nil)
	declaration["codeAuthor"] = entry
	if _, err := Normalize(declaration, raw); err == nil {
		t.Fatal("second author accepted")
	}
	declaration, raw = sample(t, nil)
	raw[entry] = append(raw[entry], ' ')
	if _, err := Normalize(declaration, raw); err == nil {
		t.Fatal("original bytes no longer match pin")
	}
}
func TestIndependentCoverageDetectsDeletionReuseAndUnknownObservations(t *testing.T) {
	declaration, raw := sample(t, nil)
	inventory, err := Normalize(declaration, raw)
	if err != nil {
		t.Fatal(err)
	}
	baseline := []Identity{{"readTarget", Route{"GET", "/target"}}, {"integrateTarget", Route{"PUT", "/integrations"}}}
	observed := []Route{{"GET", "/target"}, {"PUT", "/integrations"}}
	if result, err := CheckCoverage(inventory, baseline, observed, true); err != nil || result != "matched" {
		t.Fatal(result, err)
	}
	for _, input := range []struct {
		routes   []Route
		complete bool
	}{{observed[:1], true}, {nil, false}, {observed, false}} {
		if result, err := CheckCoverage(inventory, baseline, input.routes, input.complete); err != nil || result != "unknown" {
			t.Fatal("absence inferred from incomplete observation", result, err)
		}
	}
	if _, err := CheckCoverage(inventory, baseline, append(observed, Route{"DELETE", "/target"}), true); err == nil {
		t.Fatal("undeclared actual route accepted")
	}
	inventory["operations"] = inventory["operations"].([]any)[:1]
	if _, err := CheckCoverage(inventory, baseline, observed, true); err == nil {
		t.Fatal("deleting declaration silently shrank coverage")
	}
	declaration, raw = sample(t, func(r map[string]any) {
		r["paths"].(map[string]any)["/target"].(map[string]any)["get"].(map[string]any)["operationId"] = "newIdentity"
	})
	inventory, err = Normalize(declaration, raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CheckCoverage(inventory, baseline, observed, true); err == nil {
		t.Fatal("historical operation identity changed")
	}
}

func TestSchemaResourceBasesAndLiteralPropertyNamesStayDistinct(t *testing.T) {
	declaration, raw := sample(t, func(root map[string]any) {
		root["components"].(map[string]any)["schemas"].(map[string]any)["Node"] = map[string]any{
			"$id": "./node.json", "type": "object", "properties": map[string]any{
				"$id": map[string]any{"type": "string"}, "$ref": map[string]any{"type": "string"},
				"child": map[string]any{"$ref": "#"},
			}, "default": map[string]any{"$ref": "literal instance data"},
		}
	})
	inventory, err := Normalize(declaration, raw)
	if err != nil {
		t.Fatal(err)
	}
	targets := inventory["referenceTargets"].([]any)
	if len(targets) != 1 || targets[0] != "https://test.invalid/api/node.json" {
		t.Fatalf("schema resource base changed: %v", targets)
	}
	declaration, raw = sample(t, func(root map[string]any) {
		nodes := root["components"].(map[string]any)["schemas"].(map[string]any)
		nodes["A"] = map[string]any{"$id": "./collision.json"}
		nodes["B"] = map[string]any{"$id": "./collision.json"}
	})
	if _, err = Normalize(declaration, raw); err == nil {
		t.Fatal("duplicate embedded resource writers accepted")
	}
}

func TestDeclaredORANDAndAnonymousHaveSeparateActualBoundaryProbes(t *testing.T) {
	declaration, raw := sample(t, func(root map[string]any) {
		paths := root["paths"].(map[string]any)
		for path, settings := range map[string]struct {
			id      string
			options []any
		}{
			"/public": {"readPublic", []any{}},
			"/and":    {"andAccess", []any{map[string]any{"bearer": []any{}, "key": []any{}}}},
			"/or":     {"orAccess", []any{map[string]any{"bearer": []any{}}, map[string]any{"key": []any{}}}},
		} {
			paths[path] = map[string]any{"get": map[string]any{"operationId": settings.id, "security": settings.options, "responses": map[string]any{"200": map[string]any{"description": "TEST read"}}}}
		}
	})
	inventory, err := Normalize(declaration, raw)
	if err != nil {
		t.Fatal(err)
	}
	if get(t, inventory, "readPublic")["securityOrigin"] != "operation" || len(get(t, inventory, "andAccess")["security"].([]any)) != 1 || len(get(t, inventory, "orAccess")["security"].([]any)) != 2 {
		t.Fatal("declaration semantics lost")
	}
	// Independent fixed test resource rules, not generated from inventory.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bearer, key := r.Header.Get("Authorization") == "Bearer TEST-worker", r.Header.Get("X-Key") == "TEST-key"
		allowed := r.URL.Path == "/public" || (r.URL.Path == "/target" && bearer) || (r.URL.Path == "/and" && bearer && key) || (r.URL.Path == "/or" && (bearer || key))
		if !allowed {
			w.WriteHeader(401)
			return
		}
		w.WriteHeader(200)
	}))
	defer server.Close()
	transport := &http.Transport{Proxy: nil}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: time.Second}
	for _, probe := range []struct {
		path        string
		bearer, key bool
		status      int
	}{
		{"/public", false, false, 200}, {"/target", false, false, 401}, {"/target", true, false, 200},
		{"/and", true, false, 401}, {"/and", false, true, 401}, {"/and", true, true, 200},
		{"/or", false, false, 401}, {"/or", true, false, 200}, {"/or", false, true, 200},
	} {
		request, err := http.NewRequest("GET", server.URL+probe.path, nil)
		if err != nil {
			t.Fatal(err)
		}
		if probe.bearer {
			request.Header.Set("Authorization", "Bearer TEST-worker")
		}
		if probe.key {
			request.Header.Set("X-Key", "TEST-key")
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != probe.status {
			t.Fatalf("actual boundary disagrees for %s: %d", probe.path, response.StatusCode)
		}
	}
}
