package main

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/AzzCraft/cadence-oss/cadence-core/internal/exactjson"
	"github.com/AzzCraft/cadence-oss/cadence-core/internal/httpinventory"
)

// Caller pins prove byte consistency, never authority or actual coverage.
func httpInventoryProbe(value any) (any, error) {
	v, ok := value.(map[string]any)
	if !ok || len(v) != 2 {
		return nil, errors.New("invalid HTTP probe")
	}
	declaration, ok := v["declaration"]
	if !ok {
		return nil, errors.New("missing HTTP declaration")
	}
	sources, ok := v["originals"].([]any)
	if !ok || len(sources) > 8 {
		return nil, errors.New("invalid HTTP originals")
	}
	originals := map[string][]byte{}
	for _, item := range sources {
		source, ok := item.(map[string]any)
		if !ok || len(source) != 2 {
			return nil, errors.New("invalid HTTP source")
		}
		uri, ok := source["uri"].(string)
		if !ok {
			return nil, errors.New("invalid source URI")
		}
		text, ok := source["originalBase64"].(string)
		if !ok {
			return nil, errors.New("missing source bytes")
		}
		if _, exists := originals[uri]; exists {
			return nil, errors.New("duplicate source")
		}
		raw, err := base64.StdEncoding.Strict().DecodeString(text)
		if err != nil || base64.StdEncoding.EncodeToString(raw) != text {
			return nil, errors.New("invalid source encoding")
		}
		originals[uri] = raw
	}
	return httpinventory.Normalize(declaration, originals)
}

// Supplied baselines/observations are checked facts, not installation approval.
// The caller must obtain them from its separately protected collector/policy.
func httpCoverageProbe(value any) (any, error) {
	v, ok := value.(map[string]any)
	if !ok || len(v) != 4 {
		return nil, errors.New("invalid HTTP coverage probe")
	}
	inventory, ok := v["inventory"].(map[string]any)
	if !ok {
		return nil, errors.New("missing HTTP inventory")
	}
	complete, ok := v["observationComplete"].(bool)
	if !ok {
		return nil, errors.New("explicit HTTP observation completeness required")
	}
	baselineRows, ok := v["baseline"].([]any)
	if !ok || len(baselineRows) > 1024 {
		return nil, errors.New("invalid HTTP baseline")
	}
	observedRows, ok := v["observed"].([]any)
	if !ok || len(observedRows) > 1024 {
		return nil, errors.New("invalid HTTP observations")
	}
	baseline := make([]httpinventory.Identity, 0, len(baselineRows))
	observed := make([]httpinventory.Route, 0, len(observedRows))
	for _, raw := range baselineRows {
		row, ok := raw.(map[string]any)
		if !ok || len(row) != 3 {
			return nil, errors.New("invalid HTTP baseline identity")
		}
		id, idOK := row["operationId"].(string)
		method, methodOK := row["method"].(string)
		path, pathOK := row["path"].(string)
		if !idOK || !methodOK || !pathOK || len(id) > 128 || len(method) > 16 || len(path) > 2048 {
			return nil, errors.New("invalid HTTP baseline fields")
		}
		baseline = append(baseline, httpinventory.Identity{OperationID: id, Route: httpinventory.Route{Method: method, Path: path}})
	}
	for _, raw := range observedRows {
		row, ok := raw.(map[string]any)
		if !ok || len(row) != 2 {
			return nil, errors.New("invalid HTTP observation")
		}
		method, methodOK := row["method"].(string)
		path, pathOK := row["path"].(string)
		if !methodOK || !pathOK || len(method) > 16 || len(path) > 2048 {
			return nil, errors.New("invalid HTTP route fields")
		}
		observed = append(observed, httpinventory.Route{Method: method, Path: path})
	}
	coverage, err := httpinventory.CheckCoverage(inventory, baseline, observed, complete)
	if err != nil {
		return nil, err
	}
	original, err := exactjson.Canonical(value)
	if err != nil {
		return nil, err
	}
	return map[string]any{"coverage": coverage, "inputDigest": fmt.Sprintf("sha256:%x", sha256.Sum256(original)), "authority": false, "qualification": false}, nil
}
