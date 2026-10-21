package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/AzzCraft/cadence-oss/cadence-core/internal/replay"
	"github.com/AzzCraft/cadence-oss/cadence-core/internal/sanitize"
)

func main() {
	expectedPath := flag.String("expected", "", "path to the expected replay bundle")
	actualPath := flag.String("actual", "", "path to the independently produced replay bundle")
	flag.Parse()
	if *expectedPath == "" || *actualPath == "" {
		emit(map[string]any{
			"schemaVersion": 1,
			"task":          "CAD-003",
			"command":       "replay",
			"ok":            false,
			"code":          "MISSING_COMPARISON_INPUT",
			"message":       "CAD-003 replay compare requires distinct --expected and --actual bundle paths",
		})
		os.Exit(2)
	}
	left, leftErr := os.Stat(*expectedPath)
	right, rightErr := os.Stat(*actualPath)
	if *expectedPath == *actualPath || leftErr == nil && rightErr == nil && os.SameFile(left, right) {
		emit(map[string]any{"schemaVersion": 1, "task": "CAD-003", "command": "replay", "ok": false, "code": "IDENTICAL_INPUT_PATHS", "message": "expected and actual bundle paths must differ"})
		os.Exit(2)
	}
	expected, err := replay.Load(*expectedPath)
	if err != nil {
		emit(map[string]any{"schemaVersion": 1, "task": "CAD-003", "command": "replay", "ok": false, "code": "EXPECTED_BUNDLE_READ_FAILED", "message": fmt.Sprintf("CAD-003 expected bundle read failed: %v", err)})
		os.Exit(1)
	}
	actual, err := replay.Load(*actualPath)
	if err != nil {
		emit(map[string]any{
			"schemaVersion": 1,
			"task":          "CAD-003",
			"command":       "replay",
			"ok":            false,
			"code":          "ACTUAL_BUNDLE_READ_FAILED",
			"message":       fmt.Sprintf("CAD-003 actual bundle read failed: %v", err),
		})
		os.Exit(1)
	}
	report := replay.Compare(&expected, &actual)
	emit(report)
	if !report.Compare.Same {
		os.Exit(1)
	}
}

func emit(v any) {
	// Convert the known report/error DTOs to JSON-shaped values before redaction.
	// UseNumber preserves counters and comparison outcomes without float rounding.
	raw, err := json.Marshal(v)
	if err != nil {
		fmt.Fprintln(os.Stderr, "replay: invalid report")
		os.Exit(1)
	}
	var public any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&public); err != nil {
		fmt.Fprintln(os.Stderr, "replay: invalid report")
		os.Exit(1)
	}
	v = sanitize.SanitizeReport(public)
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		fmt.Fprintf(os.Stderr, "CAD-003 replay encode failed: %v\n", err)
	}
}
