package main

import (
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
	expectedOut := flag.String("expected-out", "", "artifact directory verified by the expected replay bundle")
	actualOut := flag.String("actual-out", "", "artifact directory verified by the actual replay bundle")
	flag.Parse()
	if *expectedPath == "" || *actualPath == "" || *expectedOut == "" || *actualOut == "" {
		emit(map[string]any{
			"schemaVersion": 1,
			"task":          "CAD-003",
			"command":       "replay",
			"ok":            false,
			"code":          "MISSING_COMPARISON_INPUT",
			"message":       "CAD-003 replay compare requires --expected, --actual, --expected-out, and --actual-out",
		})
		os.Exit(2)
	}
	expectedInfo, err := os.Stat(*expectedPath)
	if err != nil {
		emit(map[string]any{"schemaVersion": 1, "task": "CAD-003", "command": "replay", "ok": false, "code": "EXPECTED_BUNDLE_READ_FAILED", "message": fmt.Sprintf("CAD-003 expected bundle read failed: %v", err)})
		os.Exit(1)
	}
	actualInfo, err := os.Stat(*actualPath)
	if err != nil {
		emit(map[string]any{"schemaVersion": 1, "task": "CAD-003", "command": "replay", "ok": false, "code": "ACTUAL_BUNDLE_READ_FAILED", "message": fmt.Sprintf("CAD-003 actual bundle read failed: %v", err)})
		os.Exit(1)
	}
	if *expectedPath == *actualPath || os.SameFile(expectedInfo, actualInfo) {
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
	if err := replay.VerifyBundle(&expected, *expectedOut); err != nil {
		emit(map[string]any{"schemaVersion": 1, "task": "CAD-003", "command": "replay", "ok": false, "code": "EXPECTED_ARTIFACT_VERIFY_FAILED", "message": fmt.Sprintf("CAD-003 expected artifact verification failed: %v", err)})
		os.Exit(1)
	}
	if err := replay.VerifyBundle(&actual, *actualOut); err != nil {
		emit(map[string]any{"schemaVersion": 1, "task": "CAD-003", "command": "replay", "ok": false, "code": "ACTUAL_ARTIFACT_VERIFY_FAILED", "message": fmt.Sprintf("CAD-003 actual artifact verification failed: %v", err)})
		os.Exit(1)
	}
	report := replay.Compare(&expected, &actual)
	emit(sanitize.SanitizeReport(report))
	if !report.Compare.Same {
		os.Exit(1)
	}
}

func emit(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		fmt.Fprintf(os.Stderr, "CAD-003 replay encode failed: %v\n", err)
	}
}
