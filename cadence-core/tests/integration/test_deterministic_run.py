from __future__ import annotations

import json
from pathlib import Path


CORE_ROOT = Path(__file__).resolve().parents[2]




def test_cad_001_golden_fixed_clock_report_is_stable_and_diagnostic() -> None:
    report = json.loads(
        (CORE_ROOT / "tests" / "fixtures" / "cad001" / "deterministic_run_contract.json").read_text(
            encoding="utf-8"
        )
    )

    assert report["task"] == "CAD-001"
    assert report["fixedClock"] == "2026-04-25T00:00:00Z"
    repeated = report["repeatedRuns"]
    assert repeated[0]["runId"] == repeated[1]["runId"]
    assert repeated[0]["timestamp"] == repeated[1]["timestamp"] == report["fixedClock"]
    assert report["changedAttempt"]["runId"] != repeated[0]["runId"]
    assert report["changedInput"]["runId"] != repeated[0]["runId"]
    diagnostic = report["diagnostics"][0]
    assert diagnostic["task"] == "CAD-001"
    assert diagnostic["field"] == "timestamp"
    assert "CAD-001" in diagnostic["message"]
    assert "timestamp" in diagnostic["message"]
