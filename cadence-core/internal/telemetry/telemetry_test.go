package telemetry

import (
	"testing"
	"time"
)

func TestCounterAndGaugeAndTimer(t *testing.T) {
	r := NewRegistry()
	r.IncrCounter("runs", 3)
	r.IncrCounter("runs", 2)
	r.SetGauge("memory_mb", 128)
	r.ObserveDuration("phase", 10*time.Millisecond)
	r.ObserveDuration("phase", 30*time.Millisecond)
	r.ObserveDuration("phase", 20*time.Millisecond)

	s := r.Snapshot()
	if s.Counters["runs"] != 5 {
		t.Fatalf("counter runs got %d", s.Counters["runs"])
	}
	if s.Gauges["memory_mb"] != 128 {
		t.Fatalf("gauge memory_mb got %v", s.Gauges["memory_mb"])
	}
	ts := s.Timers["phase"]
	if ts.Count != 3 || ts.Min != 10*time.Millisecond || ts.Max != 30*time.Millisecond ||
		ts.Total != 60*time.Millisecond {
		t.Fatalf("timer stats wrong: %+v", ts)
	}
}

func TestSnapshotIsCopy(t *testing.T) {
	r := NewRegistry()
	r.IncrCounter("a", 1)
	s := r.Snapshot()
	s.Counters["a"] = 999
	s2 := r.Snapshot()
	if s2.Counters["a"] != 1 {
		t.Fatal("snapshot must be a copy")
	}
}
