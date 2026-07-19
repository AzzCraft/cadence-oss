// Package telemetry — minimal in-memory metric counters / timers used by
// the runtime and exported via the standard observability adapter.
package telemetry

import (
	"sort"
	"sync"
	"time"
)

// Registry is a thread-safe collection of counters and gauges.
type Registry struct {
	mu       sync.Mutex
	counters map[string]int64
	gauges   map[string]float64
	timers   map[string][]time.Duration
}

// NewRegistry returns a fresh Registry.
func NewRegistry() *Registry {
	return &Registry{
		counters: map[string]int64{},
		gauges:   map[string]float64{},
		timers:   map[string][]time.Duration{},
	}
}

// IncrCounter adds delta to the named counter.
func (r *Registry) IncrCounter(name string, delta int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.counters[name] += delta
}

// SetGauge sets the named gauge to v.
func (r *Registry) SetGauge(name string, v float64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.gauges[name] = v
}

// ObserveDuration records a duration sample for the named timer.
func (r *Registry) ObserveDuration(name string, d time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.timers[name] = append(r.timers[name], d)
}

// Snapshot returns a deterministic, sorted snapshot.
type Snapshot struct {
	Counters map[string]int64
	Gauges   map[string]float64
	Timers   map[string]TimerStats
}

// TimerStats summarizes recorded durations.
type TimerStats struct {
	Count int
	Total time.Duration
	Min   time.Duration
	Max   time.Duration
}

// Snapshot returns a copy of the current registry state.
func (r *Registry) Snapshot() Snapshot {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := Snapshot{
		Counters: make(map[string]int64, len(r.counters)),
		Gauges:   make(map[string]float64, len(r.gauges)),
		Timers:   make(map[string]TimerStats, len(r.timers)),
	}
	for k, v := range r.counters {
		s.Counters[k] = v
	}
	for k, v := range r.gauges {
		s.Gauges[k] = v
	}
	for k, samples := range r.timers {
		ts := TimerStats{Count: len(samples)}
		if len(samples) > 0 {
			sorted := append([]time.Duration(nil), samples...)
			sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
			ts.Min, ts.Max = sorted[0], sorted[len(sorted)-1]
			for _, d := range sorted {
				ts.Total += d
			}
		}
		s.Timers[k] = ts
	}
	return s
}
