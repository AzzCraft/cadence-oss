package clock

import (
	"testing"
	"time"
)

func TestFixedClockReturnsSameInstant(t *testing.T) {
	at := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	c := FixedClock{At: at}
	if c.Now() != at {
		t.Fatal("FixedClock returned different time")
	}
	if c.Now() != c.Now() {
		t.Fatal("FixedClock not idempotent")
	}
}

func TestSteppedClockAdvances(t *testing.T) {
	start := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	c := NewSteppedClock(start, time.Second)
	t0 := c.Now()
	t1 := c.Now()
	t2 := c.Now()
	if !t0.Equal(start) {
		t.Fatalf("first Now != start: %v vs %v", t0, start)
	}
	if !t1.Equal(start.Add(time.Second)) {
		t.Fatalf("second Now wrong: %v", t1)
	}
	if !t2.Equal(start.Add(2 * time.Second)) {
		t.Fatalf("third Now wrong: %v", t2)
	}
}

func TestSystemClockReturnsRecent(t *testing.T) {
	now := SystemClock{}.Now()
	if time.Since(now) > 5*time.Second || time.Since(now) < -5*time.Second {
		t.Fatalf("SystemClock not recent: %v", now)
	}
}
