// Package clock — deterministic clock source.
//
// DAS-04-001: For replay determinism the runtime never reads the wall
// clock directly. It calls Clock.Now() on a Clock implementation. The
// FixedClock implementation always returns the same instant, allowing
// two runs over the same input to produce byte-identical evidence.
package clock

import (
	"fmt"
	"sync"
	"time"
)

// Clock is the time source used by deterministic runtime components.
type Clock interface {
	Now() time.Time
}

// SystemClock returns the wall time. Use only for non-deterministic paths
// such as audit timestamps that are sealed in the evidence pack via the
// hash chain rather than fed back into computation.
type SystemClock struct{}

func (SystemClock) Now() time.Time { return time.Now().UTC() }

// FixedClock returns At every time Now is called.
type FixedClock struct {
	At time.Time
}

func (f FixedClock) Now() time.Time { return f.At }

// ParseFixedClock builds a CAD-001 deterministic fixed clock from RFC3339 input.
func ParseFixedClock(value string) (FixedClock, error) {
	at, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return FixedClock{}, fmt.Errorf("CAD-001 fixed clock parse %q: %w", value, err)
	}
	return FixedClock{At: at.UTC()}, nil
}

// RFC3339 returns the CAD-001 canonical UTC timestamp for a Clock.
func RFC3339(c Clock) string {
	return c.Now().UTC().Format(time.RFC3339)
}

// SteppedClock advances by Step on each call to Now. The first call
// returns Start. Useful for tests that want a monotonic but predictable
// clock without coupling to wall time.
type SteppedClock struct {
	mu    sync.Mutex
	cur   time.Time
	Start time.Time
	Step  time.Duration
	once  bool
}

// NewSteppedClock returns a SteppedClock starting at start advancing by step.
func NewSteppedClock(start time.Time, step time.Duration) *SteppedClock {
	return &SteppedClock{Start: start, Step: step, cur: start}
}

func (c *SteppedClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.once {
		c.once = true
		return c.cur
	}
	c.cur = c.cur.Add(c.Step)
	return c.cur
}
