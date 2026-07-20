// Package budget — token / time budgets with deterministic termination.
//
// DAS-04-005: Each run has a budget (tokens, time, plugin calls). When
// any axis is exhausted the run terminates with a stable termination
// reason recorded in the evidence chain. Termination is observable and
// idempotent — calling Charge after exhaustion does not change the
// reason.
package budget

import (
	"errors"
	"sync"
	"time"
)

// Reason is a stable termination reason string.
type Reason string

const (
	ReasonNone             Reason = ""
	ReasonTokensExhausted  Reason = "tokens_exhausted"
	ReasonTimeExhausted    Reason = "time_exhausted"
	ReasonPluginsExhausted Reason = "plugin_calls_exhausted"
)

// Budget tracks remaining capacity along three axes.
type Budget struct {
	mu               sync.Mutex
	TokensRemaining  int64
	TimeRemaining    time.Duration
	PluginsRemaining int

	terminated bool
	reason     Reason
}

// New returns a Budget with the given limits.
func New(tokens int64, dur time.Duration, plugins int) *Budget {
	return &Budget{
		TokensRemaining:  tokens,
		TimeRemaining:    dur,
		PluginsRemaining: plugins,
	}
}

// Reason returns the stable termination reason or ReasonNone.
func (b *Budget) Reason() Reason {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.reason
}

// Terminated reports whether the budget is exhausted.
func (b *Budget) Terminated() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.terminated
}

// terminate marks the budget exhausted with the given reason. Idempotent
// — only the first reason wins so the evidence chain is stable.
func (b *Budget) terminate(r Reason) {
	if !b.terminated {
		b.terminated = true
		b.reason = r
	}
}

// ChargeTokens deducts n tokens. Returns ErrTerminated when the budget
// is already or becomes exhausted.
func (b *Budget) ChargeTokens(n int64) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.terminated {
		return ErrTerminated
	}
	b.TokensRemaining -= n
	if b.TokensRemaining < 0 {
		b.terminate(ReasonTokensExhausted)
		return ErrTerminated
	}
	return nil
}

// ChargeTime deducts d. Returns ErrTerminated when exhausted.
func (b *Budget) ChargeTime(d time.Duration) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.terminated {
		return ErrTerminated
	}
	b.TimeRemaining -= d
	if b.TimeRemaining < 0 {
		b.terminate(ReasonTimeExhausted)
		return ErrTerminated
	}
	return nil
}

// ChargePlugin deducts one plugin call.
func (b *Budget) ChargePlugin() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.terminated {
		return ErrTerminated
	}
	b.PluginsRemaining--
	if b.PluginsRemaining < 0 {
		b.terminate(ReasonPluginsExhausted)
		return ErrTerminated
	}
	return nil
}

// ErrTerminated is returned when a charge cannot be applied because the
// budget is exhausted.
var ErrTerminated = errors.New("budget terminated")
