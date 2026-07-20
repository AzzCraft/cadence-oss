// Package concurrency — small primitives used by the runtime: bounded
// worker pool with deterministic ordered fan-out, and a context-aware
// semaphore.
package concurrency

import (
	"context"
	"errors"
	"sync"
)

// Semaphore is a counting semaphore with context cancel.
type Semaphore struct {
	ch chan struct{}
}

// NewSemaphore returns a Semaphore allowing n concurrent holders.
func NewSemaphore(n int) *Semaphore {
	if n <= 0 {
		n = 1
	}
	return &Semaphore{ch: make(chan struct{}, n)}
}

// Acquire blocks until a slot is free or ctx is cancelled.
func (s *Semaphore) Acquire(ctx context.Context) error {
	select {
	case s.ch <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Release returns a slot.
func (s *Semaphore) Release() { <-s.ch }

// Pool runs jobs with bounded parallelism, returning results in input order.
type Pool struct {
	N int
}

// Map applies fn to each input, with at most p.N concurrent goroutines.
// Output slice is in the same order as inputs. The first error returned by
// fn is propagated; remaining work is cancelled via context.
func (p *Pool) Map(ctx context.Context, inputs []any, fn func(context.Context, int, any) (any, error)) ([]any, error) {
	if p.N <= 0 {
		p.N = 1
	}
	out := make([]any, len(inputs))
	errs := make([]error, len(inputs))
	sem := NewSemaphore(p.N)
	var wg sync.WaitGroup

	cctx, cancel := context.WithCancel(ctx)
	defer cancel()

	for i, in := range inputs {
		if err := sem.Acquire(cctx); err != nil {
			// Cancellation here means a previous fn returned an error
			// or the caller cancelled. Stop scheduling and let wg.Wait
			// drain in-flight work; the original error is in errs.
			break
		}
		wg.Add(1)
		go func(i int, in any) {
			defer wg.Done()
			defer sem.Release()
			r, err := fn(cctx, i, in)
			out[i] = r
			errs[i] = err
			if err != nil {
				cancel()
			}
		}(i, in)
	}
	wg.Wait()
	for _, e := range errs {
		if e != nil && !errors.Is(e, context.Canceled) {
			return out, e
		}
	}
	return out, nil
}
