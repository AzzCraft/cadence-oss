package concurrency

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestSemaphoreCapsConcurrency(t *testing.T) {
	s := NewSemaphore(2)
	var inFlight, peak int32
	var done = make(chan struct{}, 5)
	for i := 0; i < 5; i++ {
		go func() {
			_ = s.Acquire(context.Background())
			n := atomic.AddInt32(&inFlight, 1)
			for {
				p := atomic.LoadInt32(&peak)
				if n <= p || atomic.CompareAndSwapInt32(&peak, p, n) {
					break
				}
			}
			time.Sleep(20 * time.Millisecond)
			atomic.AddInt32(&inFlight, -1)
			s.Release()
			done <- struct{}{}
		}()
	}
	for i := 0; i < 5; i++ {
		<-done
	}
	if peak > 2 {
		t.Fatalf("peak concurrency %d > 2", peak)
	}
}

func TestSemaphoreContextCancel(t *testing.T) {
	s := NewSemaphore(1)
	_ = s.Acquire(context.Background())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()
	if err := s.Acquire(ctx); err == nil {
		t.Fatal("expected timeout error")
	}
}

func TestPoolMapPreservesOrder(t *testing.T) {
	p := &Pool{N: 3}
	inputs := []any{1, 2, 3, 4, 5}
	out, err := p.Map(context.Background(), inputs, func(_ context.Context, i int, v any) (any, error) {
		return v.(int) * 10, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for i, v := range []int{10, 20, 30, 40, 50} {
		if out[i] != v {
			t.Fatalf("idx %d: got %v want %d", i, out[i], v)
		}
	}
}

func TestPoolMapPropagatesError(t *testing.T) {
	p := &Pool{N: 2}
	want := errors.New("boom")
	_, err := p.Map(context.Background(), []any{1, 2, 3}, func(_ context.Context, i int, v any) (any, error) {
		if i == 1 {
			return nil, want
		}
		return v, nil
	})
	if !errors.Is(err, want) {
		t.Fatalf("want boom, got %v", err)
	}
}

func TestPoolPreservesCancellation(t *testing.T) {
	pool := &Pool{N: 1}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := pool.Map(ctx, []any{1, 2}, func(context.Context, int, any) (any, error) { t.Fatal("pre-cancelled job ran"); return nil, nil }); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := pool.Map(context.Background(), []any{1}, func(context.Context, int, any) (any, error) { return nil, context.Canceled }); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	business := errors.New("business failure")
	if _, err := pool.Map(context.Background(), []any{1, 2}, func(_ context.Context, i int, _ any) (any, error) {
		if i == 0 {
			return nil, business
		}
		return nil, context.Canceled
	}); !errors.Is(err, business) {
		t.Fatal(err)
	}
	expired, stop := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer stop()
	if _, err := pool.Map(expired, []any{1}, func(context.Context, int, any) (any, error) { return 1, nil }); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
}
