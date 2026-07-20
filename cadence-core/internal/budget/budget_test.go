package budget

import (
	"errors"
	"testing"
	"time"
)

func TestTokensExhausted(t *testing.T) {
	b := New(100, time.Hour, 10)
	if err := b.ChargeTokens(50); err != nil {
		t.Fatal(err)
	}
	if err := b.ChargeTokens(60); !errors.Is(err, ErrTerminated) {
		t.Fatalf("expected terminated, got %v", err)
	}
	if r := b.Reason(); r != ReasonTokensExhausted {
		t.Fatalf("wrong reason: %s", r)
	}
}

func TestTimeExhausted(t *testing.T) {
	b := New(1000, 100*time.Millisecond, 10)
	_ = b.ChargeTime(150 * time.Millisecond)
	if b.Reason() != ReasonTimeExhausted {
		t.Fatal("expected time_exhausted")
	}
}

func TestPluginsExhausted(t *testing.T) {
	b := New(1000, time.Hour, 1)
	_ = b.ChargePlugin()
	if err := b.ChargePlugin(); !errors.Is(err, ErrTerminated) {
		t.Fatal("expected terminated on second plugin call")
	}
	if b.Reason() != ReasonPluginsExhausted {
		t.Fatal("wrong reason")
	}
}

func TestReasonIsIdempotent(t *testing.T) {
	b := New(0, time.Hour, 10)
	_ = b.ChargeTokens(1)
	first := b.Reason()
	_ = b.ChargeTime(time.Hour)
	_ = b.ChargePlugin()
	if b.Reason() != first {
		t.Fatal("reason changed after first termination")
	}
}

func TestNotTerminatedInitially(t *testing.T) {
	b := New(1, time.Second, 1)
	if b.Terminated() {
		t.Fatal("new budget reports terminated")
	}
	if b.Reason() != ReasonNone {
		t.Fatal("new budget has reason")
	}
}
