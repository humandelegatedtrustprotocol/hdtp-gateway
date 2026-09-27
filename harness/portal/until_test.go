package portal

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// A wait that runs out is a failure, not an arrival: Rendered's placeholder wait returned nil at its
// deadline, and the view was then read as if it had drawn.
func TestUntilFailsWhenTheBudgetRunsOut(t *testing.T) {
	err := until(context.Background(), 30*time.Millisecond, 5*time.Millisecond, "a view that never loads",
		func(context.Context) (bool, error) { return false, nil })
	if err == nil || !strings.Contains(err.Error(), "a view that never loads") {
		t.Fatalf("a probe that never answered done gave %v, want an error naming what was awaited", err)
	}
}

func TestUntilReturnsWhenTheProbeAnswersDone(t *testing.T) {
	calls := 0
	err := until(context.Background(), time.Minute, time.Millisecond, "the third look",
		func(context.Context) (bool, error) { calls++; return calls == 3, nil })
	if err != nil || calls != 3 {
		t.Fatalf("got %v after %d probes, want nil after 3", err, calls)
	}
}

func TestUntilStopsOnAProbeErrorAndOnTheContext(t *testing.T) {
	boom := errors.New("the page went away")
	if err := until(context.Background(), time.Minute, time.Millisecond, "x",
		func(context.Context) (bool, error) { return false, boom }); !errors.Is(err, boom) {
		t.Errorf("a probe's error gave %v, want it returned", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	began := time.Now()
	if err := until(ctx, time.Minute, time.Minute, "x",
		func(context.Context) (bool, error) { return false, nil }); !errors.Is(err, context.Canceled) {
		t.Errorf("an ended context gave %v, want context.Canceled", err)
	}
	if time.Since(began) > 5*time.Second {
		t.Errorf("an ended context still slept the interval out")
	}
}
