package fleet

import (
	"fmt"
	"testing"
)

// A quorum with one current voter must make bounded durable progress, rather
// than requiring an unbounded loop or all current voters to return first.
func TestAutomationReplayIntermediateRecoveryBounded(t *testing.T) {
	f := NewAutomationFixture(t, 3)
	f.Isolate(2)
	for i := 0; i < 17; i++ {
		if _, err := f.Engine(0).Submit(f.Context(), f.Barrier(0, fmt.Sprintf("intermediate-%d", i))); err != nil {
			t.Fatal(err)
		}
	}
	want := f.Head(t, 0)
	f.Heal(2)
	f.Isolate(1)
	if err := f.Engine(2).Recover(f.Context()); err == nil {
		t.Fatal("intermediate recovery did not yield at its budget")
	}
	if h := f.Head(t, 2); h.Sequence != 17 {
		t.Fatalf("bounded intermediate progress=%+v, want sequence17", h)
	}
	if err := f.Engine(2).Recover(f.Context()); err != nil {
		t.Fatalf("bounded intermediate recovery did not resume: %v", err)
	}
	if h := f.Head(t, 2); h != want {
		t.Fatalf("resumed prefix=%+v, want %+v", h, want)
	}
	f.Heal(1)
	f.Converge(t)
}
