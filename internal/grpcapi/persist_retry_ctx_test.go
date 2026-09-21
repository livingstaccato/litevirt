package grpcapi

import (
	"context"
	"testing"
	"time"
)

// The retry loop around the state write sleeps between attempts with
// time.Sleep, which no context can interrupt. A caller that has already gone
// away — or a shutdown — still waits out the full backoff, 600ms of a goroutine
// that has nothing left to do for anyone.
//
// This is the same bug the read half of the chokepoint was rewritten to remove,
// one layer down and unfixed.
func TestPersistVMStateDirect_StopsRetryingWhenTheContextIsDone(t *testing.T) {
	s := gateTestServer(t)
	// Make every write fail so the loop runs its full retry budget.
	s.db.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	_ = s.persistVMStateDirect(ctx, "vm1", "running", "detail", "vm_state")
	elapsed := time.Since(start)

	// The uncancellable backoff is 100+200+300 = 600ms.
	if elapsed > 300*time.Millisecond {
		t.Fatalf("took %v with an already-cancelled context — the backoff between retries "+
			"is uninterruptible, so the caller's cancellation buys nothing", elapsed)
	}
}
