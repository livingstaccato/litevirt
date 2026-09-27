package health

import (
	"testing"
	"time"
)

// An action the correlated-failure guard suppresses was not taken, so it does
// not count toward the action backoff. Counting it grew the backoff on every
// suppressed attempt for as long as the correlated event lasted.
func TestVMCheck_SuppressedActionDoesNotGrowTheBackoff(t *testing.T) {
	f := newGraceFixture(t, restartCheck)
	f.probe.set(false, "tcp 10.0.0.9:81: connection refused")
	f.v.mu.Lock()
	for _, n := range []string{"db1", "db2", "db3"} { // failing, not yet acted on
		f.v.failures[n] = 2
	}
	f.v.mu.Unlock()

	for i := 0; i < 3; i++ {
		f.v.checkVMAt(f.ctx, *f.vm(), restartCheck, false)
		f.clock.advance(10 * time.Second)
	}
	if n := f.starts(); n != 0 {
		t.Fatalf("the VM was restarted %d times during a correlated failure, want 0", n)
	}
	f.v.mu.Lock()
	acts, last := f.v.actionCount["web"], f.v.lastAction["web"]
	f.v.mu.Unlock()
	if acts != 0 || !last.IsZero() {
		t.Fatalf("suppressed actions counted toward the backoff: actionCount=%d lastAction=%v, want 0 and unset", acts, last)
	}

	// The event ends: the next failed probe acts at once, with no backoff
	// built up by the suppressed attempts.
	f.v.mu.Lock()
	for _, n := range []string{"db1", "db2", "db3"} {
		delete(f.v.failures, n)
	}
	f.v.mu.Unlock()
	f.v.checkVMAt(f.ctx, *f.vm(), restartCheck, false)
	if n := f.starts(); n != 1 {
		t.Fatalf("after the correlated event the failing VM was restarted %d times, want 1", n)
	}
}

// A VM whose action is held back by its backoff has already been acted on;
// its failure run is not a fresh failure and does not count toward
// correlation. Counting it, a handful of VMs sitting in backoff kept the guard
// on — and suppressed every other VM's action — indefinitely.
func TestVMCheck_BackoffHeldVMsDoNotMakeAFailureCorrelated(t *testing.T) {
	f := newGraceFixture(t, restartCheck)
	f.probe.set(false, "tcp 10.0.0.9:81: connection refused")
	now := f.clock.now()
	f.v.mu.Lock()
	for _, n := range []string{"db1", "db2", "db3"} { // acted on, now held by the backoff
		f.v.failures[n] = 2
		f.v.actionCount[n] = 1
		f.v.lastAction[n] = now
	}
	f.v.mu.Unlock()

	f.v.checkVMAt(f.ctx, *f.vm(), restartCheck, false)
	if n := f.starts(); n != 1 {
		t.Fatalf("the failing VM was restarted %d times, want 1: VMs held by their backoff made the failure look correlated", n)
	}

	// Past their backoff the same runs are fresh failures again, and count.
	f.clock.advance(actionBackoff(1) + time.Second)
	f.v.mu.Lock()
	f.v.lastAction["web"] = time.Time{}
	f.v.actionCount["web"] = 0
	f.v.mu.Unlock()
	f.v.checkVMAt(f.ctx, *f.vm(), restartCheck, false)
	if n := f.starts(); n != 1 {
		t.Fatalf("the VM was restarted again (%d starts) though three other VMs are failing out of backoff", n)
	}
}
