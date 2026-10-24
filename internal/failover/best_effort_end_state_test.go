package failover

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fence"
)

// The best-effort end state: failover recovers a best-effort host's workloads
// only on its partition pause, waited out (TestPartitionPause_*), or on an
// operator's confirmation. These are the branches the partition-pause tests
// do not cover.

// A host-key mismatch says a different machine answered at the host's
// address: the host may be reachable to the majority somewhere else and never
// pause, so even with its pause relied on, the fence is not a self-pause and
// the VM is held.
//
// Mutation: let asSelfPause rewrite a WrongHost result — the fence is
// recorded self_paused and the VM moves once the (zero) wait passes.
func TestBestEffort_AHostKeyMismatchIsHeldEvenWithThePause(t *testing.T) {
	c, db, ctx, _ := pauseCoordinator(t, true)
	c.PauseWaitFor = func(int) time.Duration { return 0 }
	c.SetFencer(func(context.Context, fence.HostConfig) fence.Result {
		return fence.Result{Method: "best-effort-ssh", Detail: "SSH failed (exit status 255): Host key verification failed.",
			Dialled: true, WrongHost: true}
	})
	c.run(ctx)
	c.run(ctx)
	if got := vmHost(t, db, ctx); got != "down" {
		t.Fatalf("VM recovered to %q on a fence that reached a different machine", got)
	}
	if _, a := newestAssurance(t, db, ctx, "down"); a != corrosion.FenceFailed {
		t.Fatalf("fence recorded %s, want failed", a)
	}
	assertHeldWithTheWayOut(t, c, "down")
}

// The way out works: a best-effort host held on a fence that proves nothing
// recovers once an operator confirms it off, with no further fence.
//
// Mutation: never resume from a confirmation (resumeFromConfirmation) — the
// VM stays held after it. (The split-brain guard's best-effort confirmation
// case, for a confirmation that comes first, is pinned by
// TestSharedDiskFence_ABestEffortHostConfirmedOffFirstMovesInOneStep.)
func TestBestEffort_FenceConfirmAfterTheHoldRecovers(t *testing.T) {
	c, db, ctx, _ := pauseCoordinator(t, false)
	c.run(ctx)
	if got := vmHost(t, db, ctx); got != "down" {
		t.Fatalf("precondition: VM moved to %q on an unproven fence", got)
	}
	assertHeldWithTheWayOut(t, c, "down")
	operatorConfirms(t, db, ctx, "down")
	c.run(ctx)
	if got := vmHost(t, db, ctx); got != "alive" {
		t.Fatalf("VM still on %q after the operator confirmed the host off (hold %q)", got, c.holdReason["down"])
	}
}

// A fence row an older build recorded as an assumed best-effort success (no
// partition-pause reliance in its detail) is not authority here: a coordinator
// resuming from it holds the VM.
//
// Mutation: drop notAFenceUnlessPaused from recoverFenced — the resumed
// assumed row recovers the VM.
func TestBestEffort_AResumedAssumedRowIsHeld(t *testing.T) {
	db, ctx := seedDownHost(t, "best-effort", nil)
	fenceRowDetailAt(t, db, "old-assumed", "best-effort-ssh", "fenced", "SSH failed (exit status 255), proceeding anyway",
		time.Now().Add(-20*time.Second))
	if err := corrosion.UpdateHostState(ctx, db, "down", "fenced"); err != nil {
		t.Fatal(err)
	}
	for _, o := range []string{"coordinator", "alive"} {
		failingSince(t, db, o, time.Now().Add(-time.Minute), time.Now())
	}
	c := newTestCoordinator("coordinator", db)
	c.SetFencer(dialledFencer())
	c.run(ctx)
	if got := vmHost(t, db, ctx); got != "down" {
		t.Fatalf("VM recovered to %q from an assumed best-effort row with no pause relied on", got)
	}
	assertHeldWithTheWayOut(t, c, "down")
}

// A fencer that still reports a best-effort fence as an assumed success (the
// old contract) is judged by the same rule: with no pause relied on it is a
// failure, recorded so, and the VM is held.
//
// Mutation: make notAFenceUnlessPaused pass every result — the VM moves.
func TestBestEffort_AnAssumedSuccessWithoutThePauseIsHeld(t *testing.T) {
	c, db, ctx, _ := pauseCoordinator(t, false)
	c.SetFencer(fencerReturning("best-effort-ssh", true))
	c.run(ctx)
	if got := vmHost(t, db, ctx); got != "down" {
		t.Fatalf("VM recovered to %q on an assumed best-effort success", got)
	}
	if _, a := newestAssurance(t, db, ctx, "down"); a != corrosion.FenceFailed {
		t.Fatalf("fence recorded %s, want failed", a)
	}
	assertHeldWithTheWayOut(t, c, "down")
}
