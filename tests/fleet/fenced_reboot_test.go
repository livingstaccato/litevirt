// Fleet scenario: a host that was fenced and is powered back on is not fenced
// again on the failure run that its fence already acted on (lab 1,
// 2026-10-14).
//
// node-6 SSH-fenced node-3 at 17:36:27. The harness powered node-3 on; its
// boot write recorded it 'active' at 17:41:06 (an unclean stop leaves no
// restart marker, so it boots active at once), and its gRPC server listened
// at 17:41:22, 16 s later, after network reconcile. Its observers had counted
// it failing without a break since 17:36. The coordinator's activation filter
// lets such an inherited run count 13 s after the activation (afreshRun), so
// at 17:41:22.9 quorum formed and node-3 was SSH-powered off again, 0.6 s
// after it began to answer. Before the lab's fence key reached every peer the
// same re-fence ran and failed harmlessly.
package fleet

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/failover"
)

// fenceThenBoot takes d down while active and waits for the coordinator to
// fence it, then makes the boot write of an unclean boot (state 'active')
// while d still does not answer. It returns the boot write's time.
func (f *restartFleet) fenceThenBoot(t *testing.T) time.Time {
	t.Helper()
	ctx := context.Background()
	f.down.Store(true)
	eventually(t, time.Minute, "the coordinator to fence d once it stops answering", func() bool {
		return len(f.fences()) == 1
	})
	eventually(t, convergeTimeout, "d to be recorded down after its fence on d's own replica", func() bool {
		h, err := corrosion.GetHost(ctx, f.d.DB, f.d.Name)
		return err == nil && h != nil && h.State != "active"
	})
	// The machine is off for a while; its observers keep counting.
	time.Sleep(3 * time.Second)
	booted := time.Now()
	if err := corrosion.UpdateHostStartup(ctx, f.d.DB, f.d.Name, "active", "", 0, 0, 0, false); err != nil {
		t.Fatalf("boot write: %v", err)
	}
	return booted
}

// TestFleet_FencedHostPoweredBackOnIsNotFencedBeforeItServes: d is fenced,
// boots, records itself active and takes 16 s to answer, longer than the 13 s
// the activation filter allows an inherited run. It is not fenced again,
// neither in the gap nor after it answers.
//
// Mutation: give a run that a fence already acted on the same allowance as
// any inherited run (afreshRun) — d is fenced a second time inside the gap.
func TestFleet_FencedHostPoweredBackOnIsNotFencedBeforeItServes(t *testing.T) {
	f := newRestartFleet(t, 3405)
	booted := f.fenceThenBoot(t)

	for deadline := booted.Add(16 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		if fs := f.fences(); len(fs) != 1 {
			t.Fatalf("d was fenced again %s after its boot write, before it answered (%d fences)",
				fs[len(fs)-1].Sub(booted).Round(time.Millisecond), len(fs))
		}
	}
	f.down.Store(false)
	served := time.Now()
	eventually(t, convergeTimeout, "every observer to see d answer", func() bool {
		for _, n := range f.observers {
			if got, at, ok := observedFailures(n, f.d.Name); !ok || got != 0 || !at.After(served) {
				return false
			}
		}
		return true
	})
	time.Sleep(time.Second)
	if fs := f.fences(); len(fs) != 1 {
		t.Fatalf("d was fenced %d times; want only the first fence", len(fs))
	}
}

// TestFleet_FencedHostThatNeverServesIsFencedAgainAfterTheTimeout: the other
// half. d is fenced, boots, records itself active and never answers. It is
// fenced again, but only once it has been active without answering for the
// coordinator's upgrading timeout, the allowance a graceful restart gets.
//
// Mutation: drop inherited runs a fence acted on outright — d is never fenced
// again.
func TestFleet_FencedHostThatNeverServesIsFencedAgainAfterTheTimeout(t *testing.T) {
	const timeout = 25 * time.Second
	f := newRestartFleet(t, 3406, func(c *failover.Coordinator) { c.UpgradingTimeout = timeout })
	booted := f.fenceThenBoot(t)
	eventually(t, timeout+convergeTimeout, "the coordinator to fence d again, active and silent past the timeout", func() bool {
		return len(f.fences()) > 1
	})
	if d := f.fences()[1].Sub(booted); d < timeout {
		t.Fatalf("d was fenced again %s after its boot write, inside the %s timeout", d.Round(time.Millisecond), timeout)
	}
}
