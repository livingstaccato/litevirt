// Fleet scenario: a daemon stopped gracefully (SIGTERM) keeps its host
// 'upgrading' through its boot, and records it active only once it serves.
//
// The boot write used to record such a host 'active' a few seconds before its
// gRPC server listened. The coordinator's activation filter
// (failover.countedSinceActive) holds a fence back for 13 s after that write,
// which covers lab 1's 3 s gap but no gap longer than that: a host whose
// startup between the boot write and its listener took longer was fenced on
// the count its observers carried through the restart. Booting 'upgrading'
// and confirming once serving (hostboot.ConfirmServing) closes the gap
// whatever its length; a host that never serves is still fenced once it has
// been 'upgrading' for the coordinator's timeout.
package fleet

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/failover"
	"github.com/litevirt/litevirt/internal/hostboot"
)

// sigtermRestart stops d as systemd's SIGTERM does and boots it again, with
// its probes unanswered throughout, and returns the boot decision and when the
// boot write was made.
func (f *restartFleet) sigtermRestart(t *testing.T, dataDir string) (hostboot.Boot, time.Time) {
	t.Helper()
	ctx := context.Background()
	if err := hostboot.MarkRestarting(ctx, f.d.DB, f.d.Name, dataDir, time.Now()); err != nil {
		t.Fatalf("SIGTERM: %v", err)
	}
	eventually(t, convergeTimeout, "the SIGTERM's 'upgrading' write to reach every observer", func() bool {
		for _, n := range f.observers {
			if h, err := corrosion.GetHost(ctx, n.DB, f.d.Name); err != nil || h == nil || h.State != "upgrading" {
				return false
			}
		}
		return true
	})
	f.down.Store(true)
	past := 5 + 2
	eventually(t, time.Minute, "every observer to count d failing past the fence threshold", func() bool {
		for _, n := range f.observers {
			if got, _, ok := observedFailures(n, f.d.Name); !ok || got < past {
				return false
			}
		}
		return true
	})
	b := hostboot.BootState(ctx, f.d.DB, f.d.Name, dataDir, false, time.Now())
	booted := time.Now()
	if err := corrosion.UpdateHostStartup(ctx, f.d.DB, f.d.Name, b.State, "", 0, 0, 0, false); err != nil {
		t.Fatalf("boot write: %v", err)
	}
	return b, booted
}

// TestFleet_SIGTERMRestartIsUpgradingUntilItServes: d's daemon is stopped by
// SIGTERM and boots again, and 16 s pass between its boot write and its gRPC
// server answering — longer than the 13 s the coordinator's activation filter
// covers. d is 'upgrading' throughout and is not fenced; once it serves it is
// recorded active and still not fenced.
//
// Mutation: have BootState return 'active' after a SIGTERM (the boot write
// before this change) — the decision is refused; with failover's
// upgradingLifeGrace also giving every run only afreshRun, d is fenced about
// 14 s after its boot write, inside the gap.
func TestFleet_SIGTERMRestartIsUpgradingUntilItServes(t *testing.T) {
	f := newRestartFleet(t, 3403)
	ctx := context.Background()
	b, booted := f.sigtermRestart(t, t.TempDir())
	if b.State != "upgrading" || !b.AwaitServing {
		t.Errorf("boot after a SIGTERM decided %+v, want 'upgrading' until it serves", b)
	}

	for deadline := booted.Add(16 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		if fs := f.fences(); len(fs) != 0 {
			t.Fatalf("d was fenced %s after its boot write, before it served: %+v",
				fs[0].Sub(booted).Round(time.Millisecond), b)
		}
	}
	served := f.answer()
	if b.AwaitServing {
		if flipped, state, err := hostboot.ConfirmServing(ctx, f.d.DB, f.d.Name); err != nil || !flipped {
			t.Fatalf("confirm serving: flipped=%v state=%q err=%v", flipped, state, err)
		}
	}
	eventually(t, convergeTimeout, "every observer to see d answer, and d active", func() bool {
		for _, n := range f.observers {
			if got, at, ok := observedFailures(n, f.d.Name); !ok || got != 0 || !at.After(served) {
				return false
			}
		}
		h, err := corrosion.GetHost(ctx, f.a.DB, f.d.Name)
		return err == nil && h != nil && h.State == "active"
	})
	time.Sleep(time.Second)
	if fs := f.fences(); len(fs) != 0 {
		t.Fatalf("d was fenced %s after its boot write (%d fences)", fs[0].Sub(booted).Round(time.Millisecond), len(fs))
	}
}

// TestFleet_SIGTERMRestartThatNeverServesIsFencedAfterTheTimeout: d boots
// 'upgrading' and never serves. It is fenced once it has been 'upgrading' for
// the coordinator's timeout, counted from the state write — not from the
// hosts row, which d keeps rewriting with version reports.
//
// Mutations: time the 'upgrading' skip from the hosts row's updated_at (the
// version reports push it out and d is never fenced); boot 'active' (d is
// fenced 13 s after the boot write, inside the timeout).
func TestFleet_SIGTERMRestartThatNeverServesIsFencedAfterTheTimeout(t *testing.T) {
	const timeout = 25 * time.Second
	f := newRestartFleet(t, 3404, func(c *failover.Coordinator) { c.UpgradingTimeout = timeout })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	_, booted := f.sigtermRestart(t, t.TempDir())

	// A host that is up but not serving still reports: its version and
	// resources go to the hosts row, bumping its updated_at.
	var reports atomic.Int32
	go func() {
		tk := time.NewTicker(time.Second)
		defer tk.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tk.C:
				if corrosion.UpdateHostResources(ctx, f.d.DB, f.d.Name, 4, 4096, int(reports.Add(1))) == nil {
					continue
				}
			}
		}
	}()

	eventually(t, timeout+convergeTimeout, "the coordinator to fence d, 'upgrading' past its timeout", func() bool {
		return len(f.fences()) > 0
	})
	if first := f.fences()[0]; first.Sub(booted) < timeout {
		t.Fatalf("d was fenced %s after its boot write, inside the %s it may be 'upgrading'",
			first.Sub(booted).Round(time.Millisecond), timeout)
	}
	if reports.Load() == 0 {
		t.Fatal("fixture: d made no resource report while it was 'upgrading'")
	}
}
