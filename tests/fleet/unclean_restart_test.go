// Fleet scenario: a daemon that stops without a graceful-stop marker (a crash,
// a kill, a stop whose 'upgrading' write a WAL quarantine refused) keeps its
// host 'upgrading' through its boot, and records it active only once it
// serves.
//
// On lab 1 (2026-10-14) such a boot recorded node-5 'active' 0.1 s after it
// started; it served 23 s later, and its peers SSH-fenced it at 19 s. Booting
// 'upgrading' gives it the coordinator's upgrading timeout to serve, as a
// graceful restart has; a daemon that never serves is still fenced once that
// passes, and one that crash-loops before serving is 'upgrading' only once.
package fleet

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/failover"
	"github.com/litevirt/litevirt/internal/hostboot"
)

// uncleanBoot is the boot write of d's daemon started again after a crash:
// what hostboot decides for dataDir, written at once, while d does not
// answer. It returns the decision and the write's time.
func (f *restartFleet) uncleanBoot(t *testing.T, dataDir string) (hostboot.Boot, time.Time) {
	t.Helper()
	ctx := context.Background()
	b := hostboot.BootState(ctx, f.d.DB, f.d.Name, dataDir, false, time.Now())
	booted := time.Now()
	if err := corrosion.UpdateHostStartup(ctx, f.d.DB, f.d.Name, b.State, "", 0, 0, 0, false); err != nil {
		t.Fatalf("boot write: %v", err)
	}
	return b, booted
}

// TestFleet_UncleanRestartIsUpgradingUntilItServes: d's daemon crashes while d
// is active and starts again at once. 30 s pass between its boot write and
// its gRPC server answering — longer than the cluster takes to fence a host
// that stops answering. d is 'upgrading' throughout and is not fenced; once it
// serves it is recorded active and still not fenced.
//
// Mutation: have BootState return 'active' for a boot without the marker (the
// boot write before this change) — d is fenced inside the gap.
func TestFleet_UncleanRestartIsUpgradingUntilItServes(t *testing.T) {
	f := newRestartFleet(t, 3406)
	ctx := context.Background()
	dir := t.TempDir()
	f.down.Store(true) // the crash: no SIGTERM, no 'upgrading' write
	b, booted := f.uncleanBoot(t, dir)
	if b.State != "upgrading" || !b.AwaitServing {
		t.Errorf("boot after a crash decided %+v, want 'upgrading' until it serves", b)
	}

	for deadline := booted.Add(30 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		if fs := f.fences(); len(fs) != 0 {
			t.Fatalf("d was fenced %s after its boot write, before it served: %+v",
				fs[0].Sub(booted).Round(time.Millisecond), b)
		}
	}
	past := 5 + 2
	for _, n := range f.observers {
		if got, _, ok := observedFailures(n, f.d.Name); !ok || got < past {
			t.Fatalf("fixture: %s counted d failing %d times (ok=%v), want past the fence threshold", n.Name, got, ok)
		}
	}
	f.down.Store(false)
	hostboot.Served(dir)
	if b.AwaitServing {
		if flipped, state, err := hostboot.ConfirmServing(ctx, f.d.DB, f.d.Name); err != nil || !flipped {
			t.Fatalf("confirm serving: flipped=%v state=%q err=%v", flipped, state, err)
		}
	}
	served := time.Now()
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

// TestFleet_UncleanRestartThatNeverServesIsFencedAfterTheTimeout: d crashes,
// boots 'upgrading' and never serves. It is fenced once it has been
// 'upgrading' for the coordinator's timeout, counted from the boot write, and
// not before.
//
// Mutations: boot 'active' — d is fenced inside the timeout; have the
// coordinator skip an 'upgrading' host whatever its age — d is never fenced.
func TestFleet_UncleanRestartThatNeverServesIsFencedAfterTheTimeout(t *testing.T) {
	const timeout = 25 * time.Second
	f := newRestartFleet(t, 3407, func(c *failover.Coordinator) { c.UpgradingTimeout = timeout })
	f.down.Store(true)
	b, booted := f.uncleanBoot(t, t.TempDir())
	if b.State != "upgrading" {
		t.Errorf("boot after a crash decided %+v, want 'upgrading'", b)
	}
	eventually(t, timeout+convergeTimeout, "the coordinator to fence d, 'upgrading' past its timeout", func() bool {
		return len(f.fences()) > 0
	})
	if first := f.fences()[0]; first.Sub(booted) < timeout {
		t.Fatalf("d was fenced %s after its boot write, inside the %s it may be 'upgrading'",
			first.Sub(booted).Round(time.Millisecond), timeout)
	}
}

// TestFleet_UncleanCrashLoopIsUpgradingOnce: d crashes, boots 'upgrading',
// dies before serving and is started again. That boot follows one that never
// served and records d 'active', so the coordinator fences d on its failure
// count, long before the upgrading timeout the first boot started: a daemon
// that crash-loops cannot keep re-arming it.
//
// Mutation: drop the AwaitingPath check from hostboot's unclean boot — the
// second boot is 'upgrading' again and d is not fenced inside the window.
func TestFleet_UncleanCrashLoopIsUpgradingOnce(t *testing.T) {
	f := newRestartFleet(t, 3408)
	dir := t.TempDir()
	f.down.Store(true)
	if b, _ := f.uncleanBoot(t, dir); b.State != "upgrading" {
		t.Fatalf("first boot after a crash decided %+v, want 'upgrading'", b)
	}
	time.Sleep(5 * time.Second) // it dies before serving; systemd starts it again
	b, booted := f.uncleanBoot(t, dir)
	if b.State != "active" || b.AwaitServing {
		t.Errorf("boot after a daemon that never served decided %+v, want 'active'", b)
	}
	// Well inside the 2-minute upgrading timeout the first boot started.
	eventually(t, 45*time.Second, "the coordinator to fence the crash-looping d on its failure count", func() bool {
		return len(f.fences()) > 0
	})
	if first := f.fences()[0]; first.Sub(booted) > 45*time.Second {
		t.Fatalf("d was fenced %s after its second boot", first.Sub(booted).Round(time.Millisecond))
	}
}
