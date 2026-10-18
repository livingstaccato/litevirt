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
	"sync/atomic"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/failover"
	"github.com/litevirt/litevirt/internal/fence"
	"github.com/litevirt/litevirt/internal/hostboot"
)

// uncleanBoot is the boot write of d's daemon started again after a crash:
// what hostboot decides for dataDir, written at once (unless the decision
// defers it until d serves), while d does not answer. It returns the decision
// and the boot's time.
func (f *restartFleet) uncleanBoot(t *testing.T, dataDir string) (hostboot.Boot, time.Time) {
	t.Helper()
	return f.uncleanBootAt(t, dataDir, time.Now())
}

// uncleanBootAt is uncleanBoot with hostboot judging the boot at now. The
// write, guarded as the daemon's is when the decision read a state, is made
// at once.
func (f *restartFleet) uncleanBootAt(t *testing.T, dataDir string, now time.Time) (hostboot.Boot, time.Time) {
	t.Helper()
	ctx := context.Background()
	b := hostboot.BootState(ctx, f.d.DB, f.d.Name, dataDir, false, now)
	booted := time.Now()
	switch {
	case b.Deferred:
	case b.From != "":
		if applied, err := corrosion.UpdateHostStartupFrom(ctx, f.d.DB, f.d.Name, b.From, b.State, "", 0, 0, 0, false); err != nil || !applied {
			t.Fatalf("boot write from %q: applied=%v err=%v", b.From, applied, err)
		}
	default:
		if err := corrosion.UpdateHostStartup(ctx, f.d.DB, f.d.Name, b.State, "", 0, 0, 0, false); err != nil {
			t.Fatalf("boot write: %v", err)
		}
	}
	return b, booted
}

// unservedGap holds d unanswered from its boot at booted for at least min,
// and then until every observer has counted it failing past the fence
// threshold, failing the test if d is fenced meanwhile. A count past the
// threshold is what makes the gap a test: without it there is nothing for the
// coordinator to fence on. An observer whose own process stalls discards the
// count it had and counts nothing for health.StallGrace (health's stall
// rule), so on a loaded host one can still be short of it at min; the gap
// then runs on, up to max, which stays inside the coordinator's upgrading
// allowance so a fence in it is still one before d served.
func (f *restartFleet) unservedGap(t *testing.T, booted time.Time, min, max time.Duration, b hostboot.Boot) {
	t.Helper()
	past := 5 + 2
	counted := func() (string, int, bool) {
		for _, n := range f.observers {
			if got, _, ok := observedFailures(n, f.d.Name); !ok || got < past {
				return n.Name, got, false
			}
		}
		return "", 0, true
	}
	for {
		if fs := f.fences(); len(fs) != 0 {
			t.Fatalf("d was fenced %s after its boot, before it served: %+v", fs[0].Sub(booted).Round(time.Millisecond), b)
		}
		el := time.Since(booted)
		if el >= min {
			name, got, ok := counted()
			if ok {
				return
			}
			if el >= max {
				t.Fatalf("fixture: %s counted d failing %d times %s after its boot, want past the fence threshold",
					name, got, el.Round(time.Millisecond))
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// TestFleet_UncleanRestartIsUpgradingUntilItServes: d's daemon crashes while d
// is active and starts again at once. At least 30 s pass between its boot write and
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

	f.unservedGap(t, booted, 30*time.Second, 90*time.Second, b)
	served := f.answer()
	hostboot.Served(dir)
	if b.AwaitServing {
		if flipped, state, err := hostboot.ConfirmServing(ctx, f.d.DB, f.d.Name); err != nil || !flipped {
			t.Fatalf("confirm serving: flipped=%v state=%q err=%v", flipped, state, err)
		}
	}
	// Generous: what is asserted is that d is never fenced, not how fast it
	// settles. (The timeouts this was raised for were the stamp, not the
	// settling: see restartFleet.answer.)
	eventually(t, time.Minute, "every observer to see d answer, and d active", func() bool {
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
// served and writes nothing: d stays 'upgrading' from the first boot write,
// is not recorded 'active' while it does not answer, and is fenced once the
// coordinator's timeout has passed since that first write. A daemon that
// crash-loops cannot keep re-arming it.
//
// Mutations: drop the AwaitingPath check from hostboot's unclean boot — the
// second boot writes 'upgrading' again and re-arms the timeout; return
// 'active' for it (the rule before) — the coordinator reads d 'active'.
func TestFleet_UncleanCrashLoopIsUpgradingOnce(t *testing.T) {
	const timeout = 40 * time.Second
	f := newRestartFleet(t, 3408, func(c *failover.Coordinator) { c.UpgradingTimeout = timeout })
	ctx := context.Background()
	dir := t.TempDir()
	f.down.Store(true)
	b, first := f.uncleanBoot(t, dir)
	if b.State != "upgrading" || b.Deferred {
		t.Fatalf("first boot after a crash decided %+v, want 'upgrading' written", b)
	}
	// The state and its since come from one read of the membership row. Read
	// apart, the boot write could replicate between them: the since of the
	// split pass's 'active' copy, then the 'upgrading' of the boot write.
	var since time.Time
	eventually(t, convergeTimeout, "the first boot write to reach the coordinator", func() bool {
		states, err := corrosion.HostsStateSince(ctx, f.a.DB)
		s, ok := states[f.d.Name]
		since = s.Since
		return err == nil && ok && s.State == "upgrading"
	})
	time.Sleep(20 * time.Second) // it dies before serving; systemd starts it again
	b, second := f.uncleanBoot(t, dir)
	if b.State != "upgrading" || !b.AwaitServing || !b.Deferred {
		t.Errorf("boot after a daemon that never served decided %+v, want the recorded 'upgrading' kept, no boot write", b)
	}
	time.Sleep(2 * time.Second) // anything it wrote has replicated by now
	h, err := corrosion.GetHost(ctx, f.a.DB, f.d.Name)
	at, ok, serr := corrosion.HostStateSince(ctx, f.a.DB, f.d.Name)
	if err != nil || h == nil || h.State != "upgrading" || serr != nil || !ok || !at.Equal(since) {
		t.Fatalf("after the second boot the coordinator reads d %+v (err %v), 'upgrading' since %s (ok=%v err=%v); want 'upgrading' since the first write, %s",
			h, err, at, ok, serr, since)
	}
	// The re-arm itself is pinned above (the coordinator's 'upgrading' since
	// is still the first write's). What follows only needs the fence to
	// come after the first write's timeout and before the second boot's
	// would end — 20 s of slack under -race on a loaded host.
	eventually(t, timeout+convergeTimeout, "the coordinator to fence d, 'upgrading' past the first boot's timeout", func() bool {
		return len(f.fences()) > 0
	})
	fenced := f.fences()[0]
	if fenced.Sub(first) < timeout {
		t.Fatalf("d was fenced %s after its first boot write, inside the %s it may be 'upgrading'",
			fenced.Sub(first).Round(time.Millisecond), timeout)
	}
	if fenced.Sub(second) >= timeout {
		t.Fatalf("d was fenced %s after its second boot: that boot re-armed the timeout", fenced.Sub(second).Round(time.Millisecond))
	}
}

// TestFleet_UncleanBootOfAStaleUpgradingHostIsNotFencedBeforeItServes: d is
// stuck 'upgrading' past the coordinator's timeout while it answers (its
// serving check never recorded it active, so it raised
// upgrading_unconfirmed), and peers that reach it do not fence it. Its daemon
// then crashes and starts again: the boot has serving evidence, and the host
// has been 'upgrading' for longer than hostboot's window.
//
// That boot used to record d 'active' 22 s before it serves, and its peers
// fenced it on the failure count they kept through the crash; making no write
// is worse, since the coordinator fences a host stuck 'upgrading' as soon as
// its failures reach quorum. It writes a fresh 'upgrading' once, guarded on
// the 'upgrading' it read, and d is not fenced before or after it serves.
//
// hostboot's window is the coordinator's 2 minutes in production; here the
// coordinator's is 30 s, and hostboot judges the boot 2 minutes on.
//
// Mutations: return 'active' for the stale 'upgrading' (the rule before) — d
// is fenced on its failure count inside the gap; make no write (Deferred) —
// d is fenced as a stuck host inside the gap.
func TestFleet_UncleanBootOfAStaleUpgradingHostIsNotFencedBeforeItServes(t *testing.T) {
	const timeout = 30 * time.Second
	f := newRestartFleet(t, 3411, func(c *failover.Coordinator) { c.UpgradingTimeout = timeout })
	ctx := context.Background()
	if err := corrosion.UpdateHostState(ctx, f.d.DB, f.d.Name, "upgrading"); err != nil {
		t.Fatal(err)
	}
	eventually(t, convergeTimeout, "d's 'upgrading' to reach the coordinator", func() bool {
		h, err := corrosion.GetHost(ctx, f.a.DB, f.d.Name)
		return err == nil && h != nil && h.State == "upgrading"
	})
	time.Sleep(timeout + 2*time.Second) // stuck past the coordinator's timeout, answering
	if fs := f.fences(); len(fs) != 0 {
		t.Fatalf("fixture: d was fenced while it answered: %d fences", len(fs))
	}

	f.down.Store(true) // the crash; it starts again at once
	b, booted := f.uncleanBootAt(t, t.TempDir(), time.Now().Add(hostboot.UpgradingTimeout))
	if b.State != "upgrading" || !b.AwaitServing || b.Deferred || b.From != "upgrading" {
		t.Errorf("unclean boot of a host stuck 'upgrading' decided %+v, want a fresh 'upgrading' written from upgrading", b)
	}
	f.unservedGap(t, booted, 22*time.Second, timeout-3*time.Second, b)
	served := f.answer()
	if flipped, state, err := hostboot.ConfirmServing(ctx, f.d.DB, f.d.Name); err != nil || !flipped {
		t.Fatalf("confirm serving: flipped=%v state=%q err=%v", flipped, state, err)
	}
	eventually(t, time.Minute, "every observer to see d answer, and d active", func() bool {
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
		t.Fatalf("d was fenced %s after its boot (%d fences)", fs[0].Sub(booted).Round(time.Millisecond), len(fs))
	}
}

// TestFleet_BootAfterAQuarantinedStopIsNotFencedBeforeItServes is lab 1's
// ReleaseTokenRollbackRule cleanup (2026-10-16, build cab27191, 3 of 3 runs):
// d boots after a crash, records itself 'upgrading' and is stopped before it
// serves; its next boot is WAL-quarantined, so neither that boot nor its
// SIGTERM writes anything; then it is upgraded again and boots unquarantined.
// That boot followed a daemon that never served and recorded node-5 'active'
// 0.1 s in; it listened 23 s later, and node-2 SSH-fenced it after 16 s.
//
// Here the last boot keeps d 'upgrading', and d is not fenced through a gap
// of at least 30 s before it serves, nor after it serves and is recorded active with its
// boot report.
//
// Mutation: return 'active' for a boot that follows a never-served one
// (hostboot's rule before this change) — d is fenced inside the gap.
func TestFleet_BootAfterAQuarantinedStopIsNotFencedBeforeItServes(t *testing.T) {
	f := newRestartFleet(t, 3410)
	ctx := context.Background()
	dir := t.TempDir()
	f.down.Store(true)
	if b, _ := f.uncleanBoot(t, dir); b.State != "upgrading" || b.Deferred {
		t.Fatalf("fixture: the crash boot decided %+v, want 'upgrading' written", b)
	}
	// The quarantined boot decides like any other and writes nothing; its
	// SIGTERM writes nothing either.
	_ = hostboot.BootState(ctx, f.d.DB, f.d.Name, dir, false, time.Now())
	b, booted := f.uncleanBoot(t, dir)
	if b.State != "upgrading" || !b.AwaitServing || !b.Deferred {
		t.Errorf("the boot after a quarantined stop decided %+v, want the recorded 'upgrading' kept until it serves", b)
	}
	f.unservedGap(t, booted, 30*time.Second, 90*time.Second, b)
	served := f.answer()
	hostboot.Served(dir)
	if b.Deferred {
		flipped, state, err := hostboot.ConfirmServingReport(ctx, f.d.DB, f.d.Name, b.State, hostboot.Report{Version: "v-up"})
		if err != nil || !flipped {
			t.Fatalf("confirm serving: flipped=%v state=%q err=%v", flipped, state, err)
		}
	}
	eventually(t, time.Minute, "every observer to see d answer, and d active with its boot report", func() bool {
		for _, n := range f.observers {
			if got, at, ok := observedFailures(n, f.d.Name); !ok || got != 0 || !at.After(served) {
				return false
			}
		}
		h, err := corrosion.GetHost(ctx, f.a.DB, f.d.Name)
		return err == nil && h != nil && h.State == "active" && h.Version == "v-up"
	})
	time.Sleep(time.Second)
	if fs := f.fences(); len(fs) != 0 {
		t.Fatalf("d was fenced %s after its boot (%d fences)", fs[0].Sub(booted).Round(time.Millisecond), len(fs))
	}
}

// TestFleet_HandledHostThatRebootsUncleanAndNeverServesIsFencedAgain: d (best
// effort) fails with a running VM; the coordinator fences it and parks the
// VM's recovery on d's partition-pause wait, so d is cached as handled. d's
// machine reboots: its replica stopped at the crash and still reads d active,
// so its boot write records it 'upgrading', which wins over the coordinator's
// write once replication returns. Its daemon never serves.
//
// The coordinator judges d afresh from that write (upgradingSinceHandled): it
// skips d for the upgrading timeout and then fences it again, and the VM is
// recovered. On the build before, the cached skip held d for good — 'upgrading'
// is neither back ('active') nor down — and the VM stayed on a dead host.
//
// Mutations: drop the 'upgrading' arm from clearRecoveredFromFenced — d is
// never fenced again; have upgradingLife report nothing — the first fence's
// row holds the second back for recentFenceWindow (5 min), past this bound.
func TestFleet_HandledHostThatRebootsUncleanAndNeverServesIsFencedAgain(t *testing.T) {
	const timeout = 25 * time.Second
	var shortWait atomic.Bool
	f := newRestartFleet(t, 3409, func(c *failover.Coordinator) {
		c.UpgradingTimeout = timeout
		c.PartitionPauseEnforced = func(context.Context) bool { return true }
		c.PeerPausesOnLoss = func(string) bool { return true }
		c.PauseWaitFor = func(int) time.Duration {
			if shortWait.Load() {
				return 0
			}
			return 10 * time.Minute
		}
	})
	f.mu.Lock()
	f.fenceAs = &fence.Result{Method: "best-effort-ssh", Success: true, Detail: "SSH failed (fleet), proceeding anyway"}
	f.mu.Unlock()
	ctx := context.Background()
	if err := corrosion.InsertVM(ctx, f.a.DB, corrosion.VMRecord{
		Name: "uv", HostName: f.d.Name, State: "running", CPUActual: 1, MemActual: 256,
		Spec: `{"name":"uv","cpu":1,"memory_mib":256,"on_host_failure":"restart-any"}`,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	f.c.WaitConverged(t, convergeTimeout)

	// The machine dies: no probe answers, and nothing replicates to or from
	// it, so its replica keeps the state it had.
	f.c.Isolate(f.d)
	f.down.Store(true)
	eventually(t, time.Minute, "the coordinator to fence d", func() bool { return len(f.fences()) == 1 })
	time.Sleep(3 * time.Second) // a few cycles: the recovery is parked, d cached
	if vm := vmOn(t, f.a, "uv"); vm == nil || vm.HostName != f.d.Name {
		t.Fatalf("fixture: uv was recovered at once (%+v); its recovery must wait on d's pause", vm)
	}
	if h, err := corrosion.GetHost(ctx, f.d.DB, f.d.Name); err != nil || h == nil || h.State != "active" {
		t.Fatalf("fixture: d's own replica reads d %+v (%v), want the active it had at the crash", h, err)
	}

	// It reboots; its daemon makes the boot write and never serves.
	b, booted := f.uncleanBoot(t, t.TempDir())
	if b.State != "upgrading" {
		t.Fatalf("boot of d from a replica that reads it active decided %+v, want 'upgrading'", b)
	}
	shortWait.Store(true)
	f.c.ClearLinkFaults()
	eventually(t, convergeTimeout, "d's 'upgrading' boot write to reach the coordinator", func() bool {
		h, err := corrosion.GetHost(ctx, f.a.DB, f.d.Name)
		return err == nil && h != nil && h.State == "upgrading"
	})

	eventually(t, timeout+convergeTimeout+10*time.Second, "the coordinator to fence d again", func() bool {
		return len(f.fences()) >= 2
	})
	if second := f.fences()[1]; second.Sub(booted) < timeout {
		t.Fatalf("d was fenced again %s after its boot write, inside the %s it may be 'upgrading'",
			second.Sub(booted).Round(time.Millisecond), timeout)
	}
	eventually(t, convergeTimeout, "uv to be recovered off d", func() bool {
		vm := vmOn(t, f.a, "uv")
		return vm != nil && vm.HostName != f.d.Name
	})
}
