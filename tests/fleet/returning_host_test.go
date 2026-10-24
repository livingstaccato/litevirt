// Fleet scenario: a host recorded fenced, offline, in maintenance, draining
// or joining boots again. Its boot write ends that state, as it always has (no
// `lv host undrain` after a reboot), but records it 'upgrading' until its
// daemon serves, not 'active' at once. An 'active' write starts the host's new
// life, and a failing run that its observers begin after it counts toward a
// fence at once: a host whose observers did not probe it while it was out of
// service (maintenance, joining), or did without a fence acting on the run
// (draining), was fenced about 10 s after its boot write, before a daemon that
// takes longer than that to listen (lab 1 measured 16-23 s) served. A fenced
// host's inherited run already gets the upgrading timeout
// (failover.inheritedRunGraceFrom); for it the change is what the cluster
// records: 'upgrading', not an 'active' host that does not answer.
package fleet

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/failover"
	"github.com/litevirt/litevirt/internal/fence"
	"github.com/litevirt/litevirt/internal/hostboot"
)

// fenceAndReturn takes d down until the coordinator fences it and d's own
// replica reads the state the fence recorded (want), then makes d's boot
// write while d still does not answer. It returns the boot decision and the
// write's time.
func (f *restartFleet) fenceAndReturn(t *testing.T, want, dataDir string) (hostboot.Boot, time.Time) {
	t.Helper()
	ctx := context.Background()
	f.down.Store(true)
	eventually(t, time.Minute, "the coordinator to fence d", func() bool { return len(f.fences()) == 1 })
	eventually(t, convergeTimeout, "d's replica to read d "+want, func() bool {
		h, err := corrosion.GetHost(ctx, f.d.DB, f.d.Name)
		return err == nil && h != nil && h.State == want
	})
	rows, err := f.a.DB.Query(ctx, `SELECT result FROM fencing_log WHERE host_name = ?`, f.d.Name)
	if err != nil || len(rows) == 0 {
		t.Fatalf("fixture: no fencing_log row for d's fence (%v)", err)
	}
	// The machine is off for a while; its observers keep counting. (A boot
	// write in the fence row's own second is that row's life, as for an
	// 'active' write: fenceRowCutoff.)
	time.Sleep(3 * time.Second)
	b := hostboot.BootState(ctx, f.d.DB, f.d.Name, dataDir, false, time.Now())
	booted := time.Now()
	f.returningWrite(t, b)
	return b, booted
}

// returningWrite is d's boot write for b with returning_boot open: a
// returning boot through hostboot.WriteReturningBoot (the grant the gate
// would hand it), any other boot as written before.
func (f *restartFleet) returningWrite(t *testing.T, b hostboot.Boot) {
	t.Helper()
	ctx := context.Background()
	if b.Returning {
		applied, err := hostboot.WriteReturningBoot(ctx, f.d.DB, f.d.Name,
			capabilities.GrantForTest(t, capabilities.FeatureReturningBoot), b.From, hostboot.Report{})
		if err != nil || !applied {
			t.Fatalf("returning boot write: applied=%v err=%v", applied, err)
		}
		return
	}
	if err := corrosion.UpdateHostStartup(ctx, f.d.DB, f.d.Name, b.State, "", 0, 0, 0, false); err != nil {
		t.Fatalf("boot write: %v", err)
	}
}

// TestFleet_FencedHostReturningIsUpgradingUntilItServes: d stops answering
// and the coordinator fences it, recording it 'fenced' (a fence that
// succeeded) or 'offline' (one that failed). d boots again and 30 s pass
// between its boot write and its gRPC server answering. d is 'upgrading'
// throughout, cluster-wide, and is not fenced again; once it serves it is
// recorded active, is still not fenced, and its fence stays on record.
//
// Mutation: have hostboot.BootState skip returningBoot (the boot write records
// d 'active', as before) — the coordinator reads d active before it served.
func TestFleet_FencedHostReturningIsUpgradingUntilItServes(t *testing.T) {
	for _, tc := range []struct {
		state string
		seed  int64
		as    *fence.Result
	}{
		{"fenced", 3431, nil},
		{"offline", 3432, &fence.Result{Method: "fleet-test", Success: false, Detail: "fleet: fence failed"}},
	} {
		t.Run(tc.state, func(t *testing.T) {
			f := newRestartFleet(t, tc.seed)
			f.mu.Lock()
			f.fenceAs = tc.as
			f.mu.Unlock()
			ctx := context.Background()
			dir := t.TempDir()
			b, booted := f.fenceAndReturn(t, tc.state, dir)
			if b.State != "upgrading" || !b.AwaitServing {
				t.Errorf("boot of d recorded %s decided %+v, want 'upgrading' until it serves", tc.state, b)
			}
			eventually(t, convergeTimeout, "d's boot write to reach every observer", func() bool {
				for _, n := range f.observers {
					if h, err := corrosion.GetHost(ctx, n.DB, f.d.Name); err != nil || h == nil || h.State != b.State {
						return false
					}
				}
				return true
			})

			for deadline := booted.Add(30 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
				if fs := f.fences(); len(fs) != 1 {
					t.Fatalf("d was fenced again %s after its boot write, before it served: %+v",
						fs[1].Sub(booted).Round(time.Millisecond), b)
				}
				if h, err := corrosion.GetHost(ctx, f.a.DB, f.d.Name); err == nil && h != nil && h.State == "active" {
					t.Fatalf("the coordinator reads d active %s after its boot write, before it served",
						time.Since(booted).Round(time.Millisecond))
				}
			}
			past := 5 + 2
			for _, n := range f.observers {
				if got, _, ok := observedFailures(n, f.d.Name); !ok || got < past {
					t.Fatalf("fixture: %s counted d failing %d times (ok=%v), want past the fence threshold", n.Name, got, ok)
				}
			}

			served := f.answer()
			hostboot.Served(dir)
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
			if fs := f.fences(); len(fs) != 1 {
				t.Fatalf("d was fenced again %s after its boot write (%d fences)", fs[1].Sub(booted).Round(time.Millisecond), len(fs))
			}
			rows, err := f.a.DB.Query(ctx, `SELECT result FROM fencing_log WHERE host_name = ?`, f.d.Name)
			if err != nil || len(rows) != 1 {
				t.Fatalf("d's fence is not on record once it returned: %d rows (%v)", len(rows), err)
			}
		})
	}
}

// TestFleet_FencedHostReturningThatNeverServesIsFencedAgain: d is fenced,
// boots 'upgrading' and never serves. Its earlier fence does not hold the
// coordinator back: d is fenced again once it has been 'upgrading' for the
// coordinator's timeout, counted from the boot write, and not before.
//
// Mutation: have the coordinator skip an 'upgrading' host whatever its age —
// d is never fenced again. (Recorded 'active' instead, d is also fenced at the
// timeout, by failover.inheritedRunGraceFrom, so skipping returningBoot does not
// turn this red; TestFleet_FencedHostReturningIsUpgradingUntilItServes pins
// that.)
func TestFleet_FencedHostReturningThatNeverServesIsFencedAgain(t *testing.T) {
	const timeout = 25 * time.Second
	f := newRestartFleet(t, 3433, func(c *failover.Coordinator) { c.UpgradingTimeout = timeout })
	b, booted := f.fenceAndReturn(t, "fenced", t.TempDir())
	if b.State != "upgrading" {
		t.Errorf("boot of d recorded fenced decided %+v, want 'upgrading'", b)
	}
	eventually(t, timeout+convergeTimeout+10*time.Second, "the coordinator to fence d again", func() bool {
		return len(f.fences()) >= 2
	})
	if second := f.fences()[1]; second.Sub(booted) < timeout {
		t.Fatalf("d was fenced again %s after its boot write, inside the %s it may be 'upgrading'",
			second.Sub(booted).Round(time.Millisecond), timeout)
	}
}

// TestFleet_OutOfServiceHostReturningIsUpgradingUntilItServes: d is recorded
// in maintenance, draining or joining; its daemon stops and starts again at
// once, and 30 s pass between its boot write and its gRPC server answering.
// The joining case is a re-admission that reached d's running daemon (a peer
// records it 'joining', d's replica receives it) before d restarted: a fresh
// joiner's first boot reads the 'active' its own registration inserts, and
// takes the unclean-restart rule (TestFleet_UncleanRestartIsUpgradingUntilItServes,
// hostboot TestFreshJoinerFirstBootTakesTheRestartRules).
// d is 'upgrading' throughout and is not fenced; once it serves it is recorded
// active and still not fenced.
//
// Mutation: have hostboot.BootState skip returningBoot (the boot write records
// d 'active', as before) — d is fenced inside the gap.
func TestFleet_OutOfServiceHostReturningIsUpgradingUntilItServes(t *testing.T) {
	for _, tc := range []struct {
		state string
		seed  int64
	}{
		{"maintenance", 3434},
		{"draining", 3435},
		{corrosion.HostStateJoining, 3436},
	} {
		t.Run(tc.state, func(t *testing.T) {
			f := newRestartFleet(t, tc.seed)
			ctx := context.Background()
			if err := corrosion.UpdateHostState(ctx, f.a.DB, f.d.Name, tc.state); err != nil {
				t.Fatalf("record d %s: %v", tc.state, err)
			}
			eventually(t, convergeTimeout, "every node to read d "+tc.state, func() bool {
				for _, n := range append([]*Node{f.d}, f.observers...) {
					if h, err := corrosion.GetHost(ctx, n.DB, f.d.Name); err != nil || h == nil || h.State != tc.state {
						return false
					}
				}
				return true
			})
			// The daemon stops (a crash, or a restart the SIGTERM leaves
			// unrecorded) and starts again at once.
			f.down.Store(true)
			dir := t.TempDir()
			b := hostboot.BootState(ctx, f.d.DB, f.d.Name, dir, false, time.Now())
			booted := time.Now()
			f.returningWrite(t, b)
			if b.State != "upgrading" || !b.AwaitServing {
				t.Errorf("boot of d recorded %s decided %+v, want 'upgrading' until it serves", tc.state, b)
			}

			for deadline := booted.Add(30 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
				if fs := f.fences(); len(fs) != 0 {
					t.Fatalf("d was fenced %s after its boot write, before it served: %+v",
						fs[0].Sub(booted).Round(time.Millisecond), b)
				}
				if h, err := corrosion.GetHost(ctx, f.a.DB, f.d.Name); err == nil && h != nil && h.State == "active" {
					t.Fatalf("the coordinator reads d active %s after its boot write, before it served",
						time.Since(booted).Round(time.Millisecond))
				}
			}
			past := 5 + 2
			for _, n := range f.observers {
				if got, _, ok := observedFailures(n, f.d.Name); !ok || got < past {
					t.Fatalf("fixture: %s counted d failing %d times (ok=%v), want past the fence threshold", n.Name, got, ok)
				}
			}

			served := f.answer()
			hostboot.Served(dir)
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
				t.Fatalf("d was fenced %s after its boot write (%d fences)", fs[0].Sub(booted).Round(time.Millisecond), len(fs))
			}
		})
	}
}
