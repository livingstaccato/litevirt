// Fleet scenario: a host that restarts is not fenced in the seconds between
// its daemon's boot write and its first answered probe (lab 1, 2026-10-11).
//
// On lab 1 a quick node restart had the coordinator SSH-power the node off
// again about 25 s into its boot: node-5 twice, node-2 once. Each time the
// daemon's SIGTERM had recorded it 'upgrading', which held the fence back
// while it was down, and its boot write recorded it 'active' about 3 s before
// its gRPC server listened. Every observer had kept counting the host's
// failures through the restart, so its next unanswered probe published a
// count already past the fence threshold, stamped after the boot write. The
// coordinator dropped only observations OLDER than the host's activation, so
// that row counted, quorum formed at once, and the host was fenced as soon as
// sshd answered. node-1's journal, node-2:
//
//	10:48:44 failover: target is upgrading, skipping fence host=node-2
//	10:48:59 (node-2) boot write: active
//	10:49:02 failover: quorum reached — host exceeded failure threshold observers=4 quorum=3
//	10:49:02 (node-2) litevirtd starting grpc=0.0.0.0:7443
//
// A host that has just turned active is counted down afresh: a failing run
// that began before the activation counts only once the host has failed for a
// whole run's worth of probes since it.
package fleet

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/failover"
	"github.com/litevirt/litevirt/internal/fence"
	"github.com/litevirt/litevirt/internal/health"
)

// restartFleet is four nodes with real health checkers on the observers a, b
// and o, and a's coordinator polling on the real clock. d is the host that
// restarts. down makes d's probes go unanswered, as a host whose daemon is
// stopped, or not yet listening, does.
type restartFleet struct {
	c         *Cluster
	a, d      *Node
	observers []*Node
	down      atomic.Bool

	mu       sync.Mutex
	fencedAt []time.Time
}

func newRestartFleet(t *testing.T, seed int64, tune ...func(*failover.Coordinator)) *restartFleet {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	c := New(t, Options{Nodes: 4, IndependentReplicas: true, FaultSeed: seed})
	f := &restartFleet{c: c, a: c.Nodes[0], d: c.Nodes[3], observers: []*Node{c.Nodes[0], c.Nodes[1], c.Nodes[2]}}
	c.WaitConverged(t, convergeTimeout)
	// host_membership_split_v1 is mandatory and latched on any current
	// cluster, lab 1 included: every node reads host_membership, which is
	// where the coordinator learns when a host turned active.
	for _, n := range c.Nodes {
		splitMembership(t, n)
	}
	c.WaitConverged(t, convergeTimeout)
	for _, n := range f.observers {
		ch := health.NewChecker(n.Name, n.PKIDir, n.DB)
		// The daemon's readiness prober, reduced to the one fact this
		// scenario turns on: d answers, or it does not.
		ch.SetPeerReadiness(func(_ context.Context, host, _ string) (bool, string, error) {
			if host == f.d.Name && f.down.Load() {
				return false, "", context.DeadlineExceeded
			}
			return true, "", nil
		})
		go ch.Start(ctx)
	}
	coord := failover.NewCoordinator(f.a.Name, f.a.DB)
	for _, fn := range tune {
		fn(coord)
	}
	coord.SetFencer(func(_ context.Context, h fence.HostConfig) fence.Result {
		if h.Name == f.d.Name {
			f.mu.Lock()
			f.fencedAt = append(f.fencedAt, time.Now())
			f.mu.Unlock()
		}
		return fence.Result{Method: "fleet-test", Success: true}
	})
	go func() {
		tk := time.NewTicker(250 * time.Millisecond)
		defer tk.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tk.C:
				coord.RunOnce(ctx)
			}
		}
	}()
	return f
}

func (f *restartFleet) fences() []time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]time.Time(nil), f.fencedAt...)
}

// restart takes d down as a graceful stop does — its SIGTERM records it
// 'upgrading' — and waits until every observer has counted it failing past
// the fence threshold, then makes the boot write that records it 'active'
// again, while it still does not answer. It returns the boot write's time.
func (f *restartFleet) restart(t *testing.T) time.Time {
	t.Helper()
	ctx := context.Background()
	if err := corrosion.UpdateHostState(ctx, f.d.DB, f.d.Name, "upgrading"); err != nil {
		t.Fatalf("SIGTERM's 'upgrading' write: %v", err)
	}
	eventually(t, convergeTimeout, "the 'upgrading' write to reach every observer", func() bool {
		for _, n := range f.observers {
			if h, err := corrosion.GetHost(ctx, n.DB, f.d.Name); err != nil || h == nil || h.State != "upgrading" {
				return false
			}
		}
		return true
	})
	f.down.Store(true)
	past := health.FailuresToFence + 2
	eventually(t, time.Minute, "every observer to count d failing past the fence threshold", func() bool {
		for _, n := range f.observers {
			if got, _, ok := observedFailures(n, f.d.Name); !ok || got < past {
				return false
			}
		}
		return true
	})
	if n := len(f.fences()); n != 0 {
		t.Fatalf("fixture: d was fenced %d times while it was recorded 'upgrading'", n)
	}
	booted := time.Now()
	if err := corrosion.UpdateHostStartup(ctx, f.d.DB, f.d.Name, "active", "", 0, 0, 0, false); err != nil {
		t.Fatalf("boot write: %v", err)
	}
	return booted
}

// TestFleet_RestartedHostIsNotFencedBeforeItServes: d restarts, its boot write
// records it 'active', and its gRPC server answers 3 s later, as on lab 1. It
// must not be fenced in between, nor after.
//
// Mutation: drop the run-start check from the coordinator's activation filter
// (failover.countedSinceActive) — the first unanswered probe after the boot
// write carries the count from the restart and d is fenced at once.
func TestFleet_RestartedHostIsNotFencedBeforeItServes(t *testing.T) {
	f := newRestartFleet(t, 3401)
	booted := f.restart(t)

	// lab 1 measured 3 s from the boot write to the gRPC listener on every
	// one of the three re-fenced restarts.
	time.Sleep(3 * time.Second)
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
	// Two more coordinator cycles past the last observer's healthy verdict.
	time.Sleep(time.Second)
	if fs := f.fences(); len(fs) != 0 {
		t.Fatalf("d was fenced %s after its boot write recorded it active, before it had failed a whole "+
			"run of probes since: the failure count from its restart carried over (%d fences)",
			fs[0].Sub(booted).Round(time.Millisecond), len(fs))
	}
}

// TestFleet_RestartedHostThatNeverServesIsFenced: the other half. d's boot
// write records it 'active' and it never answers. It is a failed host like any
// other and is fenced, once it has failed a whole run of probes since the
// activation.
//
// Mutation: discard every failing run that began before the activation, with
// no allowance for its length since — the observers' runs never break, so d
// is never fenced.
func TestFleet_RestartedHostThatNeverServesIsFenced(t *testing.T) {
	f := newRestartFleet(t, 3402)
	booted := f.restart(t)
	eventually(t, convergeTimeout, "the coordinator to fence the restarted host that does not answer", func() bool {
		return len(f.fences()) > 0
	})
	first := f.fences()[0]
	if grace := time.Duration(health.FailuresToFence-1) * health.ProbeInterval; first.Sub(booted) < grace {
		t.Fatalf("d was fenced %s after its boot write, inside the %s its observers need to count it down afresh",
			first.Sub(booted).Round(time.Millisecond), grace)
	}
}
