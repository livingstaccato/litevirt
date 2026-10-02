package fleet

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fence"
)

// TestFleet_FenceRecovery_FenceRowBeforeItsState: the successor holds a
// leader's fencing_log row for d while d is still 'active' in its replica, and
// the 'fenced' state arrives a cycle later. That is the order a leader on the
// previous release writes them in — two separate entries, the row first — and
// a leader that dies between the two pushes leaves its successor exactly here.
//
// The successor used to cache the host as handled on the first look ("recently
// fenced"), and the cache is cleared only for hosts back to 'active', so the
// state arriving a moment later was never read: the workload stayed on d for
// the life of the process. It must wait instead, and resume once the state
// lands — without fencing d a second time.
//
// Mutation: restore the c.fenced[target] = true in run's recently-fenced skip.
func TestFleet_FenceRecovery_FenceRowBeforeItsState(t *testing.T) {
	ctx := context.Background()
	vm := "vm-row-first"
	c, a, b, cc, x, d := crashFleet(t, 2721, vm)
	voters := []*Node{a, b, cc}
	ledger := watchClaims(t, c)

	clock := NewVirtualClock(time.Now().UTC())
	cs := c.NewCoordinators(clock)
	var fenced atomic.Int32
	cs.ByNode[a.Name].Gate = quorateGate{}
	cs.ByNode[a.Name].SetFencer(func(context.Context, fence.HostConfig) fence.Result {
		fenced.Add(1)
		return fence.Result{Method: "ipmi", Success: true}
	})

	// x, a leader on the previous release, records its verified fence of d:
	// the fencing_log row first, in an entry of its own.
	if err := corrosion.InsertFenceLog(ctx, x.DB, corrosion.FenceLogRecord{
		ID: "fence-x-" + d.Name, HostName: d.Name, Method: "ipmi", Result: "fenced", Detail: "verified off",
	}); err != nil {
		t.Fatalf("x's fence row: %v", err)
	}
	waitFor(t, func() bool {
		for _, n := range voters {
			rows, err := n.DB.Query(ctx, `SELECT 1 AS one FROM fencing_log WHERE host_name = ?`, d.Name)
			if err != nil || len(rows) == 0 {
				return false
			}
		}
		return true
	}, "x's fence row on every voter")

	// The successor's first look: the row, and d still 'active'.
	cs.Tick(ctx, a)
	if h, _ := corrosion.GetHost(ctx, a.DB, d.Name); h == nil || h.State != "active" {
		t.Fatalf("fixture: %s is %+v on %s before its state write, want 'active'", d.Name, h, a.Name)
	}

	// x's second entry, the state, lands; then x is gone.
	if err := corrosion.UpdateHostState(ctx, x.DB, d.Name, "fenced"); err != nil {
		t.Fatalf("x's state write: %v", err)
	}
	waitFor(t, func() bool {
		for _, n := range voters {
			if h, err := corrosion.GetHost(ctx, n.DB, d.Name); err != nil || h == nil || h.State != "fenced" {
				return false
			}
		}
		return true
	}, "d 'fenced' on every voter")
	c.Crash(x)

	clock.Advance(time.Minute)
	for _, n := range voters {
		PublishHealth(t, n, d.Name, streakSince(2*time.Minute), clock.Now())
	}
	c.WaitConverged(t, convergeTimeout, voters...)

	decided := tickUntilDecided(ctx, t, cs, a, d, vm, 4)
	if decided == nil {
		t.Fatalf("the successor never resumed the recovery once d's 'fenced' state arrived: %+v", vmOn(t, a, vm))
	}
	if n := fenced.Load(); n != 0 {
		t.Errorf("the successor fenced %s %d time(s); x's verified fence was on record", d.Name, n)
	}
	c.WaitConverged(t, convergeTimeout, voters...)
	claimReconciler(t, c.Node(decided.HostName)).ReconcileOnce(ctx)
	checkClaimSafety(t, ledger, a, vm, c.Nodes)
}

// waitFor polls cond until it holds or convergeTimeout passes.
func waitFor(t *testing.T, cond func() bool, what string) {
	t.Helper()
	for deadline := time.Now().Add(convergeTimeout); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}
