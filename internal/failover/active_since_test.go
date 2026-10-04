package failover

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fence"
)

// A host that just turned active is counted down afresh: an observation older
// than the moment it turned active is about the host before — joining, here —
// and does not count toward its fence quorum. On the kvm003 lab (drill 6,
// main-b3368d7c) a re-added host was fenced 2 s after its boot write, on
// counts observed while it was joining.
//
// Mutation: drop the activeSince check in run — the host is fenced on the
// observations from before its boot write.
func TestHostJustActiveIsCountedAfresh(t *testing.T) {
	db, ctx := seedDownHost(t, "ssh", nil)
	db.SetHostMembershipGate(func() bool { return true })
	if _, err := db.SplitHostMembership(ctx); err != nil || !db.HostMembershipLive() {
		t.Fatalf("split host membership: live=%v err=%v", db.HostMembershipLive(), err)
	}
	// The failure rows seedDownHost wrote are a moment old; the host then
	// boots and records itself active.
	time.Sleep(1100 * time.Millisecond)
	if err := corrosion.UpdateHostStartup(ctx, db, "down", "active", "", 0, 0, 0, false); err != nil {
		t.Fatalf("boot write: %v", err)
	}
	c := newTestCoordinator("coordinator", db)
	fences := 0
	c.SetFencer(func(context.Context, fence.HostConfig) fence.Result {
		fences++
		return fence.Result{Method: "ssh", Success: true}
	})
	c.run(ctx)
	if fences != 0 {
		t.Fatalf("a host that just turned active was fenced on observations from before (%d fences)", fences)
	}

	// The observers count it down after it turned active: fenced as usual.
	for _, o := range []string{"coordinator", "alive"} {
		if err := db.Execute(ctx,
			`INSERT OR REPLACE INTO host_health (observer, target, status, consecutive_failures, last_seen, updated_at)
			 VALUES (?, 'down', 'suspect', ?, NULL, ?)`, o, offlineThreshold, db.NowTS()); err != nil {
			t.Fatalf("insert health: %v", err)
		}
	}
	c.run(ctx)
	if fences != 1 {
		t.Fatalf("the host, counted down after it turned active, was fenced %d times, want 1", fences)
	}
}

// A boot write that lands after a cycle counted a joining host's observers,
// and before it read the host's state, must not let that count fence the host
// now active: the cycle's snapshot of when hosts turned active does not have
// it, so it waits for the next cycle.
//
// Mutation: return false from turnedActiveThisCycle — the first case passes
// the host through.
func TestTurnedActiveThisCycle(t *testing.T) {
	db, ctx := seedDownHost(t, "ssh", nil)
	liveMembership(t, db)
	c := newTestCoordinator("coordinator", db)

	if err := corrosion.UpdateHostState(ctx, db, "down", corrosion.HostStateJoining); err != nil {
		t.Fatal(err)
	}
	snapshot, err := corrosion.HostsActiveSince(ctx, db) // the cycle's read: down is joining
	if err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpdateHostStartup(ctx, db, "down", "active", "", 0, 0, 0, false); err != nil {
		t.Fatal(err) // the boot write lands mid-cycle
	}
	if !c.turnedActiveThisCycle(ctx, "down", snapshot) {
		t.Error("a host that turned active after the cycle counted its observers was let through")
	}

	snapshot, err = corrosion.HostsActiveSince(ctx, db) // next cycle
	if err != nil {
		t.Fatal(err)
	}
	if c.turnedActiveThisCycle(ctx, "down", snapshot) {
		t.Error("a host active since before the cycle's snapshot was held back")
	}
}
