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
