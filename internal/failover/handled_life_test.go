package failover

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// splitHost is a db holding host "h" in state, read from host_membership, as
// on every current cluster (host_membership_split_v1 is mandatory).
func splitHost(t *testing.T, state string) (*corrosion.Client, context.Context) {
	t.Helper()
	ctx := context.Background()
	db := newTestDB(t)
	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
		Name: "h", Address: "10.0.0.9", SSHUser: "root", CertSerial: "s", State: "active",
	}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}
	db.SetHostMembershipGate(func() bool { return true })
	if _, err := db.SplitHostMembership(ctx); err != nil || !db.HostMembershipLive() {
		t.Fatalf("split host membership: live=%v err=%v", db.HostMembershipLive(), err)
	}
	setState(t, ctx, db, state)
	return db, ctx
}

func setState(t *testing.T, ctx context.Context, db *corrosion.Client, state string) {
	t.Helper()
	time.Sleep(5 * time.Millisecond) // a strictly newer state write
	if err := corrosion.UpdateHostState(ctx, db, "h", state); err != nil {
		t.Fatal(err)
	}
}

// A host handled for an outage that then records itself 'upgrading' — the
// boot write of a daemon restarted without a graceful-stop marker, made from
// a replica that stopped at the crash — is judged afresh: cleared from the
// cache, as an 'active' boot write clears it. Without that the cached skip
// hid it for good, and a daemon that never served was never fenced again.
//
// Mutation: drop the 'upgrading' arm from clearRecoveredFromFenced — the host
// stays cached.
func TestHandledHostThatRecordsUpgradingIsJudgedAfresh(t *testing.T) {
	db, ctx := splitHost(t, "active")
	c := newTestCoordinator("coordinator", db)
	c.markHandled(ctx, "h")
	setState(t, ctx, db, "fenced")
	c.clearRecoveredFromFenced(ctx)
	if !c.fenced["h"] {
		t.Fatal("a fenced host was dropped from the handled cache")
	}
	setState(t, ctx, db, "upgrading")
	c.clearRecoveredFromFenced(ctx)
	if c.fenced["h"] {
		t.Fatal("a handled host that recorded itself 'upgrading' since stayed cached")
	}
	if _, ok := c.handledAt["h"]; ok {
		t.Fatal("the handled mark outlived the cache entry")
	}
}

// A host the coordinator handled while it was ALREADY 'upgrading' (fenced
// past its upgrading timeout, the 'fenced' write not landed) stays handled:
// only a state write newer than the one read when it was handled is a new
// life. So does a host cached with no mark.
//
// Mutation: drop the newer-than check in upgradingSinceHandled — the host
// fenced while upgrading is dropped from the cache and fenced again.
func TestHandledWhileUpgradingStaysHandled(t *testing.T) {
	db, ctx := splitHost(t, "upgrading")
	c := newTestCoordinator("coordinator", db)
	c.markHandled(ctx, "h")
	c.clearRecoveredFromFenced(ctx)
	if !c.fenced["h"] {
		t.Fatal("a host handled while 'upgrading' was dropped from the cache with no new state write")
	}
	// A resumed recovery marks it again; the first mark stands.
	setState(t, ctx, db, "upgrading")
	first := c.handledAt["h"]
	c.markHandled(ctx, "h")
	if c.handledAt["h"] != first {
		t.Fatal("a later mark of the same episode replaced the first")
	}

	db2, ctx2 := splitHost(t, "fenced")
	c2 := newTestCoordinator("coordinator", db2)
	c2.fenced["h"] = true // handled by a path that kept no mark
	setState(t, ctx2, db2, "upgrading")
	c2.clearRecoveredFromFenced(ctx2)
	if !c2.fenced["h"] {
		t.Fatal("a host cached with no mark was dropped")
	}
}

// A fence row older than the host's own 'upgrading' write is about a host
// that was up after it (fenceRowCutoff, upgradingLife), so it does not hold
// back the fence of a daemon that then never serves for recentFenceWindow.
//
// Mutation: have upgradingLife report nothing — the cutoff is unknown.
func TestFenceRowCutoffOfAnUpgradingHost(t *testing.T) {
	db, ctx := splitHost(t, "upgrading")
	c := newTestCoordinator("coordinator", db)
	since, ok, err := corrosion.HostStateSince(ctx, db, "h")
	if err != nil || !ok {
		t.Fatalf("HostStateSince: %v %v", ok, err)
	}
	got, known := c.fenceRowCutoff(ctx, "h")
	if !known || !got.Equal(since.Truncate(time.Second)) {
		t.Fatalf("fenceRowCutoff of an upgrading host = %s known=%v, want %s", got, known, since.Truncate(time.Second))
	}
	setState(t, ctx, db, "offline")
	if _, known := c.fenceRowCutoff(ctx, "h"); known {
		t.Fatal("an offline host has a fence-row cutoff")
	}
}
