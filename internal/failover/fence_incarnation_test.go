package failover

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fence"
)

// A fence row written before a host last turned active is about an earlier
// life of the host, not the one now failing: the machine removed under the
// name before `lv host add` gave it to a new one, or the same machine before
// it booted again. On the kvm003 lab (drill 6) the old node-5 was
// fence-confirmed, removed with `lv host rm --dead` and re-added minutes
// later; for the rest of the five-minute window recentlyFenced counted the
// old machine's confirmation, and a failure of the new machine went unfenced.
//
// A row newer than the host's last activation still counts: that is the race
// the window exists for, a fence whose 'fenced' state has not reached this
// replica yet.

// liveMembership opens the host_membership gate and runs the split pass, as
// host_membership_split_v1 latching does on every current cluster, with every
// host active for ten minutes.
func liveMembership(t *testing.T, db *corrosion.Client) {
	t.Helper()
	db.SetHostMembershipGate(func() bool { return true })
	if _, err := db.SplitHostMembership(context.Background()); err != nil || !db.HostMembershipLive() {
		t.Fatalf("split host membership: live=%v err=%v", db.HostMembershipLive(), err)
	}
	// Every host has been active for ten minutes, not since the fixture
	// inserted it a moment ago.
	if _, err := db.DB().Exec(`UPDATE host_membership SET updated_at = ?`,
		time.Now().Add(-10*time.Minute).UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
}

func fenceRowAt(t *testing.T, db *corrosion.Client, id, method, result string, at time.Time) {
	t.Helper()
	if err := db.Execute(context.Background(),
		`INSERT OR IGNORE INTO fencing_log (id, host_name, method, result, timestamp, detail) VALUES (?, 'down', ?, ?, ?, '')`,
		id, method, result, at.UTC().Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
}

func TestRecentFence_FromBeforeTheHostLastTurnedActiveDoesNotCount(t *testing.T) {
	db, ctx := seedDownHost(t, "ssh", nil)
	liveMembership(t, db)
	c := newTestCoordinator("coordinator", db)

	// Confirmed off a minute ago, and a proof-grade IPMI fence beside it.
	fenceRowAt(t, db, "confirm-old", "manual", "manual-confirmed", time.Now().Add(-time.Minute))
	fenceRowAt(t, db, "ipmi-old", "ipmi", "fenced", time.Now().Add(-time.Minute))
	if !c.recentlyFenced(ctx, "down") || !c.manualFenceConfirmed(ctx, "down") {
		t.Fatal("fixture: rows newer than the host's last activation must count (the race the window is for)")
	}
	if _, ok := c.newestProofGradeFence(ctx, "down"); !ok {
		t.Fatal("fixture: the proof-grade fence must count before the host comes back")
	}

	// The host (a new machine under the name, or the same one rebooted)
	// records itself active.
	if err := corrosion.UpdateHostStartup(ctx, db, "down", "active", "", 0, 0, 0, false); err != nil {
		t.Fatal(err)
	}
	if c.recentlyFenced(ctx, "down") {
		t.Error("recentlyFenced counts a fence from before the host last turned active")
	}
	if c.manualFenceConfirmed(ctx, "down") {
		t.Error("a confirmation from before the host last turned active still confirms it off")
	}
	if rec, ok := c.newestProofGradeFence(ctx, "down"); ok {
		t.Errorf("a proof-grade fence from before the host last turned active still proves it off: %+v", rec)
	}
}

// The whole path: the host that came back and fails again is fenced at once,
// not skipped as recently fenced.
func TestRecentFence_ANewLifeIsFencedWithoutWaitingOutTheWindow(t *testing.T) {
	db, ctx := seedDownHost(t, "ssh", nil)
	liveMembership(t, db)
	fenceRowAt(t, db, "confirm-old", "manual", "manual-confirmed", time.Now().Add(-time.Minute))
	time.Sleep(1100 * time.Millisecond)
	if err := corrosion.UpdateHostStartup(ctx, db, "down", "active", "", 0, 0, 0, false); err != nil {
		t.Fatal(err)
	}
	// Observers count it down after it turned active.
	for _, o := range []string{"coordinator", "alive"} {
		if err := db.Execute(ctx,
			`INSERT OR REPLACE INTO host_health (observer, target, status, consecutive_failures, last_seen, updated_at)
			 VALUES (?, 'down', 'suspect', ?, NULL, ?)`, o, offlineThreshold, db.NowTS()); err != nil {
			t.Fatal(err)
		}
	}
	c := newTestCoordinator("coordinator", db)
	fences := 0
	c.SetFencer(func(context.Context, fence.HostConfig) fence.Result {
		fences++
		return fence.Result{Method: "ssh", Success: true}
	})
	c.run(ctx)
	if fences != 1 {
		t.Fatalf("the host, failing after it came back, was fenced %d times, want 1", fences)
	}
}
