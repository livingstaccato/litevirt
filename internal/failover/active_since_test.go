package failover

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fence"
	"github.com/litevirt/litevirt/internal/health"
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
	db, ctx := seedDownHost(t, "ssh", trustSSH)
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
		return fence.Result{Method: "ssh", Success: true, Detail: "stub [path=managed]"}
	})
	c.run(ctx)
	if fences != 0 {
		t.Fatalf("a host that just turned active was fenced on observations from before (%d fences)", fences)
	}

	// The observers count it down after it turned active: fenced as usual.
	// Their runs began after the boot write (last_seen, the run's first
	// failed probe), so the count is about the host active now.
	time.Sleep(10 * time.Millisecond)
	runStart := time.Now().UTC().Format(time.RFC3339Nano)
	for _, o := range []string{"coordinator", "alive"} {
		if err := db.Execute(ctx,
			`INSERT OR REPLACE INTO host_health (observer, target, status, consecutive_failures, last_seen, updated_at)
			 VALUES (?, 'down', 'suspect', ?, ?, ?)`, o, offlineThreshold, runStart, db.NowTS()); err != nil {
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
	db, ctx := seedDownHost(t, "ssh", trustSSH)
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

// countedSinceActive is the activation filter of the fence quorum: a verdict
// counts for a host recorded active since `since` only when it is about the
// host's current life — published after the activation, and either from a run
// that began after it or from one that has lasted a whole afreshRun since.
//
// Mutations: return true for a verdict published after the activation (the
// restart case of lab 1, 2026-10-11, fences at once); return false whenever
// the run began before the activation (a host that turned active and never
// answered is never fenced).
func TestCountedSinceActive(t *testing.T) {
	// Pinned, not derived: dropping the skew margin from afreshRun must fail
	// here, not move every row with it.
	if afreshRun != 13*time.Second {
		t.Fatalf("afreshRun = %s, want 13s: FailuresToFence-1 probe intervals (8 s) and fenceSkewMargin (5 s)", afreshRun)
	}
	since := time.Date(2026, 10, 11, 10, 48, 59, 0, time.UTC)
	rfc := func(t time.Time) string { return t.Format(time.RFC3339Nano) }
	for _, tc := range []struct {
		name     string
		n        int
		lastSeen string
		at       time.Time
		want     bool
	}{
		{"published before the activation", 9, rfc(since.Add(-20 * time.Second)), since.Add(-time.Second), false},
		{"run began after the activation", offlineThreshold, rfc(since.Add(time.Second)), since.Add(9 * time.Second), true},
		// node-2 on lab 1: the run began at its SIGTERM, 34 s before the boot
		// write, and its next unanswered probe landed 3 s after it.
		{"restart: run from before, 3s since", 22, rfc(since.Add(-34 * time.Second)), since.Add(3 * time.Second), false},
		{"restart: run from before, just short of a whole run since", 22, rfc(since.Add(-34 * time.Second)), since.Add(afreshRun - time.Millisecond), false},
		{"restart: run from before, a whole run since", 22, rfc(since.Add(-34 * time.Second)), since.Add(afreshRun), true},
		// The literal span: four probe intervals (8 s) and the 5 s skew margin.
		{"restart: run from before, 12.9s since", 22, rfc(since.Add(-34 * time.Second)), since.Add(12900 * time.Millisecond), false},
		{"restart: run from before, 13s since", 22, rfc(since.Add(-34 * time.Second)), since.Add(13 * time.Second), true},
		// An older observer's row has no last_seen: its run is taken to span
		// one probe interval per failure back from updated_at.
		{"older build: count reaches back before the activation", offlineThreshold, "", since.Add(2 * time.Second), false},
		{"older build: count fits after the activation", offlineThreshold, "", since.Add(time.Duration(offlineThreshold) * health.ProbeInterval), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := countedSinceActive(tc.n, tc.lastSeen, tc.at, since); got != tc.want {
				t.Errorf("countedSinceActive(n=%d, last_seen=%q, at=since%+v) = %v, want %v",
					tc.n, tc.lastSeen, tc.at.Sub(since), got, tc.want)
			}
		})
	}
}

// An older observer's row carries no last_seen; its run is estimated as one
// probe interval per failure back from updated_at (observerRunStart). Such a
// row whose estimated run fits after the host's activation counts toward the
// fence through run(), as it did before countedSinceActive.
//
// Mutation: treat a NULL last_seen as a run from before the activation — the
// host, failing since it turned active 9 s ago, is not fenced.
func TestHostJustActive_OlderObserverRowCounts(t *testing.T) {
	db, ctx := seedDownHost(t, "ssh", trustSSH)
	liveMembership(t, db)
	// The host turned active 9 s ago: FailuresToFence probes (8 s) fit since.
	if _, err := db.DB().Exec(`UPDATE host_membership SET state = 'active', updated_at = ? WHERE host_name = 'down'`,
		time.Now().Add(-9*time.Second).UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	for _, o := range []string{"coordinator", "alive"} {
		if err := db.Execute(ctx,
			`INSERT OR REPLACE INTO host_health (observer, target, status, consecutive_failures, last_seen, updated_at)
			 VALUES (?, 'down', 'suspect', ?, NULL, ?)`, o, offlineThreshold, db.NowTS()); err != nil {
			t.Fatalf("insert health: %v", err)
		}
	}
	c := newTestCoordinator("coordinator", db)
	fences := 0
	c.SetFencer(func(context.Context, fence.HostConfig) fence.Result {
		fences++
		return fence.Result{Method: "ssh", Success: true, Detail: "stub [path=managed]"}
	})
	c.run(ctx)
	if fences != 1 {
		t.Fatalf("a host failing since it turned active, seen by older observers, was fenced %d times, want 1", fences)
	}
}
