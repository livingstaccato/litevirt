package fleet

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// seedUnreplicatedHealth writes a host_health row on n beneath the replicator,
// so only anti-entropy can carry it anywhere.
func seedUnreplicatedHealth(t *testing.T, n *Node, observer, target string) {
	t.Helper()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	n.DB.Mu().Lock()
	_, err := n.DB.DB().Exec(
		`INSERT OR REPLACE INTO host_health (observer, target, status, consecutive_failures, last_seen, updated_at)
		 VALUES (?, ?, 'healthy', 0, ?, ?)`, observer, target, now, now)
	n.DB.Mu().Unlock()
	if err != nil {
		t.Fatalf("seed host_health %s→%s on %s: %v", observer, target, n.Name, err)
	}
}

func hasHealthRow(t *testing.T, n *Node, observer, target string) bool {
	t.Helper()
	return rowCount(t, n, `SELECT COUNT(*) AS n FROM host_health WHERE observer = ? AND target = ?`, observer, target) == 1
}

// A drifted observation table does not ride along with every control repair.
// Its writers re-publish it on their own cadence, so a scheduled pass repairs
// it at most once per observation-repair interval; control state drifted in
// the same exchange is repaired at once, and the operator's full pass repairs
// everything (#262 (d)).
func TestFleet_AntiEntropy_ObservationDriftIsRepairedOnItsOwnCadence(t *testing.T) {
	c := New(t, Options{Nodes: 2})
	a, b := c.Nodes[0], c.Nodes[1]
	b.DB.SetMembersForTests(func() []corrosion.PeerInfo { return []corrosion.PeerInfo{{Name: a.Name}} })
	ctx := context.Background()
	if !corrosion.NewAntiEntropy(b.DB, b.PKIDir, 0).RunOnce(ctx) {
		t.Fatal("the catch-up pass did not run")
	}
	if ok, why := b.DB.ReplicaCaughtUp(); !ok {
		t.Fatalf("precondition: b is not caught up after a full pass: %s", why)
	}

	// The first observation drift is repaired: nothing has been repaired yet.
	seedUnreplicatedHealth(t, a, "obs-1", "tgt-1")
	if !corrosion.NewAntiEntropy(b.DB, b.PKIDir, 0).RunSampledOnce(ctx) {
		t.Fatal("pass did not run")
	}
	if !hasHealthRow(t, b, "obs-1", "tgt-1") {
		t.Fatal("the first observation drift was not repaired")
	}

	// Within the interval a further observation drift waits, but the control
	// drift beside it does not.
	seedUnreplicatedHealth(t, a, "obs-2", "tgt-2")
	seedUnreplicatedStack(t, a, "drifted-stack")
	if !corrosion.NewAntiEntropy(b.DB, b.PKIDir, 0).RunSampledOnce(ctx) {
		t.Fatal("pass did not run")
	}
	if !hasStack(t, b, "drifted-stack") {
		t.Fatal("control drift was not repaired alongside a deferred observation drift")
	}
	if hasHealthRow(t, b, "obs-2", "tgt-2") {
		t.Fatal("a scheduled pass repaired observation drift again within the observation-repair interval")
	}

	// The operator's full pass repairs it regardless of the interval.
	if !corrosion.NewAntiEntropy(b.DB, b.PKIDir, 0).RunOnce(ctx) {
		t.Fatal("pass did not run")
	}
	if !hasHealthRow(t, b, "obs-2", "tgt-2") {
		t.Fatal("the operator's full pass did not repair observation drift")
	}

	// And once the interval has passed, a scheduled pass repairs it again.
	defer b.DB.SetObservationRepairIntervalForTests(0)()
	seedUnreplicatedHealth(t, a, "obs-3", "tgt-3")
	if !corrosion.NewAntiEntropy(b.DB, b.PKIDir, 0).RunSampledOnce(ctx) {
		t.Fatal("pass did not run")
	}
	if !hasHealthRow(t, b, "obs-3", "tgt-3") {
		t.Fatal("observation drift was not repaired once its interval had passed")
	}
}

// A replica that is not caught up — just started, or back from losing every
// peer — repairs observations with everything else. What it missed while away
// includes the health rows a returning node is judged by.
func TestFleet_AntiEntropy_StaleReplicaRepairsObservationsAtOnce(t *testing.T) {
	c := New(t, Options{Nodes: 2})
	a, b := c.Nodes[0], c.Nodes[1]
	b.DB.SetMembersForTests(func() []corrosion.PeerInfo { return []corrosion.PeerInfo{{Name: a.Name}} })
	ctx := context.Background()
	// Stamp a recent observation repair so only staleness can make it due.
	seedUnreplicatedHealth(t, a, "obs-0", "tgt-0")
	if !corrosion.NewAntiEntropy(b.DB, b.PKIDir, 0).RunOnce(ctx) {
		t.Fatal("pass did not run")
	}
	b.DB.MarkReplicaStale("test: lost every peer")

	seedUnreplicatedHealth(t, a, "obs-1", "tgt-1")
	if !corrosion.NewAntiEntropy(b.DB, b.PKIDir, 0).RunSampledOnce(ctx) {
		t.Fatal("pass did not run")
	}
	if !hasHealthRow(t, b, "obs-1", "tgt-1") {
		t.Fatal("a stale replica deferred observation repair")
	}
}
