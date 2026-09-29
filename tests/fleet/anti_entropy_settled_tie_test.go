package fleet

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// seedUnreplicatedLeaseTerm writes a leader_lease_terms row on n beneath the
// replicator, so only anti-entropy can carry it anywhere.
func seedUnreplicatedLeaseTerm(t *testing.T, n *Node, key string, term int64, holder string) {
	t.Helper()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	n.DB.Mu().Lock()
	_, err := n.DB.DB().Exec(
		`INSERT INTO leader_lease_terms (key, term, holder, acquired_at, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?)`, key, term, holder, now, now, now)
	n.DB.Mu().Unlock()
	if err != nil {
		t.Fatalf("seed lease term %s/%d on %s: %v", key, term, n.Name, err)
	}
}

func tableDumpsServed(c *Cluster) int { return c.AETablePulls("leader_lease_terms") }

// TestFleet_AntiEntropy_SettledTieIsNotRePulledEveryPass is the 5-node soak
// finding from colonelpanik/litevirt#262: one deliberately unresolved
// leader_lease_terms tie (two holders for one term, kept local on both sides
// until an operator acknowledges it) made every scheduled pass on every node
// find the digests different, pull the table, merge nothing, and do it again —
// forever, cluster-wide.
//
// The properties, in order:
//   - once a pull has shown that the table's only difference from this peer is
//     the tie already tracked, scheduled passes stop pulling it while neither
//     side's digest moves;
//   - the tie stays tracked (the condition, `lv doctor divergence` and the
//     gauges all read that register);
//   - a NEW row on the peer is pulled on the very next pass;
//   - the operator's full pass still pulls everything.
func TestFleet_AntiEntropy_SettledTieIsNotRePulledEveryPass(t *testing.T) {
	c := New(t, Options{Nodes: 2})
	a, b := c.Nodes[0], c.Nodes[1]
	b.DB.SetMembersForTests(func() []corrosion.PeerInfo { return []corrosion.PeerInfo{{Name: a.Name}} })
	ctx := context.Background()

	// Two holders for dual_run_detector term 2: an immutable-ledger conflict
	// that no merge resolves.
	seedUnreplicatedLeaseTerm(t, a, "dual_run_detector", 2, a.Name)
	seedUnreplicatedLeaseTerm(t, b, "dual_run_detector", 2, b.Name)

	// The catch-up pass meets the tie and tracks it.
	if !corrosion.NewAntiEntropy(b.DB, b.PKIDir, 0).RunOnce(ctx) {
		t.Fatal("the catch-up pass did not run")
	}
	if got := b.DB.UnresolvedTieCount(); got != 1 {
		t.Fatalf("precondition: b tracks %d unresolved ties after meeting the contested term, want 1", got)
	}
	if ok, why := b.DB.ReplicaCaughtUp(); !ok {
		t.Fatalf("precondition: b is not caught up after a full pass: %s", why)
	}

	// N scheduled passes: the table is pulled at most once between them. A
	// fresh AntiEntropy each time, as the observation test does, so the
	// cooldown never hides a pass.
	const passes = 6
	c.ResetAEStats()
	for i := 0; i < passes; i++ {
		if !corrosion.NewAntiEntropy(b.DB, b.PKIDir, 0).RunSampledOnce(ctx) {
			t.Fatalf("scheduled pass %d did not run", i)
		}
	}
	if got := tableDumpsServed(c); got > 1 {
		t.Errorf("%d scheduled passes pulled leader_lease_terms %d times for a tie already tracked "+
			"and unchanged on both sides; want at most 1", passes, got)
	}
	if got := b.DB.UnresolvedTieCount(); got != 1 {
		t.Errorf("the tie is no longer tracked after the deferred passes (count %d): the condition, "+
			"`lv doctor divergence` and the gauge would all read clean over a live conflict", got)
	}
	if h, ok := leaseTermHolder(t, b, "dual_run_detector", 2); !ok || h != b.Name {
		t.Errorf("b's own claim changed: holder %q present=%v", h, ok)
	}

	// A new row on the peer is a new difference in the same table: the very
	// next scheduled pass pulls it.
	seedUnreplicatedLeaseTerm(t, a, "failover", 7, a.Name)
	c.ResetAEStats()
	if !corrosion.NewAntiEntropy(b.DB, b.PKIDir, 0).RunSampledOnce(ctx) {
		t.Fatal("pass did not run")
	}
	if _, ok := leaseTermHolder(t, b, "failover", 7); !ok {
		t.Fatal("a new leader_lease_terms row on the peer was not pulled on the next pass: the " +
			"deferral hid a real difference behind the tracked tie")
	}
	if tableDumpsServed(c) == 0 {
		t.Fatal("the new row arrived without a table dump; the test is not measuring the pull")
	}

	// Settled again: the passes after it do not pull.
	c.ResetAEStats()
	for i := 0; i < passes; i++ {
		if !corrosion.NewAntiEntropy(b.DB, b.PKIDir, 0).RunSampledOnce(ctx) {
			t.Fatalf("scheduled pass %d did not run", i)
		}
	}
	// The pull that brought the new row already proved the rest is the tie.
	if got := tableDumpsServed(c); got != 0 {
		t.Errorf("after pulling the new row, %d scheduled passes pulled the table %d times; want 0",
			passes, got)
	}

	// The operator's full pass pulls whatever differs, settled or not.
	c.ResetAEStats()
	if !corrosion.NewAntiEntropy(b.DB, b.PKIDir, 0).RunOnce(ctx) {
		t.Fatal("full pass did not run")
	}
	if tableDumpsServed(c) == 0 {
		t.Error("the operator's full pass (lv cluster converge) skipped a settled table that still differs")
	}

	// A replica that is not caught up pulls everything that differs, as it
	// does for observation tables: the settlement vouches for a caught-up node.
	b.DB.MarkReplicaStale("test: lost every peer")
	c.ResetAEStats()
	if !corrosion.NewAntiEntropy(b.DB, b.PKIDir, 0).RunSampledOnce(ctx) {
		t.Fatal("pass did not run")
	}
	if tableDumpsServed(c) == 0 {
		t.Error("a stale replica's scheduled pass skipped a settled table")
	}

	// A local write moves b's own digest; that is a new difference too.
	seedUnreplicatedLeaseTerm(t, b, "failover", 9, b.Name)
	c.ResetAEStats()
	if !corrosion.NewAntiEntropy(b.DB, b.PKIDir, 0).RunSampledOnce(ctx) {
		t.Fatal("pass did not run")
	}
	if tableDumpsServed(c) == 0 {
		t.Error("a pass after a local write to the table did not re-check it against the peer")
	}
}

// TestFleet_AntiEntropy_NWayTieIsNotRePulledEveryPass is the shape the 5-node
// lab actually had after the two-way fix shipped: one lease term contested by
// EVERY node, five versions of one row, each node holding its own. A register
// that remembers one pair per row describes only the last peer this node met
// that row with, so against every other peer the proof saw an untracked
// version and the table was pulled every pass, at the old rate (#262).
//
// Every node's scheduled passes pull the table at most once, the tie stays
// tracked, and a new version of the row on a peer is still pulled at once.
func TestFleet_AntiEntropy_NWayTieIsNotRePulledEveryPass(t *testing.T) {
	c := New(t, Options{Nodes: 5})
	ctx := context.Background()
	for _, n := range c.Nodes {
		seedUnreplicatedLeaseTerm(t, n, "dual_run_detector", 2, n.Name)
	}
	// Each node's catch-up pass meets every other version.
	for _, n := range c.Nodes {
		if !corrosion.NewAntiEntropy(n.DB, n.PKIDir, 0).RunOnce(ctx) {
			t.Fatalf("%s: the catch-up pass did not run", n.Name)
		}
		if got := n.DB.UnresolvedTieCount(); got != 1 {
			t.Fatalf("precondition: %s tracks %d unresolved ties, want the one contested row", n.Name, got)
		}
		if ok, why := n.DB.ReplicaCaughtUp(); !ok {
			t.Fatalf("precondition: %s is not caught up: %s", n.Name, why)
		}
	}

	const passes = 6
	for _, n := range c.Nodes {
		c.ResetAEStats()
		for i := 0; i < passes; i++ {
			if !corrosion.NewAntiEntropy(n.DB, n.PKIDir, 0).RunSampledOnce(ctx) {
				t.Fatalf("%s: scheduled pass %d did not run", n.Name, i)
			}
		}
		if got := tableDumpsServed(c); got > 1 {
			t.Errorf("%s: %d scheduled passes pulled leader_lease_terms %d times for a five-way tie "+
				"it already tracks; want at most 1", n.Name, passes, got)
		}
		if got := n.DB.UnresolvedTieCount(); got != 1 {
			t.Errorf("%s: the tie is no longer tracked after the deferred passes (count %d)", n.Name, got)
		}
		if h, ok := leaseTermHolder(t, n, "dual_run_detector", 2); !ok || h != n.Name {
			t.Errorf("%s: its own claim changed: holder %q present=%v", n.Name, h, ok)
		}
	}

	// A sixth version of the tied row, on one peer, is a new difference: the
	// next pass against that peer pulls it, although the row is already tied.
	a, b := c.Nodes[0], c.Nodes[1]
	a.DB.Mu().Lock()
	_, err := a.DB.DB().Exec(`UPDATE leader_lease_terms SET holder = 'node-x'
		WHERE key = 'dual_run_detector' AND term = 2`)
	a.DB.Mu().Unlock()
	if err != nil {
		t.Fatalf("rewrite %s's version: %v", a.Name, err)
	}
	b.DB.SetMembersForTests(func() []corrosion.PeerInfo { return []corrosion.PeerInfo{{Name: a.Name}} })
	c.ResetAEStats()
	if !corrosion.NewAntiEntropy(b.DB, b.PKIDir, 0).RunSampledOnce(ctx) {
		t.Fatal("pass did not run")
	}
	if tableDumpsServed(c) == 0 {
		t.Error("a new version of the tied row on a peer was not pulled on the next pass")
	}
	// And once seen, it is settled too.
	c.ResetAEStats()
	for i := 0; i < passes; i++ {
		if !corrosion.NewAntiEntropy(b.DB, b.PKIDir, 0).RunSampledOnce(ctx) {
			t.Fatalf("scheduled pass %d did not run", i)
		}
	}
	if got := tableDumpsServed(c); got != 0 {
		t.Errorf("after pulling the sixth version, %d passes pulled the table %d times; want 0", passes, got)
	}
}

func leaseTermHolder(t *testing.T, n *Node, key string, term int64) (string, bool) {
	t.Helper()
	rows, err := n.DB.Query(context.Background(),
		`SELECT holder FROM leader_lease_terms WHERE key = ? AND term = ?`, key, term)
	if err != nil {
		t.Fatalf("read %s/%d on %s: %v", key, term, n.Name, err)
	}
	if len(rows) == 0 {
		return "", false
	}
	return rows[0].String("holder"), true
}
