// A host rebuilt with an EMPTY database must not claim a leader-lease term
// before it has caught up the lease ledger from its peers.
//
// Observed on the kvm003-f3 lab (main-b3368d7c, drill 6, 2026-10-03): node-5
// was removed with `lv host rm --dead`, rebuilt, and re-added with
// `lv host add`. Its daemon started at 22:04:02 on an empty state.db whose hosts
// table held only its own row. Thirty seconds later it recorded `failover`
// term 1, and at 22:05:05 `dual_run_detector` term 1 — both minted by node-1 on
// 2026-09-15. Its first anti-entropy exchange completed at 22:05:06, one second
// after the second mint. Two claimants for one (key, term) is an immutable
// ledger conflict that never heals: the drill had to acknowledge both ties on
// every host. A term is a fencing token, so a reused number is a safety
// problem, not only noise.
//
// The mint clearance asks a quorum of peers for their newest term. On that
// replica the quorum was the node itself: its voter set, derived from a hosts
// table that named only itself, was {node-5}, it had no peer to ask, and the
// high-water read returned its own empty ledger. Nothing the clearance could
// read on that replica said otherwise, which is why the gate is the replica's
// catch-up (corrosion.Client.ReplicaCaughtUp), the same signal the workload
// mutations wait on (grpcapi/replica_gate.go).
package fleet

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// TestFleet_LeaseClaim_AFreshDatabaseDoesNotReuseATerm:
//
//  1. a holds the failover lease at term 1, then re-takes it after a lapse at
//     term 2; every replica has both rows;
//  2. d is rebuilt on an empty database that knows only its own host row, and
//     nothing reaches it yet (its daemon has just started);
//  3. past a's expiry, d polls. It must record no term at all;
//  4. once an anti-entropy exchange has caught d up, it takes over above the
//     history, at term 3, and no term anywhere has two claimants.
//
// Mutation: drop the catch-up requirement from Server.LeaseMintClearance and d
// records its own term 1 in step 3.
func TestFleet_LeaseClaim_AFreshDatabaseDoesNotReuseATerm(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 4, IndependentReplicas: true, FaultSeed: 1009})
	a, d := c.Nodes[0], c.Nodes[3]
	runCheckers(t, c)
	wireMintClearance(c)

	// 1.
	t0 := time.Now().UTC()
	if held, term := acquireAt(t, a, t0); !held || term != 1 {
		t.Fatalf("%s: held=%v term=%d, want term 1", a.Name, held, term)
	}
	t1 := t0.Add(catchUpTTL + catchUpPoll)
	if held, term := acquireAt(t, a, t1); !held || term != 2 {
		t.Fatalf("%s: held=%v term=%d after a lapse, want a new tenure at term 2", a.Name, held, term)
	}
	c.WaitConverged(t, convergeTimeout)

	// 2. d is reinstalled. Its database is empty but for its own row, as the
	// lab's was: rebuildWithEmptyDB seeds the peers' rows, which `lv host add`
	// does not, so they are taken out again without logging. Pushes into d are
	// held back, as nothing had reached node-5 when it minted.
	serial := rebuildWithEmptyDB(t, c, d, a)
	if _, err := d.DB.DB().Exec(`DELETE FROM hosts WHERE name != ?`, d.Name); err != nil {
		t.Fatalf("empty %s's hosts table: %v", d.Name, err)
	}
	bootRebuiltNode(t, d, serial)
	d.DB.MarkReplicaStale("process started on a fresh database (fleet: modelled reinstall)")
	for _, p := range c.Nodes {
		if p != d {
			c.SetLinkFault(p, d, LinkFault{Block: true})
		}
	}
	d.DB.SetLeaseMintClearance(d.Server.LeaseMintClearance)
	gd := gateFor(t, c, d)
	gctx, cancel := context.WithCancel(ctx)
	t.Cleanup(cancel)
	go gd.Start(gctx)
	eventually(t, 20*time.Second, d.Name+" holds quorum on its own replica", func() bool {
		st, _, _ := gd.QuorumProof(ctx)
		return st == health.QuorumYes
	})
	if newest, err := corrosion.CurrentLeaseTerm(ctx, d.DB, leaseTermKey); err != nil || newest != 0 {
		t.Fatalf("precondition: %s's ledger must be empty (newest %d, %v)", d.Name, newest, err)
	}

	// 3. Past a's expiry, so nothing a peer could report about a LIVE lease
	// refuses d: only the term question remains.
	later := t1.Add(catchUpTTL + catchUpPoll)
	if held, term := acquireAt(t, d, later); held {
		t.Fatalf("%s took the lease at term %d on a fresh database that had not caught up; "+
			"%s minted terms 1 and 2", d.Name, term, a.Name)
	}
	for term := int64(1); term <= 2; term++ {
		if h, found := leaseTermHolderAt(t, d, term); found && h == d.Name {
			t.Fatalf("%s recorded its own term %d, which %s already holds: a permanent "+
				"immutable-ledger conflict on a fencing token", d.Name, term, a.Name)
		}
	}
	if ok, why := d.Server.LeaseMintClearance(ctx, termMint(d, 1, later)); ok || !strings.Contains(why, "caught up") {
		t.Fatalf("%s's clearance for term 1: ok=%v reason=%q; want it withheld until the replica "+
			"has caught up", d.Name, ok, why)
	}

	// 4. Catch-up: the links heal, the peers' host rows arrive (on the lab, by
	// replication, half a minute in; anti-entropy dials peers through them),
	// and an anti-entropy exchange completes.
	c.ClearLinkFaults()
	rows, err := a.DB.Query(ctx, `SELECT * FROM hosts WHERE name != ?`, d.Name)
	if err != nil {
		t.Fatalf("read %s's host rows: %v", a.Name, err)
	}
	for _, r := range rows {
		marks := strings.TrimSuffix(strings.Repeat("?, ", len(r.Columns)), ", ")
		if _, err := d.DB.DB().Exec(`INSERT OR REPLACE INTO hosts (`+strings.Join(r.Columns, ", ")+`) VALUES (`+marks+`)`,
			r.Values...); err != nil {
			t.Fatalf("deliver a host row to %s: %v", d.Name, err)
		}
	}
	convergeByAntiEntropy(t, c, convergeTimeout)
	if ok, why := d.DB.ReplicaCaughtUp(); !ok {
		t.Fatalf("%s did not catch up: %s", d.Name, why)
	}
	eventually(t, 20*time.Second, d.Name+" takes over above the history", func() bool {
		held, term, err := corrosion.AcquireLeaseWithTerm(ctx, d.DB, leaseTermKey, d.Name, catchUpTTL, later)
		if err != nil {
			t.Fatalf("%s acquire: %v", d.Name, err)
		}
		if held && term != 3 {
			t.Fatalf("%s took the lease at term %d once caught up; want term 3, above %s's 2",
				d.Name, term, a.Name)
		}
		return held
	})
	c.WaitConverged(t, convergeTimeout)
	for _, n := range c.Nodes {
		for term, want := range map[int64]string{1: a.Name, 2: a.Name, 3: d.Name} {
			if h, found := leaseTermHolderAt(t, n, term); !found || h != want {
				t.Errorf("%s: term %d holder = %q (found=%v), want %s", n.Name, term, h, found, want)
			}
		}
	}
}
