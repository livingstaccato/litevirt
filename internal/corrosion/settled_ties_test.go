package corrosion

import (
	"context"
	"testing"
)

// peerLeaseTerms is b's leader_lease_terms as the dump carries it: JSON over
// the wire, so value kinds are the post-transit ones the merge sees.
func peerLeaseTerms(t *testing.T, b *Client) syncTable {
	t.Helper()
	p, err := decompressPayload(b.dumpStateForTables([]string{"leader_lease_terms"}))
	if err != nil || len(p.Tables) != 1 {
		t.Fatalf("dump b's leader_lease_terms: err=%v tables=%d", err, len(p.Tables))
	}
	return p.Tables[0]
}

// The proof behind a settled table (settled_ties.go) answers true ONLY when
// every row that differs from the peer is a tie the register holds under
// exactly that pair of versions. Each false case below is a difference a later
// pull could still act on, or one the register does not vouch for, and would
// be hidden by a proof that answered true.
func TestResidualIsTrackedTies(t *testing.T) {
	ctx := context.Background()
	const ts = "2026-01-01T00:00:00Z"
	a, b := newTestDB(t), newTestDB(t)
	putLeaseTerm(t, a, "dual_run_detector", 2, "host-a", ts, ts)
	putLeaseTerm(t, b, "dual_run_detector", 2, "host-b", ts, ts)
	putLeaseTerm(t, a, "failover", 1, "host-a", ts, ts)
	putLeaseTerm(t, b, "failover", 1, "host-a", ts, ts)
	if err := a.MergeStateBytesLWW(b.DumpStateBytes()); err != nil {
		t.Fatal(err)
	}
	if a.UnresolvedTieCount() != 1 {
		t.Fatalf("precondition: a tracks %d ties, want the contested term", a.UnresolvedTieCount())
	}

	st := peerLeaseTerms(t, b)
	local, ties, ok := a.residualIsTrackedTies(ctx, st)
	if !ok || len(ties) != 1 {
		t.Fatalf("a table differing only by the tracked tie was not proven settled: ok=%v ties=%v", ok, ties)
	}
	digests, err := a.stateDigestForTables(ctx, []string{"leader_lease_terms"})
	if err != nil || len(digests) != 1 || !sameDigest(local, digests[0]) {
		t.Fatalf("the proof's local digest %+v is not StateDigest's %+v: a pass would never match it", local, digests)
	}

	t.Run("a differing row that is not a tracked tie", func(t *testing.T) {
		// Same PK, different facts, never merged: the register knows nothing.
		putLeaseTerm(t, b, "failover", 1, "host-b", ts, ts)
		defer putLeaseTerm(t, b, "failover", 1, "host-a", ts, ts)
		if _, _, ok := a.residualIsTrackedTies(ctx, peerLeaseTerms(t, b)); ok {
			t.Fatal("proven settled with a differing row the register does not hold")
		}
	})
	t.Run("the tie row with a different version than the one tracked", func(t *testing.T) {
		putLeaseTerm(t, b, "dual_run_detector", 2, "host-c", ts, ts)
		defer putLeaseTerm(t, b, "dual_run_detector", 2, "host-b", ts, ts)
		if _, _, ok := a.residualIsTrackedTies(ctx, peerLeaseTerms(t, b)); ok {
			t.Fatal("proven settled against a version of the tied row the register never saw")
		}
	})
	t.Run("a row on the peer only", func(t *testing.T) {
		putLeaseTerm(t, b, "failover", 2, "host-b", ts, ts)
		defer func() {
			if _, err := b.db.Exec(`DELETE FROM leader_lease_terms WHERE key='failover' AND term=2`); err != nil {
				t.Fatal(err)
			}
		}()
		if _, _, ok := a.residualIsTrackedTies(ctx, peerLeaseTerms(t, b)); ok {
			t.Fatal("proven settled although the peer holds a row this node lacks")
		}
	})
	t.Run("a row on this node only", func(t *testing.T) {
		putLeaseTerm(t, a, "failover", 3, "host-a", ts, ts)
		defer func() {
			if _, err := a.db.Exec(`DELETE FROM leader_lease_terms WHERE key='failover' AND term=3`); err != nil {
				t.Fatal(err)
			}
		}()
		if _, _, ok := a.residualIsTrackedTies(ctx, peerLeaseTerms(t, b)); ok {
			t.Fatal("proven settled although this node holds a row the peer lacks")
		}
	})
	t.Run("the tie cleared from the register", func(t *testing.T) {
		defer func() {
			if err := a.MergeStateBytesLWW(b.DumpStateBytes()); err != nil {
				t.Fatal(err)
			}
		}()
		a.clearUnresolved("leader_lease_terms", pkKey([]interface{}{"dual_run_detector", int64(2)}))
		if _, _, ok := a.residualIsTrackedTies(ctx, peerLeaseTerms(t, b)); ok {
			t.Fatal("proven settled on a tie the register no longer holds")
		}
		if a.tiesStillTracked(ties) {
			t.Fatal("a recorded settlement still vouches for a tie the register dropped")
		}
	})

	t.Run("a clear drops the version set with the register entry", func(t *testing.T) {
		key := unresolvedKey("leader_lease_terms", pkKey([]interface{}{"dual_run_detector", int64(2)}))
		defer func() {
			if err := a.MergeStateBytesLWW(b.DumpStateBytes()); err != nil {
				t.Fatal(err)
			}
		}()
		a.clearUnresolved("leader_lease_terms", pkKey([]interface{}{"dual_run_detector", int64(2)}))
		a.tieMu.Lock()
		_, kept := a.tieVersions[key]
		a.tieMu.Unlock()
		if kept {
			t.Fatal("clearUnresolved left the row's version set behind; a later tie would inherit stale versions")
		}
	})

	// Back where it started: settled again.
	if _, _, ok := a.residualIsTrackedTies(ctx, peerLeaseTerms(t, b)); !ok {
		t.Fatal("the subtests did not restore the settled state")
	}
}

// An N-way contest: one row, a different version on each of three nodes. The
// register keeps one pair per row, and after meeting c's version it names
// (a, c) — so a proof against b that asked for THE tracked pair failed, and b's
// table was re-pulled every pass (the lab's five-version dual_run_detector
// term). Every version met is in the row's set, so both peers settle.
func TestResidualIsTrackedTies_NWay(t *testing.T) {
	ctx := context.Background()
	const ts = "2026-01-01T00:00:00Z"
	a, b, c := newTestDB(t), newTestDB(t), newTestDB(t)
	putLeaseTerm(t, a, "dual_run_detector", 2, "host-a", ts, ts)
	putLeaseTerm(t, b, "dual_run_detector", 2, "host-b", ts, ts)
	putLeaseTerm(t, c, "dual_run_detector", 2, "host-c", ts, ts)
	for _, peer := range []*Client{b, c} {
		if err := a.MergeStateBytesLWW(peer.DumpStateBytes()); err != nil {
			t.Fatal(err)
		}
	}
	if got := a.UnresolvedTieCount(); got != 1 {
		t.Fatalf("precondition: a tracks %d ties, want the one contested row", got)
	}
	for name, peer := range map[string]*Client{"b": b, "c": c} {
		if _, _, ok := a.residualIsTrackedTies(ctx, peerLeaseTerms(t, peer)); !ok {
			t.Errorf("against %s: a three-way tie a has met every version of was not proven settled", name)
		}
	}
	// A version set outliving its register entry (clearUnresolved removes both
	// today; this pins that the set alone never vouches) proves nothing.
	a.tieMu.Lock()
	a.tieVersions["orphan\x00pk"] = map[string]struct{}{"v1": {}, "v2": {}}
	orphanKnown := a.tieVersionsKnownLocked("orphan\x00pk", "v1", "v2")
	a.tieMu.Unlock()
	if orphanKnown {
		t.Error("a version set with no tracked tie behind it vouched for a difference")
	}

	// A fourth version, never merged, is still unexplained.
	putLeaseTerm(t, b, "dual_run_detector", 2, "host-d", ts, ts)
	if _, _, ok := a.residualIsTrackedTies(ctx, peerLeaseTerms(t, b)); ok {
		t.Error("proven settled against a version of the tied row no merge has seen")
	}
}
