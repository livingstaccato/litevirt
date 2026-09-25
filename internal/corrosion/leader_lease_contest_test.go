package corrosion

import (
	"context"
	"reflect"
	"testing"
	"time"
)

// Unit tests for the contested-lease convergence rule. The end-to-end property
// (two or three real nodes converge to one holder and stay there) lives in
// tests/fleet/leader_lease_contest_test.go; these pin the pieces a fleet run
// cannot isolate.

// TestLeaseContest_AntiEntropyNotesBothClaimants: the dump path keeps each
// node's own claim — the ledger contract, unchanged — AND tells the lease layer
// who the other claimant is. Without the second half the lease cannot converge,
// because nothing else on the replica records that anyone else claimed the term.
func TestLeaseContest_AntiEntropyNotesBothClaimants(t *testing.T) {
	a, b := newTestDB(t), newTestDB(t)
	putLeaseTerm(t, a, "failover", 1, "host-a", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00.000000Z")
	putLeaseTerm(t, b, "failover", 1, "host-b", "2026-01-01T00:00:05Z", "2026-01-01T00:00:05.000000Z")

	gossipLeaseTerms(t, a, b)

	want := []string{"host-a", "host-b"}
	for name, c := range map[string]*Client{"a": a, "b": b} {
		if got := c.leaseTermClaimants("failover", 1); !reflect.DeepEqual(got, want) {
			t.Errorf("node %s claimants for failover/1 = %v, want %v", name, got, want)
		}
		// The ledger itself is untouched: still flagged, still kept local.
		if c.UnresolvedTieCount() == 0 {
			t.Errorf("node %s: the contested row is no longer flagged as an unresolved tie", name)
		}
	}
	if h, _, _ := LeaseTermHolder(context.Background(), a, "failover", 1); h != "host-a" {
		t.Errorf("a's term-1 row now names %q; the merge must still keep local", h)
	}
	if h, _, _ := LeaseTermHolder(context.Background(), b, "failover", 1); h != "host-b" {
		t.Errorf("b's term-1 row now names %q; the merge must still keep local", h)
	}
}

// TestLeaseContest_OneClaimantIsNotAContest: a claimant set of one — including
// an idempotent re-delivery of our own row — must not read as contested.
func TestLeaseContest_OneClaimantIsNotAContest(t *testing.T) {
	c := newTestDB(t)
	c.noteLeaseTermClaims("failover", 1, "host-a", "host-a", "")
	if got := c.leaseTermClaimants("failover", 1); got != nil {
		t.Fatalf("a single claimant reads as contested: %v", got)
	}
}

// contestedTenure gives c a live tenure of `holder` at term 1 and records that
// `rival` also claimed term 1.
func contestedTenure(t *testing.T, c *Client, holder, rival string) {
	t.Helper()
	held, term, err := AcquireLeaseWithTerm(context.Background(), c, LeaseKeyFailover, holder, time.Minute, leaseTestNow)
	if err != nil || !held || term != 1 {
		t.Fatalf("seed tenure: held=%v term=%d err=%v", held, term, err)
	}
	c.noteLeaseTermClaims(LeaseKeyFailover, 1, holder, rival)
}

// TestLeaseContest_TheLoserStandsDown: a claimant that learns of a
// lower-sorting claim for its own current term stops renewing on that tick.
func TestLeaseContest_TheLoserStandsDown(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	contestedTenure(t, c, "host-b", "host-a")

	held, term, err := AcquireLeaseWithTerm(ctx, c, LeaseKeyFailover, "host-b", time.Minute, leaseTestNow.Add(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if held {
		t.Fatalf("host-b renewed (term %d) after learning host-a also claimed its term; it must stand down", term)
	}
	if n, _ := CurrentLeaseTerm(ctx, c, LeaseKeyFailover); n != 1 {
		t.Errorf("a standing-down loser moved the threshold to %d; it must mint nothing", n)
	}
}

// TestLeaseContest_TheWinnerRetiresTheContestedTerm: the claimant that
// continues does so under a FRESH term, not the contested one.
func TestLeaseContest_TheWinnerRetiresTheContestedTerm(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	contestedTenure(t, c, "host-a", "host-b")

	held, term, err := AcquireLeaseWithTerm(ctx, c, LeaseKeyFailover, "host-a", time.Minute, leaseTestNow.Add(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if !held || term != 2 {
		t.Fatalf("winner: held=%v term=%d, want held at term 2 (the contested term 1 retired)", held, term)
	}
	// And the next tick is an ordinary renewal: term 2 is not contested.
	held, term, err = AcquireLeaseWithTerm(ctx, c, LeaseKeyFailover, "host-a", time.Minute, leaseTestNow.Add(10*time.Second))
	if err != nil || !held || term != 2 {
		t.Fatalf("renewal after retirement: held=%v term=%d err=%v, want term 2 again", held, term, err)
	}
}

// TestLeaseContest_ARetirementClassifiedFromAStaleReadDeclines: the guard, not
// the classification, decides a retirement. A peer's higher term that lands
// between the two means the contested term is no longer the newest, and minting
// above it then would promote us over a claim we never saw — the escalation the
// fail-closed branch in AcquireLeaseWithTerm exists to prevent.
func TestLeaseContest_ARetirementClassifiedFromAStaleReadDeclines(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	contestedTenure(t, c, "host-a", "host-b")
	putLeaseTerm(t, c, LeaseKeyFailover, 2, "host-c", "2026-09-08T12:00:02Z", c.NowTS())

	nowRFC := leaseTestNow.Add(5 * time.Second).UTC().Format(time.RFC3339)
	expires := leaseTestNow.Add(time.Minute).UTC().Format(time.RFC3339)
	held, _, err := takeLeaseAndMintTerm(ctx, c, LeaseKeyFailover, "host-a", expires, nowRFC,
		leaseTestNow.Add(5*time.Second), true, 1)
	if err != nil {
		t.Fatal(err)
	}
	if held {
		t.Fatal("retired term 1 although a peer's term 2 had superseded it")
	}
	if n, _ := CurrentLeaseTerm(ctx, c, LeaseKeyFailover); n != 2 {
		t.Errorf("threshold is %d after a declined retirement, want the peer's 2", n)
	}
}

// TestLeaseContest_AcknowledgingTheTieDoesNotRevivetheLoser: an operator
// acknowledging a contested term clears EVIDENCE TRACKING. It must not be what
// lets a losing claimant resume acting, which is why the claimant register is
// not the unresolved-tie register.
func TestLeaseContest_AcknowledgingTheTieDoesNotReviveTheLoser(t *testing.T) {
	ctx := context.Background()
	a, b := newTestDB(t), newTestDB(t)
	for _, n := range []struct {
		c      *Client
		holder string
	}{{a, "host-a"}, {b, "host-b"}} {
		if held, term, err := AcquireLeaseWithTerm(ctx, n.c, LeaseKeyFailover, n.holder, time.Minute, leaseTestNow); err != nil || !held || term != 1 {
			t.Fatalf("%s claim: held=%v term=%d err=%v", n.holder, held, term, err)
		}
	}
	gossipLeaseTerms(t, a, b)
	if ok, err := b.AcknowledgeLeaseTermTie(ctx, LeaseKeyFailover, 1, "operator"); err != nil || !ok {
		t.Fatalf("acknowledge: ok=%v err=%v", ok, err)
	}
	if held, term, err := AcquireLeaseWithTerm(ctx, b, LeaseKeyFailover, "host-b", time.Minute, leaseTestNow.Add(5*time.Second)); err != nil || held {
		t.Fatalf("host-b after the tie was acknowledged: held=%v term=%d err=%v; it lost the contest "+
			"and must stay stood down", held, term, err)
	}
}

// TestDeferTakeover pins the takeover-deferral predicate case by case.
func TestDeferTakeover(t *testing.T) {
	now := leaseTestNow
	ttl := 45 * time.Second
	expiredAt := func(ago time.Duration) string { return now.Add(-ago).UTC().Format(time.RFC3339) }
	cases := []struct {
		name                         string
		curHolder, curExp, eff, self string
		want                         bool
	}{
		{"no row: nothing to wait for", "", expiredAt(time.Second), "host-a", "host-b", false},
		{"row names the incarnation we saw lapse", "host-a", expiredAt(time.Second), "host-a", "host-b", false},
		{"the incarnation is ours", "host-c", expiredAt(time.Second), "host-b", "host-b", false},
		{"stale row, incarnation elsewhere, inside one TTL", "host-b", expiredAt(time.Second), "host-a", "host-b", true},
		{"stale row, incarnation elsewhere, at the TTL boundary", "host-b", expiredAt(ttl), "host-a", "host-b", true},
		{"stale row, incarnation elsewhere, past one TTL", "host-b", expiredAt(ttl + time.Second), "host-a", "host-b", false},
		{"bystander whose row missed a takeover", "host-x", expiredAt(time.Second), "host-a", "host-b", true},
		{"no incarnation recorded", "host-b", expiredAt(time.Second), "", "host-c", false},
		{"unparseable expiry does not defer", "host-b", "garbage", "host-a", "host-c", false},
	}
	for _, tc := range cases {
		if got := deferTakeover(tc.curHolder, tc.curExp, tc.eff, tc.self, now, ttl); got != tc.want {
			t.Errorf("%s: deferTakeover = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestLeaseContest_AStoodDownLoserIsNotReportedAsHolder: before the winner's
// fresh term reaches it, the loser's replica knows only that its term is
// contested — its own lease row and its own term-1 row still name it. It must
// not report itself as the holder from that moment, not one TTL later.
func TestLeaseContest_AStoodDownLoserIsNotReportedAsHolder(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	now := leaseTestNow.Add(time.Second)

	held, term, err := AcquireLeaseWithTerm(ctx, c, LeaseKeyFailover, "host-b", time.Minute, leaseTestNow)
	if err != nil || !held || term != 1 {
		t.Fatalf("seed tenure: held=%v term=%d err=%v", held, term, err)
	}
	if got, err := IsLeaseHolder(ctx, c, LeaseKeyFailover, "host-b", now); err != nil || !got {
		t.Fatalf("uncontested holder: IsLeaseHolder=%v err=%v, want true", got, err)
	}

	c.noteLeaseTermClaims(LeaseKeyFailover, 1, "host-b", "host-a")

	if got, err := IsLeaseHolder(ctx, c, LeaseKeyFailover, "host-b", now); err != nil || got {
		t.Fatalf("host-b lost the contest for term 1 to host-a but IsLeaseHolder=%v err=%v, want false", got, err)
	}
}
