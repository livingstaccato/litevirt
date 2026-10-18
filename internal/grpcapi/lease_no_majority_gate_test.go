package grpcapi

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// setTestLease writes key's leader_election row on s's replica.
func setTestLease(t *testing.T, s *Server, key, holder string, expires time.Time) {
	t.Helper()
	exp := expires.UTC().Format(time.RFC3339)
	if err := s.db.Execute(context.Background(),
		`INSERT INTO leader_election (key, holder, expires_at, updated_at)
		 VALUES (?, ?, ?, ?)
		 ON CONFLICT(key) DO UPDATE SET holder = excluded.holder,
		   expires_at = excluded.expires_at, updated_at = excluded.updated_at`,
		key, holder, exp, exp); err != nil {
		t.Fatalf("seed lease: %v", err)
	}
}

// A node that stays at the health gate never renews or takes the lease, so
// NoteLeaseLive never runs for it. Seeing the lease live for a peer must still
// end its stall: otherwise the next ordinary holder change, a lease expired for
// a moment, raises ha.lease.claim_no_majority at once with a stall start from
// before that holder, instead of a TTL after the stall began again.
//
// Mutation: NoteLeaseNoQuorum returns silently over a live holder, or
// NoteLeaseNoMajority ignores ev.Live — the brief expiry raises at once.
func TestLeaseClaimNoMajority_AGateNodeSeeingALiveHolderForgetsItsStall(t *testing.T) {
	ctx := context.Background()
	s := testServer(t)
	s.db.SetLeaseNoMajorityObserver(s.NoteLeaseNoMajority)
	counted := 0
	s.SetLeaseClaimNoMajorityObserver(func(string) { counted++ })
	key, ttl := corrosion.LeaseKeyFailover, 30*time.Second
	t0 := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)

	// Nobody holds it and this node is at the gate: a stall begins.
	corrosion.NoteLeaseNoQuorum(ctx, s.db, key, s.hostName, ttl, t0)

	// A week later a peer holds it, renewed; this node is still at the gate.
	t1 := t0.Add(7 * 24 * time.Hour)
	setTestLease(t, s, key, "peer", t1.Add(ttl))
	corrosion.NoteLeaseNoQuorum(ctx, s.db, key, s.hostName, ttl, t1)

	// The holder changes and the lease is expired for a moment.
	t2 := t1.Add(ttl + time.Second)
	corrosion.NoteLeaseNoQuorum(ctx, s.db, key, s.hostName, ttl, t2)
	if noMajorityRaised(t, s) {
		t.Fatal("a brief expiry at a holder change raised the condition from a stall start a week old")
	}

	// The non-vacuous half: a TTL with no takeover from the new start raises.
	corrosion.NoteLeaseNoQuorum(ctx, s.db, key, s.hostName, ttl, t2.Add(ttl))
	if !noMajorityRaised(t, s) {
		t.Fatal("fixture: a TTL with no takeover raised nothing")
	}
	// The live sighting is not a no-majority poll.
	if counted != 3 {
		t.Fatalf("%d no-majority polls counted, want 3 (the live sighting is not one)", counted)
	}
}

// A clearance whose high-water sweep did not run, because the health gate is
// not wired yet at start-up, asked no quorum and is not counted as a
// no-majority poll. The same node, once its gate reports the quorum lost, is.
//
// Mutation: drop the unwired check in LeaseMintClearance — the start-up
// clearance is counted and this goes red.
func TestLeaseMintClearance_AnUnwiredGateIsNotANoMajority(t *testing.T) {
	ctx := context.Background()
	s := testServer(t)
	insertTestHost(t, ctx, s.db, s.hostName, "active")
	insertTestHost(t, ctx, s.db, "node-c", "active")
	s.db.MarkReplicaCaughtUpForTests("node-c")
	counted := 0
	s.SetLeaseClaimNoMajorityObserver(func(string) { counted++ })
	req := corrosion.LeaseMintRequest{Key: corrosion.LeaseKeyFailover, Term: 1, Holder: s.hostName,
		Takeover: true, Now: clearanceNow, TTL: 30 * time.Second}

	if ok, why := s.LeaseMintClearance(ctx, req); ok {
		t.Fatalf("cleared with no gate wired (%q)", why)
	}
	if counted != 0 {
		t.Fatalf("%d start-up clearances with no gate wired counted as no majority", counted)
	}

	s.SetGate(fakeServerGate{quorum: health.QuorumNo, live: 1, needed: 2})
	if ok, why := s.LeaseMintClearance(ctx, req); ok {
		t.Fatalf("cleared with the quorum lost (%q)", why)
	}
	if counted != 1 {
		t.Fatalf("fixture: %d no-majority polls counted with the quorum lost, want 1", counted)
	}
}
