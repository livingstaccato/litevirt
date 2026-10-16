package grpcapi

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// leaseClaimNode is a voter-ready server that is the only member of an
// adopted voter generation, with one peer (node-c) answering the high-water
// read at term 0, so a mint at term 1 clears the read and reaches the claim.
// latched says whether lease_term_claim_v1 has durably latched.
func leaseClaimNode(t *testing.T, latched bool) *Server {
	t.Helper()
	ctx := context.Background()
	s := namedVoterServer(t)
	inc, err := s.db.VoterIncarnation(ctx)
	if err != nil {
		t.Fatal(err)
	}
	adoptTestGeneration(t, s, []corrosion.VoterMember{{Name: s.hostName, Incarnation: inc}})
	insertTestHost(t, ctx, s.db, s.hostName, "active")
	insertTestHost(t, ctx, s.db, "node-c", "active")
	s.db.MarkReplicaCaughtUpForTests("node-c")
	s.SetGate(fakeServerGate{quorum: health.QuorumYes, needed: 1, healthy: []string{"node-c"},
		durablyLatchedTok: map[string]bool{capabilities.LeaseTermClaimV1: latched}})
	s.peerClientOverride = fakePeers(map[string]int64{"node-c": 0})
	return s
}

func leaseClaimReq(s *Server, term int64) corrosion.LeaseMintRequest {
	return corrosion.LeaseMintRequest{Key: corrosion.LeaseKeyFailover, Term: term, Holder: s.hostName,
		Takeover: true, Now: clearanceNow}
}

// Once lease_term_claim_v1 has latched, a mint is cleared only by a decision
// of the voter generation naming this node, and that decision is recorded on
// the voters before the mint is.
//
// Mutation: skip claimLeaseTerm in LeaseMintClearance — the voter holds no
// decision and this goes red.
func TestLeaseMintClearance_ClaimsTheTermOnceLatched(t *testing.T) {
	ctx := context.Background()
	s := leaseClaimNode(t, true)
	if ok, why := s.LeaseMintClearance(ctx, leaseClaimReq(s, 1)); !ok {
		t.Fatalf("an uncontested claim was refused: %q", why)
	}
	st, found, err := s.db.ClaimState(ctx, corrosion.LeaseTermClaimKey(corrosion.LeaseKeyFailover, 1))
	if err != nil || !found || st.Value == nil || st.Value.LeaseTerm == nil || st.Value.LeaseTerm.Holder != s.hostName {
		t.Fatalf("no decision naming %s at the voter: %+v found=%v err=%v", s.hostName, st, found, err)
	}
}

// Before the latch, nothing is claimed: a node of an older build answers no
// lease-term claim, so asking would only stop takeovers for the length of a
// rolling upgrade. The high-water read clears, as it always did.
//
// Mutation: claim whatever the latch says — the voter holds a decision and
// this goes red.
func TestLeaseMintClearance_ClaimsNothingBeforeTheLatch(t *testing.T) {
	ctx := context.Background()
	s := leaseClaimNode(t, false)
	if ok, why := s.LeaseMintClearance(ctx, leaseClaimReq(s, 1)); !ok {
		t.Fatalf("an unlatched mint was refused: %q", why)
	}
	if _, found, _ := s.db.ClaimState(ctx, corrosion.LeaseTermClaimKey(corrosion.LeaseKeyFailover, 1)); found {
		t.Fatal("a lease-term claim was made before lease_term_claim_v1 latched")
	}
}

// A term already decided for another node is not cleared for this one, and
// the decision is handed to the corrosion client: the node then neither asks
// about that term again nor takes the lease over until the winner could have
// recorded it.
//
// Mutation: return true whatever the decided holder — this goes red.
func TestLeaseMintClearance_ATermDecidedForAnotherNodeIsRefused(t *testing.T) {
	ctx := context.Background()
	s := leaseClaimNode(t, true)
	k := corrosion.LeaseTermClaimKey(corrosion.LeaseKeyFailover, 1)
	signer, _, err := s.claimIdentity()
	if err != nil {
		t.Fatal(err)
	}
	other := corrosion.ClaimValue{LeaseTerm: &corrosion.LeaseTermValue{Key: corrosion.LeaseKeyFailover, Term: 1, Holder: "node-x"}}
	b := corrosion.Ballot{Round: 1, Coordinator: "node-x", Nonce: []byte{9}}
	if res, err := s.db.ClaimAccept(ctx, k, b, other, 1, signer, nil); err != nil || !res.Accepted {
		t.Fatalf("seed node-x's decision: %+v %v", res, err)
	}
	ok, why := s.LeaseMintClearance(ctx, leaseClaimReq(s, 1))
	if ok || !strings.Contains(why, "node-x") {
		t.Fatalf("cleared=%v (%q); want refused, naming node-x", ok, why)
	}
	// Handed on: AcquireLeaseWithTerm now waits rather than asking again.
	s.db.SetLeaseMintClearance(func(context.Context, corrosion.LeaseMintRequest) (bool, string) {
		t.Fatal("the clearance was asked again about a term decided for node-x")
		return false, ""
	})
	at, _ := time.Parse(time.RFC3339, clearanceNow)
	if held, _, err := corrosion.AcquireLeaseWithTerm(ctx, s.db, corrosion.LeaseKeyFailover, s.hostName, 30*time.Second, at); err != nil || held {
		t.Fatalf("held=%v err=%v within a TTL of learning node-x holds term 1", held, err)
	}
}

// With the latch formed but no member generation (genesis pending, or after
// `lv cluster voter reset`) there is no fixed majority, and every node is in
// that position together: the read alone clears, as before. But a node whose
// replica holds a member generation it has not ADOPTED may be the only node
// not claiming, so it records nothing until it has.
//
// Mutations: claim without an adopted generation — the first case goes red;
// ignore an unadopted member generation — the second goes red.
func TestLeaseTermClaimMode_WithoutAnAdoptedGeneration(t *testing.T) {
	ctx := context.Background()
	t.Run("none anywhere", func(t *testing.T) {
		s := namedVoterServer(t)
		s.SetGate(fakeServerGate{durablyLatchedTok: map[string]bool{capabilities.LeaseTermClaimV1: true}})
		if mode, _, why := s.leaseTermClaimMode(ctx); mode != leaseClaimOff {
			t.Fatalf("mode %d (%q) with no voter generation anywhere, want off", mode, why)
		}
	})
	t.Run("one this node has not adopted", func(t *testing.T) {
		s := namedVoterServer(t)
		s.SetGate(fakeServerGate{durablyLatchedTok: map[string]bool{capabilities.LeaseTermClaimV1: true}})
		s.db.SetVoterConfigGate(func() bool { return true })
		val := corrosion.VoterConfigValue{Generation: 1, Members: []corrosion.VoterMember{{Name: "node-x", Incarnation: "i"}},
			Change: corrosion.VoterChangeGenesis, CreatedBy: "test", CreatedAt: "test"}
		if err := corrosion.WriteVoterConfig(ctx, s.db, val, corrosion.ClaimCertificate{}); err != nil {
			t.Fatal(err)
		}
		mode, _, why := s.leaseTermClaimMode(ctx)
		if mode != leaseClaimClosed || !strings.Contains(why, "not adopted") {
			t.Fatalf("mode %d (%q) with an unadopted member generation, want closed", mode, why)
		}
	})
}

// lease_term_claim_v1 is mandatory, replication-gated and advertised whatever
// the node's config says: every claimant relies on every other claiming, and
// any replication recipient can hold a lease.
//
// Mutation: drop it from the mandatory set — tokenEnabled reports false and
// this goes red.
func TestAdvertise_LeaseTermClaimIsMandatoryAndUnconditional(t *testing.T) {
	tok := capabilities.LeaseTermClaimV1
	if !capabilities.Mandatory(tok) || !capabilities.ReplicationGated(tok) {
		t.Fatalf("%s: mandatory=%v replication-gated=%v, want both", tok,
			capabilities.Mandatory(tok), capabilities.ReplicationGated(tok))
	}
	if !slices.Contains(capabilities.All(), tok) {
		t.Fatalf("%s is not in All(): a node holding its marker would quarantine on its own build", tok)
	}
	s := testServer(t)
	if !s.tokenEnabled(tok) {
		t.Fatalf("%s is not enabled with no config at all", tok)
	}
	if !slices.Contains(s.advertisedCapabilities(), tok) {
		t.Fatalf("%s is not advertised", tok)
	}
}
