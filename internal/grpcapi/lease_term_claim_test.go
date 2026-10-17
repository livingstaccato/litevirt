package grpcapi

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/claims"
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

// The claim does not wait for this node's own latch: each node latches at its
// own moment, and a node minting unclaimed while its peers claim is the
// second holder they exclude.
//
// Mutation: claim only once latched (the 09116039 rule) — the voter holds no
// decision and this goes red.
func TestLeaseMintClearance_ClaimsBeforeItsOwnLatch(t *testing.T) {
	ctx := context.Background()
	s := leaseClaimNode(t, false)
	if ok, why := s.LeaseMintClearance(ctx, leaseClaimReq(s, 1)); !ok {
		t.Fatalf("an uncontested unlatched claim was refused: %q", why)
	}
	if _, found, _ := s.db.ClaimState(ctx, corrosion.LeaseTermClaimKey(corrosion.LeaseKeyFailover, 1)); !found {
		t.Fatal("no lease-term claim was made before this node's lease_term_claim_v1 latch formed")
	}
}

// The one fallback: before the latch, a majority of the voters that answered
// refuse the claim as an unknown claim type — older builds, which record
// terms unclaimed anyway. After the latch, never.
//
// Mutations: never fall back — the unlatched case goes red; fall back
// whatever the latch — the latched case goes red.
func TestLeaseMintClearance_FallsBackToTheReadOnlyOnOlderBuildsBeforeTheLatch(t *testing.T) {
	ctx := context.Background()
	for _, latched := range []bool{false, true} {
		s := leaseClaimNode(t, latched)
		// The only voter answers like a build without lease-term claims; it
		// still clears the read and records the term as an older build would.
		s.leaseClaimsAsOlderBuild.Store(true)
		key := corrosion.LeaseTermClaimKey(corrosion.LeaseKeyFailover, 1)
		cfg, err := corrosion.AdoptedVoterConfig(ctx, s.db)
		if err != nil {
			t.Fatal(err)
		}
		ok, why := s.claimLeaseTerm(ctx, cfg, leaseClaimReq(s, 1), time.Now())
		if ok != !latched {
			t.Fatalf("latched=%v: cleared=%v (%q); want the read-only fallback only before the latch", latched, ok, why)
		}
		if _, found, _ := s.db.ClaimState(ctx, key); found {
			t.Fatalf("latched=%v: the older-build voter recorded lease-term state", latched)
		}
	}
}

// A voter that does not answer is never read as an older build: with half
// the generation unreachable, no majority decides and nothing is recorded.
// The claim is counted, and once a TTL has passed without a majority the
// lease's ha.lease.claim_no_majority condition is raised; a decided claim
// resolves it.
//
// Mutations: fall back on an unreachable voter — this clears and goes red;
// never raise the condition — red; never resolve it — red.
func TestLeaseMintClearance_AnUnreachableVoterIsNoMajorityNotAFallback(t *testing.T) {
	ctx := context.Background()
	s := leaseClaimNode(t, false)
	inc, err := s.db.VoterIncarnation(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// Generation 2: this node and node-x, which nobody can reach.
	val := corrosion.VoterConfigValue{Generation: 2, Members: corrosion.SortMembers([]corrosion.VoterMember{
		{Name: s.hostName, Incarnation: inc}, {Name: "node-x", Incarnation: "x"}}),
		Change: corrosion.VoterChangeAdd("node-x"), CreatedBy: "test", CreatedAt: "test"}
	if err := corrosion.WriteVoterConfig(ctx, s.db, val, corrosion.ClaimCertificate{}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.RecordVoterAdoption(ctx, s.db, 2); err != nil {
		t.Fatal(err)
	}
	var counted []string
	s.SetLeaseClaimNoMajorityObserver(func(lease string) { counted = append(counted, lease) })
	req := leaseClaimReq(s, 1)
	req.TTL = 30 * time.Second
	if ok, why := s.LeaseMintClearance(ctx, req); ok || !strings.Contains(why, "no majority") {
		t.Fatalf("cleared=%v (%q) with one of two voters reachable; want no majority, no term", ok, why)
	}
	cond := func() (corrosion.HealthCondition, bool) {
		row, found, err := corrosion.GetHealthCondition(ctx, s.db, leaseClaimEvaluator, condLeaseClaimNoMajority,
			"cluster", corrosion.LeaseKeyFailover)
		if err != nil {
			t.Fatal(err)
		}
		return row, found && row.Lifecycle != corrosion.ConditionResolved
	}
	if _, raised := cond(); raised {
		t.Fatal("the condition was raised on the first claim without a majority, before a TTL had passed")
	}
	at, _ := time.Parse(time.RFC3339, clearanceNow)
	req.Now = at.Add(req.TTL + time.Second).Format(time.RFC3339)
	s.LeaseMintClearance(ctx, req)
	if row, raised := cond(); !raised || !strings.Contains(row.Evidence, "lv cluster voter") {
		t.Fatalf("no %s raised a TTL into the stall (row %+v)", condLeaseClaimNoMajority, row)
	}
	if len(counted) != 2 || counted[0] != corrosion.LeaseKeyFailover {
		t.Fatalf("no-majority claims counted %v, want two for %s", counted, corrosion.LeaseKeyFailover)
	}
	s.noteLeaseClaimDecided(ctx, corrosion.LeaseKeyFailover)
	if _, raised := cond(); raised {
		t.Fatal("a decided claim did not resolve the condition")
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

// The TTL a loser waits counts from when it LEARNED the decision — its
// classification instant plus the time its sweep and claim took — not from
// when it classified the lease: the winner may have classified, and started
// its own TTL, while the loser's clearance was still running.
//
// Mutation: note the decision at req.Now — the acquire 31 s later takes term 2
// and this goes red.
func TestLeaseMintClearance_TheLosersWaitCountsFromLearning(t *testing.T) {
	ctx := context.Background()
	s := leaseClaimNode(t, true)
	k := corrosion.LeaseTermClaimKey(corrosion.LeaseKeyFailover, 1)
	signer, _, err := s.claimIdentity()
	if err != nil {
		t.Fatal(err)
	}
	other := corrosion.ClaimValue{LeaseTerm: &corrosion.LeaseTermValue{Key: corrosion.LeaseKeyFailover, Term: 1, Holder: "node-x"}}
	if res, err := s.db.ClaimAccept(ctx, k, corrosion.Ballot{Round: 1, Coordinator: "node-x", Nonce: []byte{9}}, other, 1, signer, nil); err != nil || !res.Accepted {
		t.Fatalf("seed: %+v %v", res, err)
	}
	cfg, err := corrosion.AdoptedVoterConfig(ctx, s.db)
	if err != nil {
		t.Fatal(err)
	}
	// This node's clearance began 20 s before the decision came back.
	if ok, _ := s.claimLeaseTerm(ctx, cfg, leaseClaimReq(s, 1), time.Now().Add(-20*time.Second)); ok {
		t.Fatal("a term decided for node-x was cleared")
	}
	s.db.SetLeaseMintClearance(func(context.Context, corrosion.LeaseMintRequest) (bool, string) { return true, "" })
	at, _ := time.Parse(time.RFC3339, clearanceNow)
	if held, term, err := corrosion.AcquireLeaseWithTerm(ctx, s.db, corrosion.LeaseKeyFailover, s.hostName,
		30*time.Second, at.Add(31*time.Second)); err != nil || held {
		t.Fatalf("held=%v term=%d err=%v 31 s after classifying, 11 s after learning node-x holds term 1", held, term, err)
	}
}

// With the latch formed but no member generation (genesis pending, or after
// `lv cluster voter reset`) there is no fixed majority to decide with: the
// read alone clears, as before. But a node whose
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

// halfReachableNode is leaseClaimNode under generation 2 = {this node, node-x},
// with node-x unreachable: every claim finds one voter of two.
func halfReachableNode(t *testing.T) *Server {
	t.Helper()
	ctx := context.Background()
	s := leaseClaimNode(t, false)
	inc, err := s.db.VoterIncarnation(ctx)
	if err != nil {
		t.Fatal(err)
	}
	val := corrosion.VoterConfigValue{Generation: 2, Members: corrosion.SortMembers([]corrosion.VoterMember{
		{Name: s.hostName, Incarnation: inc}, {Name: "node-x", Incarnation: "x"}}),
		Change: corrosion.VoterChangeAdd("node-x"), CreatedBy: "test", CreatedAt: "test"}
	if err := corrosion.WriteVoterConfig(ctx, s.db, val, corrosion.ClaimCertificate{}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.RecordVoterAdoption(ctx, s.db, 2); err != nil {
		t.Fatal(err)
	}
	return s
}

// noMajorityRaised reports whether s's replica holds a raised
// ha.lease.claim_no_majority for the failover lease.
func noMajorityRaised(t *testing.T, s *Server) bool {
	t.Helper()
	row, found, err := corrosion.GetHealthCondition(context.Background(), s.db, leaseClaimEvaluator,
		condLeaseClaimNoMajority, "cluster", corrosion.LeaseKeyFailover)
	if err != nil {
		t.Fatal(err)
	}
	return found && row.Lifecycle != corrosion.ConditionResolved
}

// stallFor runs two no-majority claims on s, the second a TTL after the first,
// which raises the condition.
func stallFor(t *testing.T, s *Server) time.Time {
	t.Helper()
	ctx := context.Background()
	req := leaseClaimReq(s, 1)
	req.TTL = 30 * time.Second
	at, _ := time.Parse(time.RFC3339, clearanceNow)
	for _, now := range []time.Time{at, at.Add(req.TTL + time.Second)} {
		req.Now = now.Format(time.RFC3339)
		if ok, why := s.LeaseMintClearance(ctx, req); ok {
			t.Fatalf("cleared (%q) with one of two voters reachable", why)
		}
	}
	if !noMajorityRaised(t, s) {
		t.Fatal("fixture: the stall raised no condition")
	}
	return at.Add(req.TTL + time.Second)
}

// The fallback condition counts every member of the generation as a voter
// that could still accept unless it answered as an older build: unreachable
// voters, other refusals and promises never make the fallback easier.
//
// Mutations: r1's rule (a majority of those that ANSWERED refused as an older
// build) — the cut-off case falls back; count refusals rather than distinct
// members — the duplicate case falls back; drop the stale-generation guard —
// the stale-generation cases fall back. Each goes red.
func TestOlderBuildsBlockAMajority(t *testing.T) {
	unknown := func(v string) claims.Refusal {
		return claims.Refusal{Voter: v, Reason: corrosion.RefusalInvalidValue, Detail: olderBuildRefusal}
	}
	gone := func(v string) claims.Refusal { return claims.Refusal{Voter: v, Reason: claims.ReasonUnreachable} }
	stale := func(v, reason string) claims.Refusal { return claims.Refusal{Voter: v, Reason: reason, Detail: "x"} }
	for _, tc := range []struct {
		name     string
		voters   []string
		got      int
		refusals []claims.Refusal
		want     bool
	}{
		{"2 old, 2 new, all answering", []string{"o1", "o2", "v1", "v2"}, 2,
			[]claims.Refusal{unknown("o1"), unknown("o2")}, true},
		{"1 old, 2 new", []string{"o1", "v1", "v2"}, 2, []claims.Refusal{unknown("o1")}, false},
		{"3 old, 2 new", []string{"o1", "o2", "o3", "v1", "v2"}, 2,
			[]claims.Refusal{unknown("o1"), unknown("o2"), unknown("o3")}, true},
		{"2 old, 3 new, one new dead", []string{"o1", "o2", "v1", "v2", "v3"}, 2,
			[]claims.Refusal{unknown("o1"), unknown("o2"), gone("v3")}, false},
		{"2 old, 3 new, v1 cut off from v2 and v3", []string{"o1", "o2", "v1", "v2", "v3"}, 1,
			[]claims.Refusal{unknown("o1"), unknown("o2"), gone("v2"), gone("v3")}, false},
		{"older-build answers from non-members do not count", []string{"v1", "v2", "v3"}, 1,
			[]claims.Refusal{unknown("x1"), unknown("x2"), gone("v2"), gone("v3")}, false},
		{"one member answering twice counts once", []string{"o1", "v1", "v2"}, 0,
			[]claims.Refusal{unknown("o1"), unknown("o1"), gone("v1"), gone("v2")}, false},
		{"a non-member's older-build answer does not make up a blocking count", []string{"o1", "o2", "v1"}, 0,
			[]claims.Refusal{unknown("o1"), unknown("x9"), gone("o2"), gone("v1")}, false},
		{"a stale generation: the upgraded members answer wrong generation", []string{"o1", "o2", "v1", "v2"}, 0,
			[]claims.Refusal{unknown("o1"), unknown("o2"), stale("v1", corrosion.RefusalWrongGeneration),
				stale("v2", corrosion.RefusalWrongGeneration)}, false},
		{"a stale generation: a member answers sealed", []string{"o1", "o2", "v1", "v2"}, 1,
			[]claims.Refusal{unknown("o1"), unknown("o2"), stale("v2", corrosion.RefusalSealed)}, false},
		{"a stale generation: a member answers not a member", []string{"o1", "o2", "v1", "v2"}, 1,
			[]claims.Refusal{unknown("o1"), unknown("o2"), stale("v2", corrosion.RefusalNotMember)}, false},
	} {
		err := &claims.NoMajorityError{Phase: "prepare", Got: tc.got, Need: corrosion.MajorityOf(len(tc.voters)),
			Refusals: tc.refusals}
		if got := olderBuildsBlockAMajority(err, tc.voters, corrosion.MajorityOf(len(tc.voters))); got != tc.want {
			t.Errorf("%s: fallback=%v, want %v", tc.name, got, tc.want)
		}
	}
	accept := &claims.NoMajorityError{Phase: "accept", Refusals: []claims.Refusal{unknown("o1"), unknown("o2")}}
	if olderBuildsBlockAMajority(accept, []string{"o1", "o2", "v1"}, 2) {
		t.Error("an accept-phase failure fell back")
	}
}

// ha.lease.claim_no_majority resolves, and the stall start is forgotten, once
// the lease is held by anyone: this node seeing a live holder or renewing.
//
// Mutation: NoteLeaseLive resolves nothing — this goes red.
func TestLeaseClaimNoMajority_ResolvedByALiveHolder(t *testing.T) {
	s := halfReachableNode(t)
	stallFor(t, s)
	s.NoteLeaseLive(context.Background(), corrosion.LeaseKeyFailover)
	if noMajorityRaised(t, s) {
		t.Fatal("a live holder did not resolve the condition")
	}
}

// The older-build fallback records a term, so the lease is no longer stalled.
//
// Mutation: drop noteLeaseClaimDecided from the fallback — this goes red.
func TestLeaseClaimNoMajority_ResolvedByAFallback(t *testing.T) {
	ctx := context.Background()
	s := halfReachableNode(t)
	stallFor(t, s)
	// Now this node answers as an older build: of two voters one refuses the
	// type, and the other cannot make a majority alone.
	s.leaseClaimsAsOlderBuild.Store(true)
	cfg, err := corrosion.AdoptedVoterConfig(ctx, s.db)
	if err != nil {
		t.Fatal(err)
	}
	if ok, why := s.claimLeaseTerm(ctx, cfg, leaseClaimReq(s, 1), time.Now()); !ok {
		t.Fatalf("no fallback (%q)", why)
	}
	if noMajorityRaised(t, s) {
		t.Fatal("the fallback did not resolve the condition")
	}
}

// A stall start this node never ended itself — another node took the lease
// over, and this one only saw it held — must not raise the condition at once
// on a single failed claim weeks later.
//
// Mutation: NoteLeaseLive keeps the stall start — the late failure raises.
func TestLeaseClaimNoMajority_AStaleStallStartDoesNotRaise(t *testing.T) {
	ctx := context.Background()
	s := halfReachableNode(t)
	req := leaseClaimReq(s, 1)
	req.TTL = 30 * time.Second
	if ok, _ := s.LeaseMintClearance(ctx, req); ok {
		t.Fatal("fixture: cleared")
	}
	s.NoteLeaseLive(ctx, corrosion.LeaseKeyFailover) // another node holds it now
	at, _ := time.Parse(time.RFC3339, clearanceNow)
	req.Now = at.Add(7 * 24 * time.Hour).Format(time.RFC3339)
	if ok, _ := s.LeaseMintClearance(ctx, req); ok {
		t.Fatal("fixture: cleared")
	}
	if noMajorityRaised(t, s) {
		t.Fatal("one failed claim raised the condition from a stall start a week old")
	}
}

// claimPeer answers the high-water read at term 0 and a lease-term Prepare
// with a fixed refusal, as one voter of the generation would.
type claimPeer struct {
	fakeHighWaterPeer
	name, reason, detail string
}

func (p *claimPeer) PrepareRecoveryClaim(_ context.Context, req *pb.PrepareRecoveryClaimRequest, _ ...grpc.CallOption) (*pb.PrepareRecoveryClaimResponse, error) {
	return &pb.PrepareRecoveryClaimResponse{Voter: p.name, RefusalReason: p.reason, RefusalDetail: p.detail}, nil
}

// The review's mid-roll scenario. Generation 1 is {o1, o2, v1, v2}, o1 and o2
// on the previous build. `lv cluster voter rm o2` has decided generation 2 =
// {o1, v1, v2}, under which v1 and v2 are a majority and claim. A takeover by
// a node whose replica has not received generation 2 yet claims under 1: o1
// and o2 answer "unknown claim type" — an older build fails Validate before
// it checks the generation — and v1 and v2 answer wrong generation. Under
// generation 1 the older builds look like 2 of 4, which blocks a majority, so
// without the guard this node fell back and recorded the term on the read
// alone, while a node on generation 2 decided the same term for itself. It
// must record nothing.
//
// Mutation: drop the stale-generation guard — this node records term 1 and
// this goes red.
func TestLeaseMintClearance_AStaleGenerationDoesNotFallBack(t *testing.T) {
	ctx := context.Background()
	s := namedVoterServer(t)
	s.db.SetVoterConfigGate(func() bool { return true })
	members := []corrosion.VoterMember{{Name: "o1", Incarnation: "i"}, {Name: "o2", Incarnation: "i"},
		{Name: "v1", Incarnation: "i"}, {Name: "v2", Incarnation: "i"}}
	val := corrosion.VoterConfigValue{Generation: 1, Members: corrosion.SortMembers(members),
		Change: corrosion.VoterChangeGenesis, CreatedBy: "test", CreatedAt: "test"}
	if err := corrosion.WriteVoterConfig(ctx, s.db, val, corrosion.ClaimCertificate{}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.RecordVoterAdoption(ctx, s.db, 1); err != nil {
		t.Fatal(err)
	}
	insertTestHost(t, ctx, s.db, s.hostName, "active")
	for _, m := range members {
		insertTestHost(t, ctx, s.db, m.Name, "active")
	}
	s.db.MarkReplicaCaughtUpForTests("v1")
	s.SetGate(fakeServerGate{quorum: health.QuorumYes, needed: 3, healthy: []string{"o1", "o2", "v1", "v2"}})
	peers := map[string]*claimPeer{
		"o1": {name: "o1", reason: corrosion.RefusalInvalidValue, detail: olderBuildRefusal},
		"o2": {name: "o2", reason: corrosion.RefusalInvalidValue, detail: olderBuildRefusal},
		"v1": {name: "v1", reason: corrosion.RefusalWrongGeneration, detail: "v1 has adopted voter generation 2, not 1"},
		"v2": {name: "v2", reason: corrosion.RefusalWrongGeneration, detail: "v2 has adopted voter generation 2, not 1"},
	}
	s.peerClientOverride = func(_ context.Context, host string) (pb.LiteVirtClient, func(), error) {
		p, ok := peers[host]
		if !ok {
			return nil, nil, context.DeadlineExceeded
		}
		return p, func() {}, nil
	}
	s.db.SetLeaseMintClearance(s.LeaseMintClearance)
	at, _ := time.Parse(time.RFC3339, clearanceNow)
	held, term, err := corrosion.AcquireLeaseWithTerm(ctx, s.db, corrosion.LeaseKeyFailover, s.hostName, 30*time.Second, at)
	if err != nil {
		t.Fatal(err)
	}
	if held {
		t.Fatalf("a claimant on a superseded voter generation recorded term %d on the read alone, beside "+
			"the node deciding it under the new generation", term)
	}
	if newest, _ := corrosion.CurrentLeaseTerm(ctx, s.db, corrosion.LeaseKeyFailover); newest != 0 {
		t.Fatalf("term %d recorded", newest)
	}
}
