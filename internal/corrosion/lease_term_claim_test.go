package corrosion

import (
	"context"
	"testing"
	"time"
)

// Lease-term claims (capabilities.LeaseTermClaimV1): the claim key, its value,
// the voter's rules for it, and what a node does with a term it learned was
// decided for another node.

func leaseTermValue(key string, term int64, holder string) ClaimValue {
	return ClaimValue{LeaseTerm: &LeaseTermValue{Key: key, Term: term, Holder: holder}}
}

// A lease-term key names a lease-key-shaped name and a term of at least 1,
// never an attempt or an incarnation. A well-shaped name this build does not
// acquire is valid: a later build's voters claim terms of leases this one has
// never heard of, and this build must still keep and carry them.
//
// Mutations: accept any lease_term key — the malformed keys go red; require
// ValidLeaseKey — the later build's key goes red.
func TestLeaseTermClaimKey_Validate(t *testing.T) {
	for _, name := range []string{LeaseKeyFailover, "future_detector"} {
		if err := LeaseTermClaimKey(name, 3).Validate(); err != nil {
			t.Fatalf("lease-term key for %q: %v", name, err)
		}
	}
	for _, k := range []ClaimKey{
		LeaseTermClaimKey("not-a-lease", 3),
		LeaseTermClaimKey("", 3),
		LeaseTermClaimKey("Failover", 3),
		LeaseTermClaimKey(LeaseKeyFailover, 0),
		{TargetKind: ClaimKindLeaseTerm, TargetName: LeaseKeyFailover, OwnerEpoch: 3, Attempt: 1},
		{TargetKind: ClaimKindLeaseTerm, TargetName: LeaseKeyFailover, OwnerEpoch: 3, Incarnation: "i"},
	} {
		if err := k.Validate(); err == nil {
			t.Errorf("%+v validated", k)
		}
	}
	if !LeaseTermClaimKey(LeaseKeyFailover, 3).IsGenerationScoped() {
		t.Error("a lease-term key is not generation-scoped: a term decided under one generation could be decided again under the next")
	}
}

// A lease-term value digests in its own domain, over every field, and never
// alongside anything else.
func TestLeaseTermClaimValue_Digest(t *testing.T) {
	a := leaseTermValue(LeaseKeyFailover, 2, "node-a")
	da, err := a.Digest()
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range []ClaimValue{
		leaseTermValue(LeaseKeyFailover, 2, "node-b"),
		leaseTermValue(LeaseKeyFailover, 3, "node-a"),
		leaseTermValue(LeaseKeyRebalancer, 2, "node-a"),
	} {
		if db, _ := b.Digest(); db == da {
			t.Errorf("%+v digests like %+v", b.LeaseTerm, a.LeaseTerm)
		}
	}
	for name, mixed := range map[string]ClaimValue{
		"with a proof":       {LeaseTerm: a.LeaseTerm, Proof: &ActionProof{ID: "p"}},
		"with a source host": {LeaseTerm: a.LeaseTerm, SourceHost: "x"},
		"with a LUN":         {LeaseTerm: a.LeaseTerm, LUN: &LUNAllocation{LUN: "l"}},
		"with a config":      {LeaseTerm: a.LeaseTerm, Config: &VoterConfigValue{Generation: 1}},
	} {
		if _, err := mixed.Digest(); err == nil {
			t.Errorf("a lease-term value %s digested", name)
		}
	}
}

// A voter decides lease-term keys under its generation like workload keys,
// takes only a lease-term value for the key's lease and term, and never
// probes an owner for one: there is no owner, and a probe would make a
// takeover wait on the dead holder it is replacing.
//
// Mutation: let a lease-term key take a value for another term — this goes
// red.
func TestClaimVoter_LeaseTermKeys(t *testing.T) {
	ctx := context.Background()
	_, a, _, _ := threeVoters(t)
	k := LeaseTermClaimKey(LeaseKeyFailover, 2)
	if res, err := a.c.ClaimPrepare(ctx, k, testBallot(1, "b"), 1); err != nil || !res.Promised {
		t.Fatalf("prepare: %+v %v", res, err)
	}
	probed := false
	probe := func(context.Context, string) (bool, string) { probed = true; return true, "reached" }
	for name, v := range map[string]ClaimValue{
		"a proof":           workloadValue("p", "b", "ghost"),
		"another term":      leaseTermValue(LeaseKeyFailover, 3, "b"),
		"another lease":     leaseTermValue(LeaseKeyRebalancer, 2, "b"),
		"no holder":         leaseTermValue(LeaseKeyFailover, 2, ""),
		"a LUN, not a term": lunValue(2, "c", "web"),
	} {
		if res, err := a.c.ClaimAccept(ctx, k, testBallot(1, "b"), v, 1, a.signer, probe); err != nil || res.Accepted {
			t.Errorf("%s at a lease-term key was accepted: %+v %v", name, res, err)
		}
	}
	v := leaseTermValue(LeaseKeyFailover, 2, "b")
	res, err := a.c.ClaimAccept(ctx, k, testBallot(1, "b"), v, 1, a.signer, probe)
	if err != nil || !res.Accepted {
		t.Fatalf("accept: %+v %v", res, err)
	}
	if probed {
		t.Error("a voter probed an owner for a lease-term value")
	}
	// The voter now holds the value, and a later claimant learns it.
	pr, err := a.c.ClaimPrepare(ctx, k, testBallot(2, "c"), 1)
	if err != nil || !pr.Promised || pr.State.Value == nil || pr.State.Value.LeaseTerm == nil ||
		pr.State.Value.LeaseTerm.Holder != "b" {
		t.Fatalf("a later claimant did not learn the accepted holder: %+v %v", pr, err)
	}
}

// Two claimants for one term at the SAME round: the voter's ballot order
// makes the lower-sorting name the higher ballot, so whichever reaches the
// voter first, the voter ends up promised to the same one — the property that
// stops two aligned claimants from duelling forever.
func TestClaimVoter_LeaseTermTieAtOneRoundGoesToTheLowerName(t *testing.T) {
	ctx := context.Background()
	for _, order := range [][2]string{{"node-b", "node-c"}, {"node-c", "node-b"}} {
		_, a, _, _ := threeVoters(t)
		k := LeaseTermClaimKey(LeaseKeyDualRun, 7)
		for _, who := range order {
			if _, err := a.c.ClaimPrepare(ctx, k, testBallot(1, who), 1); err != nil {
				t.Fatal(err)
			}
		}
		st, _, err := a.c.ClaimState(ctx, k)
		if err != nil {
			t.Fatal(err)
		}
		if st.Promised.Coordinator != "node-b" {
			t.Fatalf("prepares in order %v left the voter promised to %s, want node-b", order, st.Promised.Coordinator)
		}
		// node-c's accept at its own round-1 ballot is now refused.
		res, _ := a.c.ClaimAccept(ctx, k, testBallot(1, "node-c"), leaseTermValue(LeaseKeyDualRun, 7, "node-c"), 1, a.signer, unreachable)
		if res.Accepted || res.Refusal != RefusalBallotStale {
			t.Fatalf("order %v: node-c's accept below node-b's promise: %+v", order, res)
		}
	}
}

// A lease-term decision survives a change of voter generation, so a term
// decided under one generation is not decided again for someone else under
// the next.
//
// Mutation: leave lease_term keys out of ClaimStatesForImport — this goes red.
func TestImportClaimsAndAdopt_CarriesLeaseTerms(t *testing.T) {
	ctx := context.Background()
	_, a, b, c := threeVoters(t)
	k := LeaseTermClaimKey(LeaseKeyFailover, 4)
	v := leaseTermValue(LeaseKeyFailover, 4, "a")
	for _, x := range []*claimTestVoter{a, b} {
		if res, _ := x.c.ClaimAccept(ctx, k, testBallot(2, "a"), v, 1, x.signer, unreachable); !res.Accepted {
			t.Fatal(res)
		}
	}
	var states []ClaimVoterState
	for _, x := range []*claimTestVoter{a, b} {
		src, err := x.c.ClaimStatesForImport(ctx, 1)
		if err != nil {
			t.Fatal(err)
		}
		states = append(states, src.States...)
	}
	next := VoterConfigValue{Generation: 2, Members: membersOf(b, c), Change: VoterChangeRm("a"), CreatedBy: "b", CreatedAt: "t"}
	if err := WriteVoterConfig(ctx, c.c, next, ClaimCertificate{}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.c.ImportClaimsAndAdopt(ctx, 2, []string{"a", "b"}, states); err != nil {
		t.Fatal(err)
	}
	res, _ := c.c.ClaimPrepare(ctx, k, testBallot(5, "z"), 2)
	if !res.Promised || res.State.Value == nil || res.State.Value.LeaseTerm == nil || res.State.Value.LeaseTerm.Holder != "a" {
		t.Fatalf("the decided term did not survive the reconfiguration: %+v", res)
	}
}

// A term this node learned was decided for another node is that node's lease
// for one TTL from the moment it was learned: no mint, and the clearance is
// not even asked, while its holder may be recording and acting under it.
// After that the next mint allocates ABOVE the decided term — a decided term
// whose holder never recorded it would otherwise be asked about, and learned
// again, forever.
//
// Mutation: drop the wait in decidedElsewhere — the second acquire mints and
// goes red; drop the move above the decided term — the third asks about term
// 1 again and goes red.
func TestAcquireLeaseWithTerm_ATermDecidedForAnotherNodeIsItsLeaseForATTL(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	const ttl = 30 * time.Second
	var asked []int64
	c.SetLeaseMintClearance(func(_ context.Context, req LeaseMintRequest) (bool, string) {
		asked = append(asked, req.Term)
		if req.Term == 1 {
			// The claim for term 1 decided host-b.
			at, _ := time.Parse(time.RFC3339, req.Now)
			c.NoteLeaseTermDecided(req.Key, req.Term, "host-b", at)
			return false, "term 1 was decided for host-b"
		}
		return true, ""
	})

	if held, _, err := AcquireLeaseWithTerm(ctx, c, LeaseKeyFailover, "host-a", ttl, leaseTestNow); err != nil || held {
		t.Fatalf("the losing claimant: held=%v err=%v, want not held", held, err)
	}
	if held, _, err := AcquireLeaseWithTerm(ctx, c, LeaseKeyFailover, "host-a", ttl, leaseTestNow.Add(ttl-time.Second)); err != nil || held {
		t.Fatalf("within a TTL of learning host-b holds term 1: held=%v err=%v, want not held", held, err)
	}
	if len(asked) != 1 {
		t.Fatalf("clearance asked about %v; within the TTL a decided term must not be claimed again", asked)
	}
	held, term, err := AcquireLeaseWithTerm(ctx, c, LeaseKeyFailover, "host-a", ttl, leaseTestNow.Add(ttl+time.Second))
	if err != nil || !held || term != 2 {
		t.Fatalf("a TTL after learning, host-b never recorded its term: held=%v term=%d err=%v, want term 2", held, term, err)
	}
	if want := []int64{1, 2}; len(asked) != 2 || asked[1] != 2 {
		t.Fatalf("clearance asked about %v, want %v", asked, want)
	}
	if h, ok, _ := LeaseTermHolder(ctx, c, LeaseKeyFailover, 1); ok {
		t.Fatalf("this node recorded term 1 for %s; it was another node's", h)
	}
}

// A decision naming this node, or one for a term below what it would claim,
// changes nothing.
func TestDecidedElsewhere_OnlyAnotherNodesCurrentTerm(t *testing.T) {
	c := testClient(t)
	now := leaseTestNow
	c.NoteLeaseTermDecided(LeaseKeyFailover, 3, "host-a", now)
	if next, wait := c.decidedElsewhere(LeaseKeyFailover, "host-a", 3, now, time.Minute); wait || next != 3 {
		t.Errorf("our own decided term: next=%d wait=%v, want 3 and no wait", next, wait)
	}
	c.NoteLeaseTermDecided(LeaseKeyFailover, 3, "host-b", now)
	if next, wait := c.decidedElsewhere(LeaseKeyFailover, "host-a", 4, now, time.Minute); wait || next != 4 {
		t.Errorf("a decided term below the one claimed: next=%d wait=%v, want 4 and no wait", next, wait)
	}
	c.NoteLeaseTermDecided(LeaseKeyFailover, 2, "host-c", now)
	if next, wait := c.decidedElsewhere(LeaseKeyFailover, "host-a", 3, now, time.Minute); !wait || next != 3 {
		t.Errorf("an older decision replaced a newer one: next=%d wait=%v", next, wait)
	}
}

// A voter-generation import that carries a lease-term decision for a lease
// this build does not know — a later build's, mid-roll — succeeds and keeps
// it. Failing the import would leave the generation sealed: no lease
// takeover and no recovery until every voter ran the later build.
//
// Mutation: require ValidLeaseKey in Validate — the import fails.
func TestImportClaimsAndAdopt_KeepsAnUnknownLeaseKey(t *testing.T) {
	ctx := context.Background()
	_, a, b, c := threeVoters(t)
	k := LeaseTermClaimKey("future_detector", 9)
	v := leaseTermValue("future_detector", 9, "a")
	for _, x := range []*claimTestVoter{a, b} {
		if res, err := x.c.ClaimAccept(ctx, k, testBallot(1, "a"), v, 1, x.signer, unreachable); err != nil || !res.Accepted {
			t.Fatalf("%s accepting a later build's lease key: %+v %v", x.name, res, err)
		}
	}
	var states []ClaimVoterState
	for _, x := range []*claimTestVoter{a, b} {
		src, err := x.c.ClaimStatesForImport(ctx, 1)
		if err != nil {
			t.Fatal(err)
		}
		states = append(states, src.States...)
	}
	next := VoterConfigValue{Generation: 2, Members: membersOf(b, c), Change: VoterChangeRm("a"), CreatedBy: "b", CreatedAt: "t"}
	if err := WriteVoterConfig(ctx, c.c, next, ClaimCertificate{}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.c.ImportClaimsAndAdopt(ctx, 2, []string{"a", "b"}, states); err != nil {
		t.Fatalf("an import carrying an unknown lease key failed: %v", err)
	}
	st, found, err := c.c.ClaimState(ctx, k)
	if err != nil || !found || st.Value == nil || st.Value.LeaseTerm == nil || st.Value.LeaseTerm.Holder != "a" {
		t.Fatalf("the decision was not carried: %+v found=%v err=%v", st, found, err)
	}
}

// A voter keeps lease-term claim state only for terms within
// leaseTermClaimRetention of the newest term its own ledger has recorded, so
// the table does not grow a row per takeover forever; a decided term above
// that, recorded or not, is kept.
//
// Mutation: drop pruneLeaseTermClaimsTx's call — the old row survives.
func TestClaimVoter_PrunesLeaseTermsWellBelowTheLedger(t *testing.T) {
	ctx := context.Background()
	_, a, _, _ := threeVoters(t)
	accept := func(term int64) {
		t.Helper()
		k := LeaseTermClaimKey(LeaseKeyFailover, term)
		if res, err := a.c.ClaimAccept(ctx, k, testBallot(1, "b"), leaseTermValue(LeaseKeyFailover, term, "b"), 1, a.signer, unreachable); err != nil || !res.Accepted {
			t.Fatalf("accept term %d: %+v %v", term, res, err)
		}
	}
	accept(2)
	putLeaseTerm(t, a.c, LeaseKeyFailover, 20, "b", "2026-09-08T12:00:00Z", a.c.NowTS())
	accept(21)
	if _, found, _ := a.c.ClaimState(ctx, LeaseTermClaimKey(LeaseKeyFailover, 2)); found {
		t.Error("term 2's claim state survived a recorded term 20")
	}
	if _, found, _ := a.c.ClaimState(ctx, LeaseTermClaimKey(LeaseKeyFailover, 21)); !found {
		t.Error("the current term's claim state was pruned")
	}
	accept(13) // within the retention margin of the recorded term 20
	if _, found, _ := a.c.ClaimState(ctx, LeaseTermClaimKey(LeaseKeyFailover, 13)); !found {
		t.Error("a term within the retention margin was pruned")
	}
}
