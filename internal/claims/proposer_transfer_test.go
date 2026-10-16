package claims

import (
	"context"
	"fmt"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// Complete promise transfer preserves one decision across two certified
// changes. The intermediate floors also check promise-only export independently.
// Only message delivery is scheduled.
func TestProposer_TransferPreservesOneDecision(t *testing.T) {
	for _, bFirst := range []bool{false, true} {
		t.Run(fmt.Sprintf("B_imports_first=%t", bFirst), func(t *testing.T) {
			testTransferPreservesOneDecision(t, bFirst)
		})
	}
}

func testTransferPreservesOneDecision(t *testing.T, bFirst bool) {
	ctx := context.Background()
	tr, vs, verifier := newMemClusterWithMembers(t, 3, "a", "b", "c", "d")
	members := func(ns ...string) []corrosion.VoterMember {
		var ms []corrosion.VoterMember
		for _, n := range ns {
			v := tr.voters[n]
			ms = append(ms, corrosion.VoterMember{Name: n, Incarnation: v.inc})
		}
		return corrosion.SortMembers(ms)
	}
	key := corrosion.ClaimKey{TargetKind: corrosion.ClaimKindVM, TargetName: "transfer", OwnerEpoch: 1}
	low, high := valueFor(key, "low"), valueFor(key, "high")
	prep := func(ns []string, b corrosion.Ballot) {
		for _, n := range ns {
			r, e := tr.Prepare(ctx, n, key, b, 1, nil)
			if e != nil || !r.Promised {
				t.Fatalf("prepare %s: %+v %v", n, r, e)
			}
		}
	}
	accept := func(n string, b corrosion.Ballot, v corrosion.ClaimValue) {
		r, e := tr.Accept(ctx, n, key, b, v, 1)
		if e != nil || !r.Accepted {
			t.Fatalf("accept %s: %+v %v", n, r, e)
		}
	}
	lo := corrosion.Ballot{Round: 1, Coordinator: "c", Nonce: []byte{1}}
	hi := corrosion.Ballot{Round: 10, Coordinator: "a", Nonce: []byte{1}}
	prep([]string{"b", "c"}, lo)
	accept("c", lo, low)
	prep([]string{"a", "b"}, hi)
	accept("a", hi, high)
	var prev *corrosion.VoterConfig
	var err error
	prev, err = corrosion.AdoptedVoterConfig(ctx, vs[0].db)
	if err != nil {
		t.Fatal(err)
	}
	change := func(gen int64, ns []string, op string, reachable []string) Outcome {
		for n := range tr.voters {
			tr.down[n] = true
		}
		for _, n := range reachable {
			tr.down[n] = false
		}
		val := corrosion.VoterConfigValue{Generation: gen + 1, Members: members(ns...), Change: op, CreatedBy: "a", CreatedAt: "transfer"}
		spec := Spec{Key: corrosion.ClaimKey{TargetKind: corrosion.ClaimKindVoterConfig, OwnerEpoch: gen}, Generation: gen, Voters: prev.Names(), PrepareQuorum: corrosion.MajorityOf(len(prev.Members)), Propose: func(map[string]corrosion.PrepareResult) (corrosion.ClaimValue, error) {
			return corrosion.ClaimValue{Config: &val}, nil
		}}
		o, e := NewProposer("a", tr).Decide(ctx, spec)
		if e != nil {
			t.Fatal(e)
		}
		want, e := corrosion.ExpectedVoterConfigCertificate(prev, *o.Value.Config)
		if e != nil {
			t.Fatal(e)
		}
		if e = verifier.Verify(o.Certificate, want); e != nil {
			t.Fatal(e)
		}
		for _, v := range vs {
			if e = corrosion.WriteVoterConfig(ctx, v.db, *o.Value.Config, o.Certificate); e != nil {
				t.Fatal(e)
			}
		}
		t.Logf("certified generation %d: %v", gen+1, ns)
		return o
	}
	sawPromiseOnly := false
	importTo := func(n string, gen int64, srcs ...string) {
		var states []corrosion.ClaimVoterState
		old, err := corrosion.GetVoterConfig(ctx, tr.voters[n].db, gen-1)
		if err != nil {
			t.Fatal(err)
		}
		if len(srcs) < corrosion.MajorityOf(len(old.Members)) {
			t.Fatal("nonquorum import")
		}
		for _, src := range srcs {
			if _, ok := old.Member(src); !ok {
				t.Fatal("nonmember import")
			}
			s, e := tr.voters[src].db.ClaimStatesForImport(ctx, gen-1)
			if e != nil || !s.Frozen {
				t.Fatalf("unfrozen %s: %+v %v", src, s, e)
			}
			if !bFirst && gen == 2 && (n == "c" || n == "d") && src == "b" {
				for _, state := range s.States {
					if state.Key == key && state.Accepted.IsZero() && state.Promised.Equal(hi) {
						sawPromiseOnly = true
					}
				}
			}
			states = append(states, s.States...)
		}
		if _, e := tr.voters[n].db.ImportClaimsAndAdopt(ctx, gen, srcs, states); e != nil {
			t.Fatal(e)
		}
		st, _, _ := tr.voters[n].db.ClaimState(ctx, key)
		t.Logf("%s adopts %d from %v: accepted %s, promise %s", n, gen, srcs, st.Accepted, st.Promised)
	}
	c2 := change(1, []string{"a", "b", "c", "d"}, corrosion.VoterChangeAdd("d"), []string{"a", "b", "c"})
	// All three old voters accepted the certified change and are sealed.
	importTo("a", 2, "a", "b")
	// With B last, C and D must receive B's promise-only state. With B
	// first, its snapshot carries both the low acceptance and high promise,
	// independently exercising the maximum-promise merge.
	if bFirst {
		importTo("b", 2, "b", "c")
	}
	importTo("c", 2, "b", "c")
	importTo("d", 2, "b", "c")
	var earlyPromises []corrosion.Ballot
	for _, n := range []string{"c", "d"} {
		st, found, err := tr.voters[n].db.ClaimState(ctx, key)
		if err != nil || !found {
			t.Fatalf("early state %s: found=%t err=%v", n, found, err)
		}
		earlyPromises = append(earlyPromises, st.Promised)
	}
	if !bFirst {
		importTo("b", 2, "b", "c")
	}
	prev = &corrosion.VoterConfig{VoterConfigValue: *c2.Value.Config}
	c3 := change(2, []string{"b", "c", "d"}, corrosion.VoterChangeRm("a"), []string{"b", "c", "d"})
	importTo("c", 3, "b", "c", "d")
	importTo("d", 3, "b", "c", "d")
	decide := func(reachable []string, start uint64) Outcome {
		for n := range tr.voters {
			tr.down[n] = true
		}
		for _, n := range reachable {
			tr.down[n] = false
		}
		spec := Spec{Key: key, Generation: 3, Voters: []string{"b", "c", "d"}, PrepareQuorum: 2, StartRound: start, Propose: func(map[string]corrosion.PrepareResult) (corrosion.ClaimValue, error) { return low, nil }}
		o, e := NewProposer("c", tr).Decide(ctx, spec)
		if e != nil {
			t.Fatal(e)
		}
		if e = verifier.Verify(o.Certificate, corrosion.CertExpectation{Key: key, ValueDigest: o.Digest, ConfigGeneration: 3, Electorate: c3.Value.Config.Members, Quorum: 2}); e != nil {
			t.Fatal(e)
		}
		t.Logf("verified generation-3 decision: dest=%s ballot=%s voters=%v", o.Value.Proof.DestHost, o.Certificate.Ballot, reachable)
		return o
	}
	first := decide([]string{"c", "d"}, 2)
	// A learns/accepts the SAME certified config while still at generation 2.
	tr.down["a"] = false
	r, e := tr.Accept(ctx, "a", c3.Certificate.Key, c3.Certificate.Ballot, c3.Value, 2)
	if e != nil || !r.Accepted {
		t.Fatalf("late config seal A: %+v %v", r, e)
	}
	importTo("b", 3, "a", "b", "c")
	second := decide([]string{"b", "c"}, 11)
	if first.Digest != second.Digest {
		t.Fatalf("SAFETY VIOLATION: two verified quorum certificates at same key and generation: %s versus %s", first.Value.Proof.DestHost, second.Value.Proof.DestHost)
	}
	if corrosion.CompareBallots(first.Certificate.Ballot, hi) <= 0 {
		t.Fatalf("new decision %s did not exceed transferred promise %s", first.Certificate.Ballot, hi)
	}
	for _, promise := range earlyPromises {
		if corrosion.CompareBallots(promise, hi) < 0 {
			t.Fatalf("generation-2 import lost high promise: %s < %s", promise, hi)
		}
	}
	if !bFirst && !sawPromiseOnly {
		t.Fatal("C,D did not receive B's promise-only snapshot before B's adoption")
	}
}
