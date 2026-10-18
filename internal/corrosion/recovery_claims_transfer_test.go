package corrosion

import (
	"context"
	"reflect"
	"testing"
)

// Filtering accepted_round loses these promises, including the scoped seals.
func TestClaimTransfer_ExportsPromiseOnly(t *testing.T) {
	ctx := context.Background()
	_, a, _, _ := threeVoters(t)
	recordLUNUseForTest(t, a)
	keys := []ClaimKey{workloadKey(), scopedKey("inc"), lunKey(0),
		{TargetKind: ClaimKindContainer, TargetName: "ct", OwnerEpoch: 1},
		{TargetKind: ClaimKindContainer, TargetName: "ct", OwnerEpoch: 1, Incarnation: "inc"}}
	for _, k := range keys {
		r, err := a.c.ClaimPrepare(ctx, k, testBallot(10, "x"), 1)
		if err != nil || !r.Promised {
			t.Fatalf("prepare %s: %+v %v", k, r, err)
		}
	}
	next := VoterConfigValue{Generation: 2, Members: membersOf(a), Change: VoterChangeGenesis, CreatedBy: "t", CreatedAt: "t"}
	if err := WriteVoterConfig(ctx, a.c, next, ClaimCertificate{}); err != nil {
		t.Fatal(err)
	}
	if err := RecordVoterAdoption(ctx, a.c, 2); err != nil {
		t.Fatal(err)
	}
	src, err := a.c.ClaimStatesForImport(ctx, 1)
	if err != nil || !src.Frozen {
		t.Fatalf("snapshot: %+v %v", src, err)
	}
	if len(src.States) != len(keys) {
		t.Fatalf("exported %d promise-only keys, want %d", len(src.States), len(keys))
	}
	seen := map[ClaimKey]bool{}
	for _, s := range src.States {
		seen[s.Key] = true
		if !s.Promised.Equal(testBallot(10, "x")) || !s.Accepted.IsZero() || s.Value != nil || s.ValueDigest != "" {
			t.Fatalf("promise changed: %+v", s)
		}
	}
	for _, k := range keys {
		if !seen[k] {
			t.Errorf("missing key %s", k)
		}
	}
}

// The highest promise and highest accepted value need not be the same row.
func TestClaimTransfer_MergesPromisesAndAcceptedIndependently(t *testing.T) {
	for _, tc := range []struct {
		name  string
		k     ClaimKey
		value ClaimValue
	}{
		{"legacy", workloadKey(), workloadValue("p", "b", "ghost")},
		{"incarnation", scopedKey("inc"), workloadValue("p", "b", "ghost")},
		{"LUN", lunKey(0), lunValue(0, "claim", "vm")},
	} {
		for _, separate := range []bool{false, true} {
			t.Run(tc.name+map[bool]string{false: "/accepted-row", true: "/promise-only-row"}[separate], func(t *testing.T) {
				ctx := context.Background()
				_, a, b, c := threeVoters(t)
				next := VoterConfigValue{Generation: 2, Members: membersOf(a, b, c), Change: VoterChangeGenesis, CreatedBy: "t", CreatedAt: "t"}
				if err := WriteVoterConfig(ctx, c.c, next, ClaimCertificate{}); err != nil {
					t.Fatal(err)
				}
				accepted := ClaimVoterState{Key: tc.k, Promised: testBallot(20, "x"), Accepted: testBallot(3, "x"), Value: &tc.value, ValueDigest: tc.value.MustDigest()}
				states := []ClaimVoterState{accepted}
				if separate {
					states[0].Promised = testBallot(3, "x")
					states = append(states, ClaimVoterState{Key: tc.k, Promised: testBallot(20, "x")})
				}
				if n, err := c.c.ImportClaimsAndAdopt(ctx, 2, []string{"a", "b"}, states); err != nil || n != 1 {
					t.Fatalf("import: %d %v", n, err)
				}
				st, found, err := c.c.ClaimState(ctx, tc.k)
				if err != nil || !found || !st.Promised.Equal(testBallot(20, "x")) || !st.Accepted.Equal(testBallot(3, "x")) || st.ValueDigest != accepted.ValueDigest || !reflect.DeepEqual(st.Value, &tc.value) || st.Accept != nil {
					t.Fatalf("merged: %+v found=%t err=%v", st, found, err)
				}
				before := st
				if n, err := c.c.ImportClaimsAndAdopt(ctx, 2, []string{"a", "b"}, []ClaimVoterState{{Key: tc.k, Promised: testBallot(99, "x")}}); err != nil || n != 0 {
					t.Fatalf("idempotent import: %d %v", n, err)
				}
				after, _, err := c.c.ClaimState(ctx, tc.k)
				if err != nil || !reflect.DeepEqual(before, after) {
					t.Fatalf("repeat adoption changed state: %+v %v", after, err)
				}
			})
		}
	}
}

func TestClaimTransfer_PreservesLocalState(t *testing.T) {
	ctx := context.Background()
	_, a, b, c := threeVoters(t)
	k := workloadKey()
	local := workloadValue("local", "a", "ghost")
	if r, err := c.c.ClaimAccept(ctx, k, testBallot(5, "x"), local, 1, c.signer, unreachable); err != nil || !r.Accepted {
		t.Fatalf("accept: %+v %v", r, err)
	}
	if r, err := c.c.ClaimPrepare(ctx, k, testBallot(30, "x"), 1); err != nil || !r.Promised {
		t.Fatalf("prepare: %+v %v", r, err)
	}
	before, _, _ := c.c.ClaimState(ctx, k)
	next := VoterConfigValue{Generation: 2, Members: membersOf(a, b, c), Change: VoterChangeGenesis, CreatedBy: "t", CreatedAt: "t"}
	if err := WriteVoterConfig(ctx, c.c, next, ClaimCertificate{}); err != nil {
		t.Fatal(err)
	}
	remote := workloadValue("remote", "b", "ghost")
	states := []ClaimVoterState{{Key: k, Promised: testBallot(20, "x"), Accepted: testBallot(3, "x"), Value: &remote, ValueDigest: remote.MustDigest()}}
	if _, err := c.c.ImportClaimsAndAdopt(ctx, 2, []string{"a", "b"}, states); err != nil {
		t.Fatal(err)
	}
	after, _, err := c.c.ClaimState(ctx, k)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("local state changed: before=%+v after=%+v err=%v", before, after, err)
	}
}

func TestClaimTransfer_PersistsPromiseOnlyAcrossReopen(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	open := func() *Client {
		c, err := NewLocalClient(dir, "a")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		if err := InitSchema(ctx, c); err != nil {
			t.Fatal(err)
		}
		return c
	}
	c := open()
	c.SetVoterConfigGate(func() bool { return true })
	inc, err := c.VoterIncarnation(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, gen := range []int64{1, 2} {
		cfg := VoterConfigValue{Generation: gen, Members: []VoterMember{{Name: "a", Incarnation: inc}}, Change: VoterChangeGenesis, CreatedBy: "t", CreatedAt: "t"}
		if err := WriteVoterConfig(ctx, c, cfg, ClaimCertificate{}); err != nil {
			t.Fatal(err)
		}
	}
	if err := RecordVoterAdoption(ctx, c, 1); err != nil {
		t.Fatal(err)
	}
	keys := []ClaimKey{workloadKey(), scopedKey("inc"), lunKey(0)}
	var states []ClaimVoterState
	for _, k := range keys {
		states = append(states, ClaimVoterState{Key: k, Promised: testBallot(10, "x")})
	}
	if n, err := c.ImportClaimsAndAdopt(ctx, 2, []string{"b", "c"}, states); err != nil || n != 3 {
		t.Fatalf("import: %d %v", n, err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	c = open()
	if g, err := AdoptedVoterGeneration(ctx, c); err != nil || g != 2 {
		t.Fatalf("adoption after reopen: %d %v", g, err)
	}
	for _, k := range keys {
		st, found, err := c.ClaimState(ctx, k)
		if err != nil || !found || !st.Promised.Equal(testBallot(10, "x")) || !st.Accepted.IsZero() {
			t.Fatalf("reopened %s: %+v %t %v", k, st, found, err)
		}
	}
}

func TestClaimTransfer_RejectsMalformedAcceptedState(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*ClaimVoterState)
	}{
		{"missing-value", func(s *ClaimVoterState) { s.Value = nil }},
		{"invalid-value", func(s *ClaimVoterState) { s.Value = &ClaimValue{} }},
		{"wrong-digest", func(s *ClaimVoterState) { s.ValueDigest = "wrong" }},
		{"missing-acceptance", func(s *ClaimVoterState) { s.Accepted = Ballot{} }},
		{"incomplete-proof", func(s *ClaimVoterState) { s.Value.Proof.DestHost = ""; s.ValueDigest = s.Value.MustDigest() }},
		{"wrong-key", func(s *ClaimVoterState) { s.Key.TargetName = "different" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			_, _, _, c := threeVoters(t)
			v := workloadValue("p", "b", "ghost")
			s := ClaimVoterState{Key: workloadKey(), Promised: testBallot(10, "x"), Accepted: testBallot(3, "x"), Value: &v, ValueDigest: v.MustDigest()}
			tc.mutate(&s)
			if _, err := c.c.ImportClaimsAndAdopt(ctx, 2, []string{"a", "b"}, []ClaimVoterState{s}); err == nil {
				t.Fatal("malformed accepted state silently adopted")
			}
			if g, err := AdoptedVoterGeneration(ctx, c.c); err != nil || g != 1 {
				t.Fatalf("failed import adopted: %d %v", g, err)
			}
			if st, found, err := c.c.ClaimState(ctx, s.Key); err != nil || found {
				t.Fatalf("failed import persisted: %+v %t %v", st, found, err)
			}
		})
	}
}

// A failed adoption commit must also roll back the imported promise.
func TestClaimTransfer_AdoptionFailureRollsBackState(t *testing.T) {
	ctx := context.Background()
	_, _, _, c := threeVoters(t)
	if _, err := c.c.db.ExecContext(ctx, `CREATE TRIGGER fail_adoption BEFORE INSERT ON local_voter_adoption BEGIN SELECT RAISE(ABORT, 'adoption failed'); END`); err != nil {
		t.Fatal(err)
	}
	s := ClaimVoterState{Key: workloadKey(), Promised: testBallot(10, "x")}
	if _, err := c.c.ImportClaimsAndAdopt(ctx, 2, []string{"a", "b"}, []ClaimVoterState{s}); err == nil {
		t.Fatal("adoption unexpectedly committed")
	}
	if st, found, err := c.c.ClaimState(ctx, s.Key); err != nil || found {
		t.Fatalf("failed adoption left promise: %+v %t %v", st, found, err)
	}
	if g, err := AdoptedVoterGeneration(ctx, c.c); err != nil || g != 1 {
		t.Fatalf("failed adoption advanced generation: %d %v", g, err)
	}
}

func TestClaimTransfer_RejectsConflictingAcceptedValues(t *testing.T) {
	for _, local := range []bool{false, true} {
		t.Run(map[bool]string{false: "sources", true: "local"}[local], func(t *testing.T) {
			ctx := context.Background()
			_, _, _, c := threeVoters(t)
			one, two := workloadValue("one", "a", "ghost"), workloadValue("two", "b", "ghost")
			k, b := workloadKey(), testBallot(3, "x")
			states := []ClaimVoterState{{Key: k, Promised: b, Accepted: b, Value: &one, ValueDigest: one.MustDigest()}, {Key: k, Promised: b, Accepted: b, Value: &two, ValueDigest: two.MustDigest()}}
			if local {
				if r, err := c.c.ClaimAccept(ctx, k, b, one, 1, c.signer, unreachable); err != nil || !r.Accepted {
					t.Fatalf("local accept: %+v %v", r, err)
				}
				states = states[1:]
			}
			if _, err := c.c.ImportClaimsAndAdopt(ctx, 2, []string{"a", "b"}, states); err == nil {
				t.Fatal("conflicting accepted values silently adopted")
			}
			if g, err := AdoptedVoterGeneration(ctx, c.c); err != nil || g != 1 {
				t.Fatalf("conflicting import adopted: %d %v", g, err)
			}
		})
	}
}

// Even an omitted remote promise cannot leave the merged promise below its
// accepted ballot. This is a merge invariant, not a mixed-version safety claim.
func TestClaimTransfer_PromiseAtLeastAccepted(t *testing.T) {
	ctx := context.Background()
	_, _, _, c := threeVoters(t)
	v := workloadValue("p", "a", "ghost")
	s := ClaimVoterState{Key: workloadKey(), Accepted: testBallot(3, "x"), Value: &v, ValueDigest: v.MustDigest()}
	if _, err := c.c.ImportClaimsAndAdopt(ctx, 2, []string{"a", "b"}, []ClaimVoterState{s}); err != nil {
		t.Fatal(err)
	}
	st, found, err := c.c.ClaimState(ctx, s.Key)
	if err != nil || !found || !st.Promised.Equal(testBallot(3, "x")) || !st.Accepted.Equal(testBallot(3, "x")) {
		t.Fatalf("merged: %+v %t %v", st, found, err)
	}
}
