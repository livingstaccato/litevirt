package corrosion

import (
	"context"
	"strings"
	"testing"
)

// LUN allocation claims: one iSCSI LUN, one disk, decided by a voter
// majority (docs/storage.md, "iSCSI: one LUN, one disk").

func lunKey(gen int64) ClaimKey { return LUNClaimKey("iscsi:iqn.x:store/lun0", gen) }

func lunValue(gen int64, claim, vm string) ClaimValue {
	return ClaimValue{LUN: &LUNAllocation{LUN: "iscsi:iqn.x:store/lun0", Generation: gen, ClaimID: claim,
		VMID: vm + "-uuid", VMName: vm, Disk: "root", Host: "a"}}
}

// A LUN key names the LUN and an allocation generation, never an attempt or an
// incarnation.
//
// Mutation: accept any LUN key — the malformed keys go red.
func TestLUNClaimKey_Validate(t *testing.T) {
	if err := lunKey(3).Validate(); err != nil {
		t.Fatalf("a LUN key: %v", err)
	}
	for _, k := range []ClaimKey{
		{TargetKind: ClaimKindLUN},
		{TargetKind: ClaimKindLUN, TargetName: "x", Attempt: 1},
		{TargetKind: ClaimKindLUN, TargetName: "x", Incarnation: "i"},
		{TargetKind: ClaimKindLUN, TargetName: "x", OwnerEpoch: -1},
	} {
		if err := k.Validate(); err == nil {
			t.Errorf("%+v validated", k)
		}
	}
}

// A LUN value digests in its own domain, over every field, and never alongside
// a proof or a config.
func TestLUNClaimValue_Digest(t *testing.T) {
	a := lunValue(0, "c1", "web")
	da, err := a.Digest()
	if err != nil {
		t.Fatal(err)
	}
	for _, mut := range []func(*LUNAllocation){
		func(l *LUNAllocation) { l.ClaimID = "c2" },
		func(l *LUNAllocation) { l.VMID = "other" },
		func(l *LUNAllocation) { l.Disk = "data" },
		func(l *LUNAllocation) { l.Host = "b" },
		func(l *LUNAllocation) { l.Generation = 1 },
		func(l *LUNAllocation) { l.VMName = "db" },
	} {
		b := lunValue(0, "c1", "web")
		mut(b.LUN)
		if db, _ := b.Digest(); db == da {
			t.Errorf("%+v digests like %+v", b.LUN, a.LUN)
		}
	}
	mixed := lunValue(0, "c1", "web")
	mixed.Proof = &ActionProof{ID: "p"}
	if _, err := mixed.Digest(); err == nil {
		t.Error("a value with a LUN and a proof digested")
	}
}

// A voter decides LUN keys under its generation like workload keys — the
// membership and seal rules hold — but takes only a LUN value whose LUN and
// generation are the key's, and never probes an owner for one.
//
// Mutation: let a LUN key take a proof value — this goes red.
func TestClaimVoter_LUNKeys(t *testing.T) {
	ctx := context.Background()
	_, a, _, _ := threeVoters(t)
	k := lunKey(0)
	if res, err := a.c.ClaimPrepare(ctx, k, testBallot(1, "b"), 1); err != nil || !res.Promised {
		t.Fatalf("prepare: %+v %v", res, err)
	}
	probed := false
	probe := func(context.Context, string) (bool, string) { probed = true; return false, "" }
	if res, err := a.c.ClaimAccept(ctx, k, testBallot(1, "b"), workloadValue("p", "b", "ghost"), 1, a.signer, probe); err != nil ||
		res.Accepted || res.Refusal != RefusalInvalidValue {
		t.Fatalf("a proof at a LUN key: %+v %v", res, err)
	}
	wrong := lunValue(1, "c1", "web") // generation 1 at a generation-0 key
	if res, _ := a.c.ClaimAccept(ctx, k, testBallot(1, "b"), wrong, 1, a.signer, probe); res.Accepted {
		t.Fatalf("a value for another generation was accepted: %+v", res)
	}
	v := lunValue(0, "c1", "web")
	res, err := a.c.ClaimAccept(ctx, k, testBallot(1, "b"), v, 1, a.signer, probe)
	if err != nil || !res.Accepted {
		t.Fatalf("accept: %+v %v", res, err)
	}
	if probed {
		t.Error("a voter probed an owner for a LUN value")
	}
	if st, _, _ := a.c.ClaimState(ctx, k); st.Value == nil || st.Value.LUN == nil || st.Value.LUN.ClaimID != "c1" {
		t.Fatalf("stored state %+v", st)
	}
}

// A LUN allocation survives a change of voter generation: the new members
// import it like a workload decision, so a reconfiguration cannot let a LUN be
// decided twice.
//
// Mutation: leave LUN keys out of the import — this goes red.
func TestImportClaimsAndAdopt_CarriesLUNAllocations(t *testing.T) {
	ctx := context.Background()
	_, a, b, c := threeVoters(t)
	k := lunKey(0)
	v := lunValue(0, "c1", "web")
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
	if !res.Promised || res.State.Value == nil || res.State.Value.LUN == nil || res.State.Value.LUN.ClaimID != "c1" {
		t.Fatalf("the LUN allocation did not survive the reconfiguration: %+v", res)
	}
	if !strings.HasPrefix(k.String(), "lun/") {
		t.Errorf("key string %q", k.String())
	}
}

// ── fix round 2 ─────────────────────────────────────────────────────────────

// A LUN key, like a workload key, is decided only under an adopted member
// generation: with none (genesis pending, or after a reset) a voter refuses
// it, so no proposer can decide a LUN over a set two replicas may count
// differently (re-review 2, I-2).
//
// Mutation: admit LUN keys without a generation — this goes red.
func TestClaimVoter_LUNKeysNeedAGeneration(t *testing.T) {
	ctx := context.Background()
	ca := newClaimTestCA(t)
	a := newClaimTestVoter(t, ca, "a")
	res, err := a.c.ClaimPrepare(ctx, lunKey(0), testBallot(1, "b"), 0)
	if err != nil || res.Promised || res.Refusal != RefusalNoVoterConfig {
		t.Fatalf("a LUN key at no generation: %+v %v, want refused %s", res, err, RefusalNoVoterConfig)
	}
}

// A host is proven removed by its tombstone, never by a row this replica
// simply does not have.
//
// Mutation: report a host with no row at all as removed — this goes red.
func TestHostRemoved_NeedsATombstone(t *testing.T) {
	ctx := context.Background()
	c := NewTestClientT(t)
	if err := InitSchema(ctx, c); err != nil {
		t.Fatal(err)
	}
	if gone, err := HostRemoved(ctx, c, "never-heard-of"); err != nil || gone {
		t.Fatalf("a host with no row here: removed=%v err=%v", gone, err)
	}
	if err := InsertHost(ctx, c, HostRecord{Name: "h", Address: "10.0.0.1", State: "active"}); err != nil {
		t.Fatal(err)
	}
	if gone, _ := HostRemoved(ctx, c, "h"); gone {
		t.Fatal("a live host reported removed")
	}
	if err := DeleteHost(ctx, c, "h"); err != nil {
		t.Fatal(err)
	}
	if gone, err := HostRemoved(ctx, c, "h"); err != nil || !gone {
		t.Fatalf("a tombstoned host: removed=%v err=%v", gone, err)
	}
}

// The per-LUN "resolved up to" checkpoint only moves forward, and is written
// only where cluster_policies may be written.
//
// Mutation: write it unconditionally (drop the max) — the regression case
// goes red.
func TestLUNResolved_MovesForwardOnly(t *testing.T) {
	ctx := context.Background()
	c := NewTestClientT(t)
	if err := InitSchema(ctx, c); err != nil {
		t.Fatal(err)
	}
	if g, err := GetLUNResolved(ctx, c, "iscsi:x/lun0"); err != nil || g != 0 {
		t.Fatalf("no checkpoint: %d %v", g, err)
	}
	if err := AdvanceLUNResolved(ctx, c, "iscsi:x/lun0", 4, "h"); err != nil {
		t.Fatal(err)
	}
	if g, _ := GetLUNResolved(ctx, c, "iscsi:x/lun0"); g != 0 {
		t.Fatalf("written behind a closed cluster-policy gate: %d", g)
	}
	c.SetClusterPolicyGate(func() bool { return true })
	for _, step := range []struct{ to, want int64 }{{4, 4}, {2, 4}, {7, 7}} {
		if err := AdvanceLUNResolved(ctx, c, "iscsi:x/lun0", step.to, "h"); err != nil {
			t.Fatal(err)
		}
		if g, _ := GetLUNResolved(ctx, c, "iscsi:x/lun0"); g != step.want {
			t.Fatalf("advance to %d: checkpoint %d, want %d", step.to, g, step.want)
		}
	}
}
