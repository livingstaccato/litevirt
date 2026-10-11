package corrosion

import (
	"context"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/capabilities"
)

// LUN allocation claims: one iSCSI LUN, one disk, decided by a voter
// majority (docs/storage.md, "iSCSI: one LUN, one disk").

func lunKey(gen int64) ClaimKey { return LUNClaimKey("iscsi:iqn.x:store/lun0", gen) }

// recordLUNUseForTest records iscsi_lun_claim used on each voter's replica, as
// the first use's acknowledgement round leaves every voter: a voter takes LUN
// keys only then (switch review M-3).
func recordLUNUseForTest(t *testing.T, vs ...*claimTestVoter) {
	t.Helper()
	for _, v := range vs {
		v.c.SetClusterPolicyGate(func() bool { return true })
		if err := RecordReleaseFeatureUse(context.Background(), v.c, capabilities.ReleaseToken,
			string(capabilities.FeatureISCSILUNClaim), v.name, true); err != nil {
			t.Fatal(err)
		}
	}
}

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
		func(l *LUNAllocation) { l.RunHost = "c" },
		func(l *LUNAllocation) { l.Kept = true },
		func(l *LUNAllocation) { l.Kept, l.Project = true, "p2" },
		func(l *LUNAllocation) { l.Kept, l.ReplacedCreatedAt = true, "2026-01-01T00:00:00Z" },
	} {
		b := lunValue(0, "c1", "web")
		mut(b.LUN)
		if db, _ := b.Digest(); db == da {
			t.Errorf("%+v digests like %+v", b.LUN, a.LUN)
		}
	}
	// RunHost and Kept are digested only when set, each in a field of its
	// own: no RunHost spelling digests like Kept.
	kept, spelled := lunValue(0, "c1", "web"), lunValue(0, "c1", "web")
	kept.LUN.Kept, spelled.LUN.RunHost = true, "kept"
	if dk, _ := kept.Digest(); func() bool { ds, _ := spelled.Digest(); return ds == dk }() {
		t.Error("a RunHost of \"kept\" digests like Kept")
	}
	// A kept allocation's project and replaced incarnation are each part of
	// what is decided.
	keptBase := lunValue(0, "c1", "web")
	keptBase.LUN.Kept = true
	dkb, _ := keptBase.Digest()
	for _, mut := range []func(*LUNAllocation){
		func(l *LUNAllocation) { l.Project = "p2" },
		func(l *LUNAllocation) { l.ReplacedCreatedAt = "2026-01-01T00:00:00Z" },
	} {
		b := lunValue(0, "c1", "web")
		b.LUN.Kept = true
		mut(b.LUN)
		if db, _ := b.Digest(); db == dkb {
			t.Errorf("%+v digests like %+v", b.LUN, keptBase.LUN)
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
	recordLUNUseForTest(t, a)
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
	recordLUNUseForTest(t, a, b, c)
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
	if err := AdvanceLUNResolved(ctx, c, capabilities.GrantForTest(t, capabilities.FeatureISCSILUNClaim), "iscsi:x/lun0", 4, "h"); err != nil {
		t.Fatal(err)
	}
	if g, _ := GetLUNResolved(ctx, c, "iscsi:x/lun0"); g != 0 {
		t.Fatalf("written behind a closed cluster-policy gate: %d", g)
	}
	c.SetClusterPolicyGate(func() bool { return true })
	for _, step := range []struct{ to, want int64 }{{4, 4}, {2, 4}, {7, 7}} {
		if err := AdvanceLUNResolved(ctx, c, capabilities.GrantForTest(t, capabilities.FeatureISCSILUNClaim), "iscsi:x/lun0", step.to, "h"); err != nil {
			t.Fatal(err)
		}
		if g, _ := GetLUNResolved(ctx, c, "iscsi:x/lun0"); g != step.want {
			t.Fatalf("advance to %d: checkpoint %d, want %d", step.to, g, step.want)
		}
	}
}

// ── fix/iscsi-followups ─────────────────────────────────────────────────────

// Switch review M-3: a voter takes a LUN key — a promise or an accept — only
// once its own replica holds iscsi_lun_claim's used record, read in the same
// transaction. A voter added after the first use, which has not replicated the
// record yet, refuses (retryable), so it never holds LUN state while a rollback
// below the release would leave it unquarantined. Workload keys are not
// affected.
//
// Mutation: drop the used-record check from admit — the unrecorded stage goes
// red.
func TestClaimVoter_LUNKeysNeedTheUsedRecord(t *testing.T) {
	ctx := context.Background()
	_, a, _, _ := threeVoters(t)
	k := lunKey(0)
	res, err := a.c.ClaimPrepare(ctx, k, testBallot(1, "b"), 1)
	if err != nil || res.Promised || res.Refusal != RefusalFeatureUnrecorded {
		t.Fatalf("prepare at a LUN key with no used record: %+v %v, want refused %s", res, err, RefusalFeatureUnrecorded)
	}
	acc, err := a.c.ClaimAccept(ctx, k, testBallot(1, "b"), lunValue(0, "c1", "web"), 1, a.signer, unreachable)
	if err != nil || acc.Accepted || acc.Refusal != RefusalFeatureUnrecorded {
		t.Fatalf("accept at a LUN key with no used record: %+v %v, want refused %s", acc, err, RefusalFeatureUnrecorded)
	}
	if st, _, _ := a.c.ClaimState(ctx, k); st.Value != nil || !st.Promised.IsZero() {
		t.Fatalf("a refused voter recorded state: %+v", st)
	}
	if res, err := a.c.ClaimPrepare(ctx, workloadKey(), testBallot(1, "b"), 1); err != nil || !res.Promised {
		t.Fatalf("a workload key with no used record: %+v %v", res, err)
	}
	recordLUNUseForTest(t, a)
	if res, err := a.c.ClaimPrepare(ctx, k, testBallot(1, "b"), 1); err != nil || !res.Promised {
		t.Fatalf("prepare once the used record is here: %+v %v", res, err)
	}
	if acc, err := a.c.ClaimAccept(ctx, k, testBallot(1, "b"), lunValue(0, "c1", "web"), 1, a.signer, unreachable); err != nil || !acc.Accepted {
		t.Fatalf("accept once the used record is here: %+v %v", acc, err)
	}
}
