package corrosion

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

func decodeStmts(t *testing.T, raw string) []Statement {
	t.Helper()
	var stmts []Statement
	if err := json.Unmarshal([]byte(raw), &stmts); err != nil {
		t.Fatalf("decode logged statements: %v", err)
	}
	return stmts
}

func specConflictOn(c *Client) { c.SetSpecConflictGate(func() bool { return true }) }

// loggedSQL is the statement text of every mutation c has logged, in order.
func loggedSQL(t *testing.T, c *Client) []string {
	t.Helper()
	var out []string
	for _, e := range walEntries(t, c, "x") {
		for _, s := range decodeStmts(t, e.Stmts) {
			out = append(out, s.SQL)
		}
	}
	return out
}

// An out-of-band spec edit keeps the previous release's shape until
// spec_conflict_v1 has latched — a previous-release peer has no ledger entry
// for the epoch-carrying one — and carries the owner epoch after.
func TestMutateDesiredSpec_CarriesTheOwnerEpochOnlyOnceLatched(t *testing.T) {
	ctx := context.Background()
	for _, latched := range []bool{false, true} {
		c := testClient(t)
		if latched {
			specConflictOn(c)
		}
		seedVM(t, c, "vm1", `{"cpu":2}`)
		if applied, gen, err := MutateDesiredSpec(ctx, c, "vm1", func(string) (string, error) { return `{"cpu":4}`, nil }); err != nil || !applied || gen != 1 {
			t.Fatalf("latched=%v: applied=%v gen=%d err=%v", latched, applied, gen, err)
		}
		var edit string
		for _, sql := range loggedSQL(t, c) {
			if strings.Contains(sql, "spec_generation = spec_generation + 1") {
				edit = sql
			}
		}
		want, _ := FingerprintSQL(vmSpecMutateSQL)
		if latched {
			want, _ = FingerprintSQL(vmSpecMutateAtEpochSQL)
		}
		if got, err := FingerprintSQL(edit); err != nil || got != want {
			t.Errorf("latched=%v: logged edit %q is not the expected shape", latched, edit)
		}
		if _, ok := LedgerLookup(want); !ok {
			t.Errorf("latched=%v: the emitted shape is not in the ledger", latched)
		}
	}
}

// specPeer is one replica: its client, its replicator, and how many of its own
// mutations have been handed out.
type specPeer struct {
	name string
	c    *Client
	r    *Replicator
	sent int
}

func newSpecPeers(t *testing.T, latched bool, names ...string) []*specPeer {
	t.Helper()
	out := make([]*specPeer, len(names))
	for i, n := range names {
		c := testClient(t)
		if latched {
			specConflictOn(c)
		}
		out[i] = &specPeer{name: n, c: c, r: NewReplicator(c, "", RelayConfig{})}
	}
	return out
}

// news returns p's mutations not yet handed out.
func (p *specPeer) news(t *testing.T) []*pb.MutationEntry {
	t.Helper()
	all := walEntries(t, p.c, p.name)
	out := all[p.sent:]
	p.sent = len(all)
	return out
}

func vmSpecOn(t *testing.T, p *specPeer) *VMRecord {
	t.Helper()
	vm, err := GetVM(context.Background(), p.c, "vm1")
	if err != nil || vm == nil {
		t.Fatalf("GetVM vm1 on %s: %v %v", p.name, vm, err)
	}
	return vm
}

// seedEverywhere creates vm1 on peers[0] and replicates it to the rest.
func seedEverywhere(t *testing.T, peers []*specPeer) {
	t.Helper()
	seedVM(t, peers[0].c, "vm1", `{"cpu":2}`)
	e := peers[0].news(t)
	for _, p := range peers[1:] {
		applyWAL(t, p.r, e)
	}
}

func setSpec(t *testing.T, p *specPeer, spec string) {
	t.Helper()
	if applied, _, err := MutateDesiredSpec(context.Background(), p.c, "vm1", func(string) (string, error) { return spec, nil }); err != nil || !applied {
		t.Fatalf("edit on %s: applied=%v err=%v", p.name, applied, err)
	}
}

// Two out-of-band edits from one generation, one on each side of a cut. Every
// replica, in whichever order it hears them, keeps the later one — the version
// anti-entropy keeps — rather than whichever came first.
//
// Red before the resolution: a and b each keep their own, c and d whichever
// came first.
func TestSpecConflict_SiblingEditsConvergeOnTheLaterEdit(t *testing.T) {
	peers := newSpecPeers(t, true, "a", "b", "c", "d")
	a, b, c, d := peers[0], peers[1], peers[2], peers[3]
	seedEverywhere(t, peers)

	setSpec(t, a, `{"cpu":4}`)
	time.Sleep(5 * time.Millisecond)
	setSpec(t, b, `{"cpu":2,"labels":{"tier":"front"}}`)
	ea, eb := a.news(t), b.news(t)

	applyWAL(t, a.r, eb)
	applyWAL(t, b.r, ea)
	applyWAL(t, c.r, ea)
	applyWAL(t, c.r, eb)
	applyWAL(t, d.r, eb)
	applyWAL(t, d.r, ea)

	want := vmSpecOn(t, b)
	for _, p := range peers {
		got := vmSpecOn(t, p)
		if got.Spec != `{"cpu":2,"labels":{"tier":"front"}}` || got.SpecGeneration != 1 || got.UpdatedAt != want.UpdatedAt {
			t.Errorf("%s holds %s@%d (%s), want b's later edit at 1 (%s)", p.name, got.Spec, got.SpecGeneration, got.UpdatedAt, want.UpdatedAt)
		}
	}
}

// The owner claims vm1 for an operation while a cut-off replica edits it at
// the same generation, later. The claim wins on every replica: the owner keeps
// its barrier, the replica takes the claim, and the owner's completion then
// clears it everywhere.
//
// Red before the resolution: b keeps its edit, so the barrier and the
// operation's spec never reach it and the completion's CAS misses there.
func TestSpecConflict_AnOperationsClaimBeatsAnOutOfBandEditAtItsGeneration(t *testing.T) {
	peers := newSpecPeers(t, true, "a", "b", "c")
	a, b, c := peers[0], peers[1], peers[2]
	seedEverywhere(t, peers)
	ctx := context.Background()

	op := OperationRecord{ID: "op-1", Method: "UpdateVM", ResourceKind: "vm", ResourceID: "vm1",
		OperationKind: string(OpResourceUpdateRunning), RequestHash: "h"}
	if ok, err := a.c.BeginVMOperation(ctx, op, `{"cpu":4}`, 0, 0); err != nil || !ok {
		t.Fatalf("BeginVMOperation: %v %v", ok, err)
	}
	time.Sleep(5 * time.Millisecond)
	setSpec(t, b, `{"cpu":2,"labels":{"tier":"front"}}`)
	ea, eb := a.news(t), b.news(t)

	applyWAL(t, a.r, eb)
	applyWAL(t, b.r, ea)
	applyWAL(t, c.r, eb)
	applyWAL(t, c.r, ea)
	for _, p := range peers {
		if got := vmSpecOn(t, p); got.Spec != `{"cpu":4}` || got.ActiveOperationID != "op-1" {
			t.Errorf("%s holds %s with barrier %q mid-operation, want the claim's spec under op-1", p.name, got.Spec, got.ActiveOperationID)
		}
	}

	if ok, err := a.c.CompleteVMOperation(ctx, "vm1", "op-1", 0, 1); err != nil || !ok {
		t.Fatalf("the owner cannot complete op-1: %v %v", ok, err)
	}
	ec := a.news(t)
	applyWAL(t, b.r, ec)
	applyWAL(t, c.r, ec)
	for _, p := range peers {
		if got := vmSpecOn(t, p); got.Spec != `{"cpu":4}` || got.ActiveOperationID != "" {
			t.Errorf("%s after completion: %s, barrier %q", p.name, got.Spec, got.ActiveOperationID)
		}
	}
}

// Until spec_conflict_v1 has latched nothing changes: an operation's claim
// meeting an edit at its generation misses its CAS as before.
func TestSpecConflict_BeforeTheLatchAClaimMeetingAnEditMissesAsBefore(t *testing.T) {
	peers := newSpecPeers(t, false, "a", "b")
	a, b := peers[0], peers[1]
	seedEverywhere(t, peers)
	op := OperationRecord{ID: "op-1", Method: "UpdateVM", ResourceKind: "vm", ResourceID: "vm1",
		OperationKind: string(OpResourceUpdateRunning), RequestHash: "h"}
	if ok, err := a.c.BeginVMOperation(context.Background(), op, `{"cpu":4}`, 0, 0); err != nil || !ok {
		t.Fatalf("BeginVMOperation: %v %v", ok, err)
	}
	setSpec(t, b, `{"cpu":2,"labels":{"tier":"front"}}`)
	applyWAL(t, b.r, a.news(t))
	if got := vmSpecOn(t, b); got.ActiveOperationID != "" || got.Spec != `{"cpu":2,"labels":{"tier":"front"}}` {
		t.Errorf("before the latch b resolved the claim: %s, barrier %q", got.Spec, got.ActiveOperationID)
	}
}

func TestResolveSpecEdit(t *testing.T) {
	const t1, t2 = "2026-10-16T10:00:00.000000001Z", "2026-10-16T10:00:00.000000002Z"
	row := func(epoch, gen int64, op, spec, ts string) specRow {
		return specRow{epoch: epoch, gen: gen, activeOp: op, spec: spec, updatedAt: ts}
	}
	edit := func(epoch, from int64, op, spec, ts string) specEdit {
		return specEdit{epoch: epoch, fromGen: from, opID: op, spec: spec, updatedAt: ts}
	}
	cases := []struct {
		name     string
		local    specRow
		in       specEdit
		finished bool
		want     specDecision
	}{
		{"no sibling", row(1, 3, "", "A", t1), edit(1, 3, "", "B", t2), false, specDecision{verdict: specApplyAsBefore}},
		{"no sibling, superseded owner", row(2, 3, "", "A", t1), edit(1, 3, "", "B", t2), false, specDecision{specKeepLocal, specDropStaleEpoch}},
		{"row ahead by two", row(1, 5, "", "A", t1), edit(1, 3, "", "B", t2), false, specDecision{verdict: specApplyAsBefore}},
		{"row behind", row(1, 2, "", "A", t1), edit(1, 3, "", "B", t2), false, specDecision{verdict: specApplyAsBefore}},
		{"this edit, already here", row(1, 4, "", "B", t2), edit(1, 3, "", "B", t2), false, specDecision{verdict: specKeepLocal}},
		{"sibling from a superseded owner", row(2, 4, "", "A", t1), edit(1, 3, "", "B", t2), false, specDecision{specKeepLocal, specDropStaleEpoch}},
		{"sibling from a newer owner", row(1, 4, "", "A", t2), edit(2, 3, "", "B", t1), false, specDecision{verdict: specApplyAsBefore}},
		{"later edit wins", row(1, 4, "", "A", t1), edit(1, 3, "", "B", t2), false, specDecision{specTakeEdit, specDropLaterEdit}},
		{"earlier edit loses", row(1, 4, "", "A", t2), edit(1, 3, "", "B", t1), false, specDecision{specKeepLocal, specDropLaterEdit}},
		{"exact tie keeps local", row(1, 4, "", "A", t1), edit(1, 3, "", "B", t1), false, specDecision{specKeepLocal, specDropTie}},
		{"same spec drops nothing", row(1, 4, "", "B", t1), edit(1, 3, "", "B", t2), false, specDecision{verdict: specTakeEdit}},
		{"barrier beats a later edit", row(1, 4, "op", "A", t1), edit(1, 3, "", "B", t2), false, specDecision{specKeepLocal, specDropOperation}},
		{"claim beats a later edit", row(1, 4, "", "A", t2), edit(1, 3, "op", "B", t1), false, specDecision{specTakeEdit, specDropOperation}},
		{"a finished claim changes nothing", row(1, 4, "", "B", t2), edit(1, 3, "op", "B", t1), true, specDecision{verdict: specKeepLocal}},
		{"its own claim", row(1, 4, "op", "B", t2), edit(1, 3, "op", "B", t1), false, specDecision{verdict: specKeepLocal}},
		{"another operation's barrier", row(1, 4, "op2", "A", t1), edit(1, 3, "op", "B", t2), false, specDecision{specKeepLocal, specDropOperation}},
	}
	for _, tc := range cases {
		if got := resolveSpecEdit(tc.local, tc.in, tc.finished); got != tc.want {
			t.Errorf("%s: got %+v, want %+v", tc.name, got, tc.want)
		}
	}
}

func mergeFrom(t *testing.T, into, from *specPeer) {
	t.Helper()
	if err := into.c.MergeStateBytesLWW(from.c.DumpStateBytes()); err != nil {
		t.Fatalf("merge %s into %s: %v", from.name, into.name, err)
	}
}

// Anti-entropy alone: the owner's operation has claimed vm1 at generation 1
// and a cut-off replica edited it at 1, later. Anti-entropy keeps the claim on
// both sides, as the WAL does — it used to copy the later edit onto the
// owner, clearing the barrier of the operation in flight.
func TestSpecConflictAE_AnOutOfBandEditNeverOverwritesABarrier(t *testing.T) {
	peers := newSpecPeers(t, true, "a", "b")
	a, b := peers[0], peers[1]
	seedEverywhere(t, peers)
	op := OperationRecord{ID: "op-1", Method: "UpdateVM", ResourceKind: "vm", ResourceID: "vm1",
		OperationKind: string(OpResourceUpdateRunning), RequestHash: "h"}
	if ok, err := a.c.BeginVMOperation(context.Background(), op, `{"cpu":4}`, 0, 0); err != nil || !ok {
		t.Fatalf("BeginVMOperation: %v %v", ok, err)
	}
	time.Sleep(5 * time.Millisecond)
	setSpec(t, b, `{"cpu":2,"labels":{"tier":"front"}}`)

	mergeFrom(t, a, b)
	mergeFrom(t, b, a)
	for _, p := range peers {
		if got := vmSpecOn(t, p); got.Spec != `{"cpu":4}` || got.ActiveOperationID != "op-1" {
			t.Errorf("%s after anti-entropy: %s, barrier %q; want the claim under op-1", p.name, got.Spec, got.ActiveOperationID)
		}
	}
	if ok, err := a.c.CompleteVMOperation(context.Background(), "vm1", "op-1", 0, 1); err != nil || !ok {
		t.Errorf("the owner cannot complete op-1 after anti-entropy: %v %v", ok, err)
	}
}

// The barrier rule holds only while the operation is in flight. b holds op-1's
// claim, heard by the WAL; c, on the previous release's resolution, kept its
// own later edit at the same generation and has heard op-1 complete. Once a
// side records op-1's terminal step the barrier no longer stands, and the
// clocks decide: c's later edit replaces the finished claim on b.
func TestSpecConflictAE_AFinishedOperationsBarrierNoLongerStands(t *testing.T) {
	peers := newSpecPeers(t, true, "a", "b")
	a, b := peers[0], peers[1]
	c := newSpecPeers(t, false, "c")[0]
	seedVM(t, a.c, "vm1", `{"cpu":2}`)
	seed := a.news(t)
	applyWAL(t, b.r, seed)
	applyWAL(t, c.r, seed)
	ctx := context.Background()
	op := OperationRecord{ID: "op-1", Method: "UpdateVM", ResourceKind: "vm", ResourceID: "vm1",
		OperationKind: string(OpResourceUpdateRunning), RequestHash: "h"}
	if ok, err := a.c.BeginVMOperation(ctx, op, `{"cpu":4}`, 0, 0); err != nil || !ok {
		t.Fatalf("BeginVMOperation: %v %v", ok, err)
	}
	begin := a.news(t)
	applyWAL(t, b.r, begin)
	time.Sleep(5 * time.Millisecond)
	setSpec(t, c, `{"cpu":2,"labels":{"tier":"front"}}`)
	if ok, err := a.c.CompleteVMOperation(ctx, "vm1", "op-1", 0, 1); err != nil || !ok {
		t.Fatalf("CompleteVMOperation: %v %v", ok, err)
	}
	applyWAL(t, c.r, begin)
	applyWAL(t, c.r, a.news(t))
	if got := vmSpecOn(t, b); got.ActiveOperationID != "op-1" {
		t.Fatalf("premise: b holds %s with barrier %q, want op-1's claim", got.Spec, got.ActiveOperationID)
	}
	if got := vmSpecOn(t, c); got.ActiveOperationID != "" || !strings.Contains(got.Spec, "tier") {
		t.Fatalf("premise: c holds %s with barrier %q, want its own edit", got.Spec, got.ActiveOperationID)
	}
	mergeFrom(t, b, c)
	if got := vmSpecOn(t, b); got.ActiveOperationID != "" || !strings.Contains(got.Spec, "tier") {
		t.Errorf("b after anti-entropy: %s, barrier %q; want c's later edit over the finished claim", got.Spec, got.ActiveOperationID)
	}
}
