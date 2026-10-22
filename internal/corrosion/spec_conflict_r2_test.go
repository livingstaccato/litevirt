package corrosion

import (
	"context"
	"strings"
	"testing"
	"time"
)

// These use only what 58f7754f already had, so each can be shown red there.

// eventsQuoting counts the dropped-edit events on p whose detail quotes part.
// The events are recorded asynchronously, one per dropped edit, and a replica
// can drop more than one (c here drops both the owner's edit and b's first), so
// the first event to land is not necessarily the one asked about: wait for one
// that quotes part, not for any.
func eventsQuoting(t *testing.T, p *specPeer, part string) int {
	t.Helper()
	for want := 1; ; want++ {
		evs := droppedEvents(t, p, want)
		n := 0
		for _, e := range evs {
			if strings.Contains(e.Detail, part) {
				n++
			}
		}
		if n > 0 || len(evs) < want {
			return n
		}
	}
}

func edit(t *testing.T, p *specPeer, spec string) {
	t.Helper()
	setSpec(t, p, spec)
	time.Sleep(5 * time.Millisecond)
}

// The review's C1: the owner edits (A), a cut-off replica edits later (X),
// then the owner writes the VM's state (S). S moves the row's clock past X's,
// which is no evidence about the spec. X is the later edit: every replica
// keeps it, the row clocks agree, and A is recorded once on each — never X.
//
// Red on 58f7754f: the owner keeps A (its row clock, 7, beats X's 6), b keeps
// X and later takes S's clock; each records the other's edit as dropped.
func TestSpecConflict_AStateWriteBetweenTheEditsDoesNotSplitTheSpec(t *testing.T) {
	peers := newSpecPeers(t, true, "a", "b", "c")
	a, b, c := peers[0], peers[1], peers[2]
	seedEverywhere(t, peers)
	edit(t, a, `{"cpu":4}`)
	edit(t, b, `{"cpu":2,"labels":{"tier":"front"}}`)
	if err := UpdateVMState(context.Background(), a.c, "vm1", "stopped", ""); err != nil {
		t.Fatal(err)
	}
	ea, eb := a.news(t), b.news(t)
	applyWAL(t, a.r, eb)
	applyWAL(t, b.r, ea)
	applyWAL(t, c.r, ea)
	applyWAL(t, c.r, eb)

	want := vmSpecOn(t, b)
	for _, p := range peers {
		got := vmSpecOn(t, p)
		if !strings.Contains(got.Spec, `"tier":"front"`) || strings.Contains(got.Spec, `"cpu":4`) ||
			got.Spec != want.Spec || got.State != "stopped" || got.UpdatedAt != want.UpdatedAt {
			t.Errorf("%s holds %s %s (%s); want b's later edit, stopped, as b holds it (%s %s)",
				p.name, got.Spec, got.State, got.UpdatedAt, want.Spec, want.UpdatedAt)
		}
	}
	for _, p := range peers {
		evs := droppedEvents(t, p, 1)
		if len(evs) != 1 || !strings.Contains(evs[0].Detail, `"cpu":4`) || strings.Contains(evs[0].Detail, "tier") {
			t.Errorf("%s: want one record, of the owner's dropped cpu edit; got %+v", p.name, evs)
		}
	}
}

// The review's I2: an operation claims vm1 for a resize to cpu=4, and a
// cut-off replica's deploy records the same cpu=4 out of band, later.
// Anti-entropy alone must keep the claim's barrier on both sides.
//
// Red on 58f7754f: the specs are equal, so the row merged by clock and the
// later out-of-band row cleared the owner's barrier.
func TestSpecConflictAE_AnEqualContentEditDuringAResizeKeepsTheBarrier(t *testing.T) {
	peers := newSpecPeers(t, true, "a", "b")
	a, b := peers[0], peers[1]
	seedEverywhere(t, peers)
	ctx := context.Background()
	op := OperationRecord{ID: "op-1", Method: "UpdateVM", ResourceKind: "vm", ResourceID: "vm1",
		OperationKind: string(OpResourceUpdateRunning), RequestHash: "h"}
	if ok, err := a.c.BeginVMOperation(ctx, op, `{"cpu":4}`, 0, 0); err != nil || !ok {
		t.Fatalf("BeginVMOperation: %v %v", ok, err)
	}
	time.Sleep(5 * time.Millisecond)
	setSpec(t, b, `{"cpu":4}`)
	mergeFrom(t, a, b)
	mergeFrom(t, b, a)
	for _, p := range peers {
		if got := vmSpecOn(t, p); got.ActiveOperationID != "op-1" {
			t.Errorf("%s after anti-entropy: barrier %q, want op-1's", p.name, got.ActiveOperationID)
		}
	}
	if ok, err := a.c.CompleteVMOperation(ctx, "vm1", "op-1", 0, 1); err != nil || !ok {
		t.Errorf("the owner cannot complete op-1: %v %v", ok, err)
	}
}

// The review's I3, first shape: b, cut off, edits twice (X1, then X2) while
// the owner edits once (A), between them. Every replica ends on X2, the
// longer line; A is gone everywhere and recorded on every replica.
//
// Red on 58f7754f: A disappears with no record anywhere.
func TestSpecConflict_TwoEditsAgainstOneRecordTheOneLost(t *testing.T) {
	peers := newSpecPeers(t, true, "a", "b", "c")
	a, b, c := peers[0], peers[1], peers[2]
	seedEverywhere(t, peers)
	edit(t, b, `{"cpu":2,"labels":{"tier":"one"}}`)
	edit(t, a, `{"cpu":4}`)
	edit(t, b, `{"cpu":2,"labels":{"tier":"two"}}`)
	ea, eb := a.news(t), b.news(t)
	applyWAL(t, a.r, eb)
	applyWAL(t, b.r, ea)
	applyWAL(t, c.r, ea)
	applyWAL(t, c.r, eb)
	for _, p := range peers {
		if got := vmSpecOn(t, p); !strings.Contains(got.Spec, `"tier":"two"`) || got.SpecGeneration != 2 {
			t.Errorf("%s holds %s@%d, want b's second edit at 2", p.name, got.Spec, got.SpecGeneration)
		}
		if eventsQuoting(t, p, `"cpu":4`) != 1 {
			t.Errorf("%s has no record of the owner's lost cpu edit", p.name)
		}
	}
}

// The review's I3, mirror shape: the owner edits twice (A1, then A2) and b,
// cut off, edits once (X), between them. Every replica ends on A2; X is
// recorded on every replica.
//
// Red on 58f7754f: X disappears with no record anywhere.
func TestSpecConflict_OneEditAgainstTwoRecordsTheOneLost(t *testing.T) {
	peers := newSpecPeers(t, true, "a", "b", "c")
	a, b, c := peers[0], peers[1], peers[2]
	seedEverywhere(t, peers)
	edit(t, a, `{"cpu":4}`)
	edit(t, b, `{"cpu":2,"labels":{"tier":"front"}}`)
	edit(t, a, `{"cpu":6}`)
	ea, eb := a.news(t), b.news(t)
	applyWAL(t, a.r, eb)
	applyWAL(t, b.r, ea)
	applyWAL(t, c.r, eb)
	applyWAL(t, c.r, ea)
	for _, p := range peers {
		if got := vmSpecOn(t, p); !strings.Contains(got.Spec, `"cpu":6`) || got.SpecGeneration != 2 {
			t.Errorf("%s holds %s@%d, want the owner's second edit at 2", p.name, got.Spec, got.SpecGeneration)
		}
		if eventsQuoting(t, p, "tier") != 1 {
			t.Errorf("%s has no record of b's lost label edit", p.name)
		}
	}
}

// The first shape again, through anti-entropy alone: a merge that carries a
// longer line over a replica's edit records that edit, on both sides.
//
// Red on 58f7754f: nothing is recorded.
func TestSpecConflictAE_TwoEditsAgainstOneRecordTheOneLost(t *testing.T) {
	peers := newSpecPeers(t, true, "a", "b")
	a, b := peers[0], peers[1]
	seedEverywhere(t, peers)
	edit(t, b, `{"cpu":2,"labels":{"tier":"one"}}`)
	edit(t, a, `{"cpu":4}`)
	edit(t, b, `{"cpu":2,"labels":{"tier":"two"}}`)
	mergeFrom(t, b, a)
	mergeFrom(t, a, b)
	for _, p := range peers {
		if got := vmSpecOn(t, p); !strings.Contains(got.Spec, `"tier":"two"`) {
			t.Errorf("%s holds %s, want b's second edit", p.name, got.Spec)
		}
		if eventsQuoting(t, p, `"cpu":4`) != 1 {
			t.Errorf("%s has no record of the owner's lost cpu edit", p.name)
		}
	}
}

// The review's C1 through anti-entropy alone: the owner's state write gives
// its row the later clock, but b's edit is the later one. Both sides keep
// b's edit — and the owner's state — and record the owner's cpu edit. b
// merges first, so the incoming row with the later clock carries the losing
// spec: the merge must still keep b's.
func TestSpecConflictAE_AStateWriteBetweenTheEditsDoesNotDecideTheSpec(t *testing.T) {
	peers := newSpecPeers(t, true, "a", "b")
	a, b := peers[0], peers[1]
	seedEverywhere(t, peers)
	edit(t, a, `{"cpu":4}`)
	edit(t, b, `{"cpu":2,"labels":{"tier":"front"}}`)
	if err := UpdateVMState(context.Background(), a.c, "vm1", "stopped", ""); err != nil {
		t.Fatal(err)
	}
	mergeFrom(t, b, a)
	mergeFrom(t, a, b)
	for _, p := range peers {
		got := vmSpecOn(t, p)
		if !strings.Contains(got.Spec, `"tier":"front"`) || strings.Contains(got.Spec, `"cpu":4`) || got.State != "stopped" {
			t.Errorf("%s holds %s %s; want b's later edit with the owner's state", p.name, got.Spec, got.State)
		}
		if eventsQuoting(t, p, `"cpu":4`) != 1 {
			t.Errorf("%s has no record of the owner's dropped cpu edit", p.name)
		}
	}
}

// A claim reaching a replica after its operation has finished there — the
// clear and the completed step came first — still wins its generation by
// its stamp, but leaves no barrier behind: nothing would ever clear it.
func TestSpecConflict_AClaimArrivingAfterItsOperationFinishedLeavesNoBarrier(t *testing.T) {
	peers := newSpecPeers(t, true, "a", "b")
	a, b := peers[0], peers[1]
	seedEverywhere(t, peers)
	ctx := context.Background()
	edit(t, b, `{"cpu":2,"labels":{"tier":"front"}}`)
	op := OperationRecord{ID: "op-1", Method: "UpdateVM", ResourceKind: "vm", ResourceID: "vm1",
		OperationKind: string(OpResourceUpdateRunning), RequestHash: "h"}
	if ok, err := a.c.BeginVMOperation(ctx, op, `{"cpu":4}`, 0, 0); err != nil || !ok {
		t.Fatalf("BeginVMOperation: %v %v", ok, err)
	}
	begin := a.news(t)
	if ok, err := a.c.CompleteVMOperation(ctx, "vm1", "op-1", 0, 1); err != nil || !ok {
		t.Fatalf("CompleteVMOperation: %v %v", ok, err)
	}
	applyWAL(t, b.r, a.news(t)) // the completion first
	applyWAL(t, b.r, begin)
	if got := vmSpecOn(t, b); got.ActiveOperationID != "" || !strings.Contains(got.Spec, `"cpu":4`) {
		t.Errorf("b holds %s with barrier %q; want the finished claim's spec and no barrier", got.Spec, got.ActiveOperationID)
	}
}

// An operation's clear is ordered by its guard, not the row's clock: a
// replica whose row clock a later write already moved past the clear still
// releases the barrier.
func TestSpecConflict_AClearOlderThanTheRowClockStillReleasesTheBarrier(t *testing.T) {
	peers := newSpecPeers(t, true, "a", "b")
	a, b := peers[0], peers[1]
	seedEverywhere(t, peers)
	ctx := context.Background()
	op := OperationRecord{ID: "op-1", Method: "UpdateVM", ResourceKind: "vm", ResourceID: "vm1",
		OperationKind: string(OpResourceUpdateRunning), RequestHash: "h"}
	if ok, err := a.c.BeginVMOperation(ctx, op, `{"cpu":4}`, 0, 0); err != nil || !ok {
		t.Fatalf("BeginVMOperation: %v %v", ok, err)
	}
	applyWAL(t, b.r, a.news(t))
	if ok, err := a.c.CompleteVMOperation(ctx, "vm1", "op-1", 0, 1); err != nil || !ok {
		t.Fatalf("CompleteVMOperation: %v %v", ok, err)
	}
	clear := a.news(t)
	time.Sleep(5 * time.Millisecond)
	if err := UpdateVMState(ctx, b.c, "vm1", "stopped", ""); err != nil { // b's row clock passes the clear's
		t.Fatal(err)
	}
	applyWAL(t, b.r, clear)
	if got := vmSpecOn(t, b); got.ActiveOperationID != "" {
		t.Errorf("b kept op-1's barrier: its clear lost to the row clock")
	}
}
