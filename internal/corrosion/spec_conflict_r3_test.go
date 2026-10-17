package corrosion

import (
	"context"
	"strings"
	"testing"
)

// The re-review's IMP-1: the owner claims vm1 (C, 0→1) for an operation while
// b, cut off, makes two out-of-band edits (X1, X2). After the heal, the WAL
// and anti-entropy keep the claim's barrier on the owner while the operation
// runs, so the owner completes it. Once it has completed, the longer line
// takes over and the claim's version is recorded as dropped, once.
//
// Red on 6963eec4: anti-entropy's generation rule carried X2 over the running
// operation's barrier and CompleteVMOperation missed.
func TestSpecConflictAE_ALongerLineWaitsForARunningOperation(t *testing.T) {
	peers := newSpecPeers(t, true, "a", "b")
	a, b := peers[0], peers[1]
	seedEverywhere(t, peers)
	ctx := context.Background()
	op := OperationRecord{ID: "op-1", Method: "UpdateVM", ResourceKind: "vm", ResourceID: "vm1",
		OperationKind: string(OpResourceUpdateRunning), RequestHash: "h"}
	if ok, err := a.c.BeginVMOperation(ctx, op, `{"cpu":4}`, 0, 0); err != nil || !ok {
		t.Fatalf("BeginVMOperation: %v %v", ok, err)
	}
	edit(t, b, `{"cpu":2,"labels":{"tier":"one"}}`)
	edit(t, b, `{"cpu":2,"labels":{"tier":"two"}}`)
	ea, eb := a.news(t), b.news(t)
	applyWAL(t, a.r, eb)
	applyWAL(t, b.r, ea)
	mergeFrom(t, a, b)
	if got := vmSpecOn(t, a); got.ActiveOperationID != "op-1" || !strings.Contains(got.Spec, `"cpu":4`) {
		t.Fatalf("the owner lost op-1's barrier mid-operation: %s, barrier %q", got.Spec, got.ActiveOperationID)
	}
	if ok, err := a.c.CompleteVMOperation(ctx, "vm1", "op-1", 0, 1); err != nil || !ok {
		t.Fatalf("the owner cannot complete op-1: %v %v", ok, err)
	}
	mergeFrom(t, a, b)
	mergeFrom(t, a, b)
	for _, p := range peers {
		if got := vmSpecOn(t, p); !strings.Contains(got.Spec, `"tier":"two"`) || got.ActiveOperationID != "" {
			t.Errorf("%s after the operation: %s, barrier %q; want b's longer line", p.name, got.Spec, got.ActiveOperationID)
		}
	}
	if n := eventsQuoting(t, a, `"cpu":4`); n != 1 {
		t.Errorf("the owner recorded the claim's version %d times, want once", n)
	}
}

// The re-review's m2: anti-entropy meets the same losing version on every
// pass until the peer holding it catches up. It is counted once.
func TestSpecConflictAE_ADropIsCountedOnce(t *testing.T) {
	peers := newSpecPeers(t, true, "a", "b")
	a, b := peers[0], peers[1]
	m := &fakeSyncMetrics{}
	a.c.SetSyncMetrics(m)
	seedEverywhere(t, peers)
	edit(t, b, `{"cpu":2,"labels":{"tier":"front"}}`)
	edit(t, a, `{"cpu":4}`) // a's is the later edit: a keeps it against b's
	for i := 0; i < 3; i++ {
		mergeFrom(t, a, b)
	}
	if n := eventsQuoting(t, a, "tier"); n != 1 {
		t.Fatalf("a recorded b's dropped edit %d times, want once", n)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	count := 0
	for _, r := range m.mergeRejected {
		if r == "vms/ae/spec_edit_dropped" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("three passes counted the one drop %d times, want once", count)
	}
}
