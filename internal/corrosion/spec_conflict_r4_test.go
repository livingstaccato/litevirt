package corrosion

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func beginOp1(t *testing.T, p *specPeer, spec string) {
	t.Helper()
	op := OperationRecord{ID: "op-1", Method: "UpdateVM", ResourceKind: "vm", ResourceID: "vm1",
		OperationKind: string(OpResourceUpdateRunning), RequestHash: "h"}
	if ok, err := p.c.BeginVMOperation(context.Background(), op, spec, 0, 0); err != nil || !ok {
		t.Fatalf("BeginVMOperation on %s: %v %v", p.name, ok, err)
	}
}

func heldCondition(t *testing.T, p *specPeer) (HealthCondition, bool) {
	t.Helper()
	row, found, err := GetHealthCondition(context.Background(), p.c, specHoldEvaluator, SpecEditHeldCode, "vm", p.c.specHoldSubject("vm1"))
	if err != nil {
		t.Fatal(err)
	}
	return row, found
}

func waitSpecHold(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); !cond(); time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
	}
}

// IMP-2: the owner's operation holds b's longer line off. The hold is
// visible on the node that holds, once per (VM, operation): a counted
// warning and a vm.spec_edit_held condition naming the operation, the owner
// and the remedy. Once the operation completes and the line applies, the
// condition resolves.
//
// Red on 0421249e: the hold left no trace.
func TestSpecConflictAE_AHeldLineIsVisible(t *testing.T) {
	peers := newSpecPeers(t, true, "a", "b")
	a, b := peers[0], peers[1]
	m := &fakeSyncMetrics{}
	a.c.SetSyncMetrics(m)
	seedEverywhere(t, peers)
	beginOp1(t, a, `{"cpu":4}`)
	edit(t, b, `{"cpu":2,"labels":{"tier":"one"}}`)
	edit(t, b, `{"cpu":2,"labels":{"tier":"two"}}`)
	ea, eb := a.news(t), b.news(t)
	applyWAL(t, a.r, eb)
	applyWAL(t, b.r, ea)
	mergeFrom(t, a, b)
	mergeFrom(t, a, b)
	waitSpecHold(t, "the held-line condition", func() bool {
		row, found := heldCondition(t, a)
		return found && row.Lifecycle == ConditionConfirmed
	})
	row, _ := heldCondition(t, a)
	if row.Severity != SeverityWarning || !strings.Contains(row.Evidence, `"operation":"op-1"`) ||
		!strings.Contains(row.Evidence, `"owner":"n1"`) || !strings.Contains(row.Evidence, "lv operation abort vm1 --force") {
		t.Errorf("condition = %+v; want a warning naming op-1, its owner n1 and the remedy", row)
	}
	m.mu.Lock()
	held := m.specEditHeld
	m.mu.Unlock()
	if held != 1 {
		t.Errorf("two held passes counted %d holds, want 1", held)
	}
	if ok, err := a.c.CompleteVMOperation(context.Background(), "vm1", "op-1", 0, 1); err != nil || !ok {
		t.Fatalf("CompleteVMOperation: %v %v", ok, err)
	}
	mergeFrom(t, a, b)
	if got := vmSpecOn(t, a); !strings.Contains(got.Spec, `"tier":"two"`) {
		t.Fatalf("premise: the line did not apply after completion: %s", got.Spec)
	}
	waitSpecHold(t, "the held-line condition to resolve", func() bool {
		row, found := heldCondition(t, a)
		return found && row.Lifecycle == ConditionResolved
	})
}

// m1: a resize claims cpu=4, and b's cut-off deploy writes the same cpu=4
// (X1), then labels (X2). X2's lineage names content equal to the claim's,
// but it does not descend from the claim: the running operation's barrier
// still holds it off.
//
// Red on 0421249e: the content-hash lineage exemption let X2 clear op-1.
func TestSpecConflictAE_AnEqualContentLineDoesNotPassARunningOperation(t *testing.T) {
	peers := newSpecPeers(t, true, "a", "b")
	a, b := peers[0], peers[1]
	seedEverywhere(t, peers)
	beginOp1(t, a, `{"cpu":4}`)
	edit(t, b, `{"cpu":4}`)
	edit(t, b, `{"cpu":4,"labels":{"tier":"two"}}`)
	ea, eb := a.news(t), b.news(t)
	applyWAL(t, a.r, eb)
	applyWAL(t, b.r, ea)
	mergeFrom(t, a, b)
	if got := vmSpecOn(t, a); got.ActiveOperationID != "op-1" {
		t.Fatalf("the owner lost op-1's barrier to an equal-content line: %s", got.Spec)
	}
	if ok, err := a.c.CompleteVMOperation(context.Background(), "vm1", "op-1", 0, 1); err != nil || !ok {
		t.Fatalf("CompleteVMOperation: %v %v", ok, err)
	}
}

// m2: the production pull is the PAGED stream, whose manifest carries no
// operation_steps. r holds op-1's claim; b holds the longer line and has
// heard op-1 complete. Paged anti-entropy from b brings the terminal step at
// rank 3, and the next pass applies the line: r converges, and its hold
// condition resolves.
func TestSpecConflictAE_PagedPullReleasesTheHoldOnceTheOperationEnds(t *testing.T) {
	peers := newSpecPeers(t, true, "a", "b", "r")
	a, b, r := peers[0], peers[1], peers[2]
	seedEverywhere(t, peers)
	beginOp1(t, a, `{"cpu":4}`)
	edit(t, b, `{"cpu":2,"labels":{"tier":"one"}}`)
	edit(t, b, `{"cpu":2,"labels":{"tier":"two"}}`)
	begin := a.news(t)
	applyWAL(t, r.r, begin)
	if ok, err := a.c.CompleteVMOperation(context.Background(), "vm1", "op-1", 0, 1); err != nil || !ok {
		t.Fatalf("CompleteVMOperation: %v %v", ok, err)
	}
	applyWAL(t, b.r, begin)
	applyWAL(t, b.r, a.news(t))
	for i := 0; i < 2; i++ {
		mergePaged(t, r.c, b.c)
	}
	if got := vmSpecOn(t, r); !strings.Contains(got.Spec, `"tier":"two"`) || got.ActiveOperationID != "" || got.SpecGeneration != 2 {
		t.Fatalf("r after two paged passes: %s@%d, barrier %q; want b's line", got.Spec, got.SpecGeneration, got.ActiveOperationID)
	}
	waitSpecHold(t, "r's hold to be resolved, if it was raised", func() bool {
		row, found := heldCondition(t, r)
		return !found || row.Lifecycle == ConditionResolved
	})
}

// m3: a drop whose event cannot be written (here: the node is quarantined)
// is not marked noted, so the next pass that drops it records it.
//
// Red on 0421249e: the drop was marked before the insert, so it was never
// recorded.
func TestSpecConflictAE_ADropWhoseEventFailedIsRecordedLater(t *testing.T) {
	peers := newSpecPeers(t, true, "a", "b")
	a, b := peers[0], peers[1]
	seedEverywhere(t, peers)
	edit(t, b, `{"cpu":2,"labels":{"tier":"front"}}`)
	edit(t, a, `{"cpu":4}`) // a's is the later edit: a keeps it, dropping b's
	var quarantined atomic.Bool
	quarantined.Store(true)
	a.c.SetWriteQuarantine(func() string {
		if quarantined.Load() {
			return "test"
		}
		return ""
	})
	mergeFrom(t, a, b)
	time.Sleep(200 * time.Millisecond) // the failed insert
	quarantined.Store(false)
	mergeFrom(t, a, b)
	if n := eventsQuoting(t, a, "tier"); n != 1 {
		t.Errorf("a recorded b's dropped edit %d times after the failed insert, want once", n)
	}
}
