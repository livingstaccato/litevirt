package corrosion

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
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

// drainSpecHolds waits for c's in-flight raises and sweeps.
func drainSpecHolds(c *Client) { c.specHold.wg.Wait() }

func heldCount(m *fakeSyncMetrics) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.specEditHeld
}

// dropsIn is how many noted drops are in state st.
func dropsIn(c *Client, st specDropState) int {
	c.specDropsMu.Lock()
	defer c.specDropsMu.Unlock()
	n := 0
	for _, s := range c.specDropsSeen {
		if s == st {
			n++
		}
	}
	return n
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
	drainSpecHolds(a.c)
	if row, found := heldCondition(t, a); !found || row.Lifecycle != ConditionObserved || row.ConfirmedAt != "" {
		t.Fatalf("after one held pass: %+v found=%v; want observed", row, found)
	}
	if n := heldCount(m); n != 0 {
		t.Errorf("one held pass counted %d holds, want 0 until confirmed", n)
	}
	mergeFrom(t, a, b)
	mergeFrom(t, a, b)
	drainSpecHolds(a.c)
	row, found := heldCondition(t, a)
	if !found || row.Lifecycle != ConditionConfirmed {
		t.Fatalf("after three held passes: %+v found=%v; want confirmed", row, found)
	}
	if row.Severity != SeverityWarning || !strings.Contains(row.Evidence, `"operation":"op-1"`) ||
		!strings.Contains(row.Evidence, `"owner":"n1"`) || !strings.Contains(row.Evidence, "lv operation show vm1") ||
		!strings.Contains(row.Evidence, "lv operation abort vm1 --operation op-1 --force") {
		t.Errorf("condition = %+v; want a warning naming op-1, its owner n1 and the scoped remedy", row)
	}
	if n := heldCount(m); n != 1 {
		t.Errorf("three held passes counted %d holds, want 1", n)
	}
	if ok, err := a.c.CompleteVMOperation(context.Background(), "vm1", "op-1", 0, 1); err != nil || !ok {
		t.Fatalf("CompleteVMOperation: %v %v", ok, err)
	}
	mergeFrom(t, a, b)
	if got := vmSpecOn(t, a); !strings.Contains(got.Spec, `"tier":"two"`) {
		t.Fatalf("premise: the line did not apply after completion: %s", got.Spec)
	}
	drainSpecHolds(a.c)
	if row, found := heldCondition(t, a); !found || row.Lifecycle != ConditionResolved {
		t.Fatalf("after the line applied: %+v found=%v; want resolved", row, found)
	}
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
	m := &fakeSyncMetrics{}
	r.c.SetSyncMetrics(m)
	// I-1: r has merely not heard op-1 finish. Its first paged pass holds at
	// the vms row, and op-1's terminal step merges only on a later page. The
	// hold is judged once the pass has merged it, so nothing is raised, and
	// above all nothing confirmed: the remedy would have an operator abort an
	// operation that already finished. Every page is delivered only once
	// whatever the earlier pages started has run, so a judgement made before
	// the pass ended would show.
	withPageBounds(t, 2, 1<<20)
	// A table ranked between the parents and the steps, so the vms row
	// merges on a page of its own, ahead of the steps' page.
	if err := UpsertHealthCondition(context.Background(), b.c, HealthCondition{Evaluator: "test", Code: "test.rank2",
		SubjectKind: "host", SubjectID: "b", Lifecycle: ConditionObserved, Severity: SeverityInfo}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		pages := collectPages(t, b.c, tableNames, nil)
		next := replay(pages)
		recv := func() (*pb.TableRowsPage, error) {
			drainSpecHolds(r.c)
			return next()
		}
		if _, _, perr, merr := r.c.mergeTableRowsStream(recv, replicatedTableSet, nil); perr != nil || merr != nil {
			t.Fatalf("paged merge: pull=%v merge=%v", perr, merr)
		}
		drainSpecHolds(r.c)
		if i == 0 {
			if row, found := heldCondition(t, r); found {
				t.Fatalf("the first pass raised a hold of an operation it heard finish in that pass: %+v", row)
			}
		}
		if row, found := heldCondition(t, r); found && (row.Lifecycle == ConditionConfirmed || row.ConfirmedAt != "") {
			t.Fatalf("pass %d confirmed a hold of an operation that has finished: %+v", i+1, row)
		}
	}
	if got := vmSpecOn(t, r); !strings.Contains(got.Spec, `"tier":"two"`) || got.ActiveOperationID != "" || got.SpecGeneration != 2 {
		t.Fatalf("r after two paged passes: %s@%d, barrier %q; want b's line", got.Spec, got.SpecGeneration, got.ActiveOperationID)
	}
	if row, found := heldCondition(t, r); found && row.Lifecycle != ConditionResolved {
		t.Fatalf("r's hold is still open after the line applied: %+v", row)
	}
	if n := heldCount(m); n != 0 {
		t.Errorf("a hold of a finished operation was warned and counted %d times, want 0", n)
	}
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
	m := &fakeSyncMetrics{}
	a.c.SetSyncMetrics(m)
	var quarantined atomic.Bool
	quarantined.Store(true)
	a.c.SetWriteQuarantine(func() string {
		if quarantined.Load() {
			return "test"
		}
		return ""
	})
	mergeFrom(t, a, b)
	waitSpecHold(t, "the failed insert", func() bool { return dropsIn(a.c, specDropUnrecorded) == 1 })
	mergeFrom(t, a, b) // still quarantined: retried, fails again
	waitSpecHold(t, "the second failed insert", func() bool { return dropsIn(a.c, specDropUnrecorded) == 1 })
	quarantined.Store(false)
	mergeFrom(t, a, b)
	waitSpecHold(t, "the recorded insert", func() bool { return dropsIn(a.c, specDropRecorded) == 1 })
	if n := eventsQuoting(t, a, "tier"); n != 1 {
		t.Errorf("a recorded b's dropped edit %d times after the failed insert, want once", n)
	}
	// m6: the write is retried, the warning and the counter are not.
	m.mu.Lock()
	rejected := len(m.mergeRejected)
	m.mu.Unlock()
	if rejected != 1 {
		t.Errorf("one drop counted %d times across failed writes, want once", rejected)
	}
}
