package corrosion

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// heldOn sets up the review's hold on r: a (owner n1) claims op-1, r hears
// the claim, b makes a longer line, and r pulls b's line twice — a confirmed
// hold of op-1 on r.
func heldOn(t *testing.T) (a, b, r *specPeer) {
	t.Helper()
	peers := newSpecPeers(t, true, "a", "b", "r")
	a, b, r = peers[0], peers[1], peers[2]
	seedEverywhere(t, peers)
	beginOp1(t, a, `{"cpu":4}`)
	edit(t, b, `{"cpu":2,"labels":{"tier":"one"}}`)
	edit(t, b, `{"cpu":2,"labels":{"tier":"two"}}`)
	applyWAL(t, r.r, a.news(t))
	b.news(t)
	mergeFrom(t, r, b)
	mergeFrom(t, r, b)
	drainSpecHolds(r.c)
	if row, found := heldCondition(t, r); !found || row.Lifecycle != ConditionConfirmed {
		t.Fatalf("premise: r's hold is %+v found=%v; want confirmed", row, found)
	}
	return a, b, r
}

// m1 of re-review 3: the owner's clear, arriving over the WAL, resolves the
// condition with no further anti-entropy pass.
func TestSpecHold_AClearOverTheWALResolvesIt(t *testing.T) {
	a, _, r := heldOn(t)
	if ok, err := a.c.CompleteVMOperation(context.Background(), "vm1", "op-1", 0, 1); err != nil || !ok {
		t.Fatalf("CompleteVMOperation: %v %v", ok, err)
	}
	applyWAL(t, r.r, a.news(t))
	drainSpecHolds(r.c)
	if row, found := heldCondition(t, r); !found || row.Lifecycle != ConditionResolved {
		t.Fatalf("after the clear over the WAL: %+v found=%v; want resolved", row, found)
	}
}

// m4: the owner aborts op-1 and deletes the VM while r is cut off; r hears
// only the tombstoned row, by anti-entropy. Its condition resolves.
func TestSpecHold_AVMDeletedResolvesIt(t *testing.T) {
	a, _, r := heldOn(t)
	ctx := context.Background()
	if ok, err := a.c.AbortVMOperation(ctx, "vm1", "op-1", 0, 1); err != nil || !ok {
		t.Fatalf("AbortVMOperation: %v %v", ok, err)
	}
	if err := DeleteVM(ctx, a.c, "vm1"); err != nil {
		t.Fatal(err)
	}
	mergeFrom(t, r, a)
	drainSpecHolds(r.c)
	if row, found := heldCondition(t, r); !found || row.Lifecycle != ConditionResolved {
		t.Fatalf("after the VM was deleted: %+v found=%v; want resolved", row, found)
	}
}

// m4: a removed host never resolves what it raised; ResolveSpecEditHeldOfHost
// does, and only that host's.
func TestSpecHold_ResolveOfARemovedHost(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	for _, subject := range []string{"vm1@gone", "vm1@kept", "vm2@xgone"} {
		if err := UpsertHealthCondition(ctx, c, HealthCondition{Evaluator: specHoldEvaluator, Code: SpecEditHeldCode,
			SubjectKind: "vm", SubjectID: subject, Lifecycle: ConditionConfirmed, Severity: SeverityWarning}); err != nil {
			t.Fatal(err)
		}
	}
	if err := ResolveSpecEditHeldOfHost(ctx, c, "gone"); err != nil {
		t.Fatal(err)
	}
	for subject, want := range map[string]string{"vm1@gone": ConditionResolved, "vm1@kept": ConditionConfirmed, "vm2@xgone": ConditionConfirmed} {
		row, _, err := GetHealthCondition(ctx, c, specHoldEvaluator, SpecEditHeldCode, "vm", subject)
		if err != nil || row.Lifecycle != want {
			t.Errorf("%s: %q %v; want %s", subject, row.Lifecycle, err, want)
		}
	}
}

// m5 / I-1: every held pass names the row's host as it is now, not the one
// the first pass saw.
func TestSpecHold_TheOwnerNamedFollowsTheRow(t *testing.T) {
	_, b, r := heldOn(t)
	if _, err := r.c.db.ExecContext(context.Background(), `UPDATE vms SET host_name = 'n9' WHERE name = 'vm1'`); err != nil {
		t.Fatal(err)
	}
	mergeFrom(t, r, b)
	drainSpecHolds(r.c)
	row, found := heldCondition(t, r)
	if !found || row.Lifecycle != ConditionConfirmed || !strings.Contains(row.Evidence, `"owner":"n9"`) ||
		!strings.Contains(row.Evidence, "on n9,") || len(row.Hosts) != 1 || row.Hosts[0] != "n9" {
		t.Fatalf("after the owner moved to n9: %+v; want it named", row)
	}
}

// m2: a raise that read the row as held, and the owner's clear arriving
// before the raise writes, never leave a stale condition open: the resolve
// that follows the clear waits for the raise and then resolves.
func TestSpecHold_ARaiseAndTheResolveAfterTheClearDoNotInvert(t *testing.T) {
	peers := newSpecPeers(t, true, "a", "b", "r")
	a, b, r := peers[0], peers[1], peers[2]
	seedEverywhere(t, peers)
	beginOp1(t, a, `{"cpu":4}`)
	edit(t, b, `{"cpu":2,"labels":{"tier":"one"}}`)
	edit(t, b, `{"cpu":2,"labels":{"tier":"two"}}`)
	applyWAL(t, r.r, a.news(t))
	mergeFrom(t, r, b)
	drainSpecHolds(r.c)

	swept := make(chan struct{}, 8)
	r.c.specHold.swept = func() { swept <- struct{}{} }
	var fired atomic.Bool
	var hookErr atomic.Value
	r.c.specHold.beforeWrite = func(string) {
		if !fired.CompareAndSwap(false, true) {
			return
		}
		if ok, err := a.c.CompleteVMOperation(context.Background(), "vm1", "op-1", 0, 1); err != nil || !ok {
			hookErr.Store(fmt.Sprintf("CompleteVMOperation: %v %v", ok, err))
			return
		}
		rows, err := a.c.Query(context.Background(), `SELECT seq, hlc, stmts FROM mutation_log ORDER BY seq`)
		if err != nil {
			hookErr.Store(err.Error())
			return
		}
		var entries []*pb.MutationEntry
		for _, row := range rows[a.sent:] {
			entries = append(entries, &pb.MutationEntry{Seq: int64(row.Int("seq")), Hlc: row.String("hlc"),
				Origin: a.name, Stmts: row.String("stmts")})
		}
		if _, err := r.r.ApplyRemoteMutations(context.Background(), entries); err != nil {
			hookErr.Store(err.Error())
			return
		}
		// Give the resolve the clear queued every chance to run first. It
		// must wait for this raise.
		select {
		case <-swept:
		case <-time.After(300 * time.Millisecond):
		}
	}
	mergeFrom(t, r, b) // the second held pass: the raise to confirmed
	drainSpecHolds(r.c)
	if e := hookErr.Load(); e != nil {
		t.Fatal(e)
	}
	if !fired.Load() {
		t.Fatal("premise: the second pass did not raise")
	}
	if row, found := heldCondition(t, r); !found || row.Lifecycle != ConditionResolved {
		t.Fatalf("after a raise and the clear's resolve crossed: %+v found=%v; want resolved", row, found)
	}
}

// m3: an anti-entropy pass over many VMs, none of them held, reads no
// condition and starts nothing; one that ends a hold reads the open
// conditions once.
func TestSpecHold_APassReadsTheConditionsAtMostOnce(t *testing.T) {
	a, b, r := heldOn(t)
	ctx := context.Background()
	for i := 2; i <= 20; i++ {
		seedVM(t, a.c, fmt.Sprintf("vm%d", i), `{"cpu":2}`)
	}
	e := a.news(t)
	applyWAL(t, b.r, e)
	applyWAL(t, r.r, e)
	for i := 2; i <= 20; i++ {
		if applied, _, err := MutateDesiredSpec(ctx, b.c, fmt.Sprintf("vm%d", i), func(string) (string, error) {
			return `{"cpu":3}`, nil
		}); err != nil || !applied {
			t.Fatalf("edit vm%d: %v %v", i, applied, err)
		}
	}
	var reads atomic.Int64
	r.c.specHold.listed = func() { reads.Add(1) }
	mergeFrom(t, r, b) // vm1 still held; vm2..vm20 take b's edits
	drainSpecHolds(r.c)
	if n := reads.Load(); n != 0 {
		t.Errorf("a pass that ended no hold read the conditions %d times, want 0", n)
	}
	if ok, err := a.c.CompleteVMOperation(ctx, "vm1", "op-1", 0, 1); err != nil || !ok {
		t.Fatalf("CompleteVMOperation: %v %v", ok, err)
	}
	applyWAL(t, b.r, a.news(t))
	for i := 2; i <= 20; i++ {
		if applied, _, err := MutateDesiredSpec(ctx, b.c, fmt.Sprintf("vm%d", i), func(string) (string, error) {
			return `{"cpu":5}`, nil
		}); err != nil || !applied {
			t.Fatalf("edit vm%d: %v %v", i, applied, err)
		}
	}
	reads.Store(0)
	mergeFrom(t, r, b)
	drainSpecHolds(r.c)
	if n := reads.Load(); n != 1 {
		t.Errorf("a pass that ended one hold, over 20 VMs, read the conditions %d times, want 1", n)
	}
	if row, found := heldCondition(t, r); !found || row.Lifecycle != ConditionResolved {
		t.Fatalf("premise: %+v found=%v; want resolved", row, found)
	}
}

// m6: while the condition cannot be written, every held pass retries the
// write, but the hold is warned and counted once.
func TestSpecHold_AFailingWriteIsNotCountedAgain(t *testing.T) {
	peers := newSpecPeers(t, true, "a", "b", "r")
	a, b, r := peers[0], peers[1], peers[2]
	seedEverywhere(t, peers)
	beginOp1(t, a, `{"cpu":4}`)
	edit(t, b, `{"cpu":2,"labels":{"tier":"one"}}`)
	edit(t, b, `{"cpu":2,"labels":{"tier":"two"}}`)
	applyWAL(t, r.r, a.news(t))
	m := &fakeSyncMetrics{}
	r.c.SetSyncMetrics(m)
	var quarantined atomic.Bool
	quarantined.Store(true)
	r.c.SetWriteQuarantine(func() string {
		if quarantined.Load() {
			return "test"
		}
		return ""
	})
	for i := 0; i < 4; i++ {
		mergeFrom(t, r, b)
		drainSpecHolds(r.c)
	}
	if _, found := heldCondition(t, r); found {
		t.Fatal("premise: the condition was written under quarantine")
	}
	if n := heldCount(m); n != 1 {
		t.Errorf("four held passes with the write failing counted %d holds, want 1", n)
	}
	quarantined.Store(false)
	mergeFrom(t, r, b)
	drainSpecHolds(r.c)
	if row, found := heldCondition(t, r); !found || row.Lifecycle != ConditionConfirmed {
		t.Fatalf("once writes work: %+v found=%v; want confirmed", row, found)
	}
	if n := heldCount(m); n != 1 {
		t.Errorf("the retried write counted the hold again: %d, want 1", n)
	}
}
