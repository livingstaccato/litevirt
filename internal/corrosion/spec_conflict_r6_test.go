package corrosion

import (
	"context"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// m-new-1 of re-review 4: r holds op-1, confirmed. A pass from p, which is at
// r's generation and holds nothing, brings vm1's row unchanged and then, on a
// later page, op-1's terminal step. The end of that pass resolves r's hold,
// though the pass held nothing: a check made at vm1's row, before the step
// merged, would find op-1 still running.
func TestSpecHold_APassThatDeliversTheTerminalStepResolvesIt(t *testing.T) {
	r, p := heldOnWithBystander(t)
	ctx := context.Background()

	// p has heard op-1 finish, but its vms row is r's: the step alone.
	if _, err := p.c.db.ExecContext(ctx, insertTerminalStepSQL, OpStepCompleted, nowRFC3339(), p.c.NowTS()); err != nil {
		t.Fatal(err)
	}
	// vm1's row (a parent of the steps) merges on a page of its own, and
	// whatever it starts runs, before the step's page arrives: a table ranked
	// between the parents and the steps puts a page between them.
	withPageBounds(t, 2, 1<<20)
	if err := UpsertHealthCondition(ctx, p.c, HealthCondition{Evaluator: "test", Code: "test.rank2",
		SubjectKind: "host", SubjectID: "p", Lifecycle: ConditionObserved, Severity: SeverityInfo}); err != nil {
		t.Fatal(err)
	}
	pages := collectPages(t, p.c, []string{"health_conditions", "operation_steps"}, nil)
	next := replay(pages)
	recv := func() (*pb.TableRowsPage, error) {
		drainSpecHolds(r.c)
		return next()
	}
	if _, _, perr, merr := r.c.mergeTableRowsStream(recv, replicatedTableSet, nil); perr != nil || merr != nil {
		t.Fatalf("paged merge: pull=%v merge=%v", perr, merr)
	}
	drainSpecHolds(r.c)
	assertResolvedBehindABarrier(t, r)
}

// The end of a pass sweeps every open hold, not only those the pass held or
// streamed: here op-1's terminal step is already on r, and a pass of an
// unrelated table resolves the hold.
func TestSpecHold_EveryPassEndSweepsTheOpenHolds(t *testing.T) {
	r, p := heldOnWithBystander(t)
	ctx := context.Background()
	if _, err := r.c.db.ExecContext(ctx, insertTerminalStepSQL, OpStepCompleted, nowRFC3339(), r.c.NowTS()); err != nil {
		t.Fatal(err)
	}
	pages := collectPages(t, p.c, []string{"hosts"}, nil)
	if _, _, perr, merr := r.c.mergeTableRowsStream(replay(pages), replicatedTableSet, nil); perr != nil || merr != nil {
		t.Fatalf("paged merge: pull=%v merge=%v", perr, merr)
	}
	drainSpecHolds(r.c)
	assertResolvedBehindABarrier(t, r)
}

const insertTerminalStepSQL = `INSERT INTO operation_steps
	(operation_id, owner_epoch, step_name, facts, created_at, updated_at, deleted_at)
	VALUES ('op-1', 0, ?, '', ?, ?, NULL)`

// heldOnWithBystander is heldOn with a fourth peer p that heard op-1's claim
// and nothing of b's line: r holds op-1, confirmed; p holds nothing.
func heldOnWithBystander(t *testing.T) (r, p *specPeer) {
	t.Helper()
	peers := newSpecPeers(t, true, "a", "b", "r", "p")
	a, b, r, p := peers[0], peers[1], peers[2], peers[3]
	seedEverywhere(t, peers)
	beginOp1(t, a, `{"cpu":4}`)
	edit(t, b, `{"cpu":2,"labels":{"tier":"one"}}`)
	edit(t, b, `{"cpu":2,"labels":{"tier":"two"}}`)
	begin := a.news(t)
	applyWAL(t, r.r, begin)
	applyWAL(t, p.r, begin)
	b.news(t)
	mergeFrom(t, r, b)
	mergeFrom(t, r, b)
	drainSpecHolds(r.c)
	if row, found := heldCondition(t, r); !found || row.Lifecycle != ConditionConfirmed {
		t.Fatalf("premise: r's hold is %+v found=%v; want confirmed", row, found)
	}
	return r, p
}

func assertResolvedBehindABarrier(t *testing.T, r *specPeer) {
	t.Helper()
	ctx := context.Background()
	if rows, err := r.c.Query(ctx, `SELECT 1 AS one FROM operation_steps WHERE operation_id = 'op-1' AND step_name = ?`, OpStepCompleted); err != nil || len(rows) == 0 {
		t.Fatalf("premise: op-1's terminal step is not on r: %v", err)
	}
	if got := vmSpecOn(t, r); got.ActiveOperationID != "op-1" {
		t.Fatalf("premise: r's barrier is %q; want op-1 still standing", got.ActiveOperationID)
	}
	if row, found := heldCondition(t, r); !found || row.Lifecycle != ConditionResolved {
		t.Fatalf("after op-1's terminal step and a pass end: %+v found=%v; want resolved", row, found)
	}
}
