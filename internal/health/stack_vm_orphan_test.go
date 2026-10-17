package health

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// orphanStackDB has stack "st", torn down at tornDown, and VM web recording
// it, created at createdAt.
func orphanStackDB(t *testing.T, createdAt, tornDown time.Time) *corrosion.Client {
	t.Helper()
	ctx := context.Background()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpsertStack(ctx, db, corrosion.StackRecord{Name: "st", ComposeYAML: "name: st\n", State: "active"}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{Name: "web", StackName: "st", HostName: "node-2", State: "running", Spec: "{}"}, nil, nil); err != nil {
		t.Fatal(err)
	}
	exec := func(q string, args ...any) {
		if _, err := db.DB().ExecContext(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`UPDATE vms SET created_at = ? WHERE name = 'web'`, createdAt.UTC().Format(time.RFC3339Nano))
	exec(`UPDATE stacks SET deleted_at = ?, state = 'deleted' WHERE name = 'st'`, tornDown.UTC().Format(time.RFC3339))
	return db
}

func outlivedCondition(t *testing.T, db *corrosion.Client) (corrosion.HealthCondition, bool) {
	t.Helper()
	row, found, err := corrosion.GetHealthCondition(context.Background(), db, stackVMOrphanEvaluator, stackVMOrphanCode, stackVMOrphanKind, "web")
	if err != nil {
		t.Fatal(err)
	}
	return row, found && row.Lifecycle != corrosion.ConditionResolved
}

// Review I-1: a VM that recorded a stack when the stack was torn down, and
// that the teardown did not delete (another incarnation than it listed), is
// reported with the remedy; it resolves once the VM is gone.
//
// Mutation: drop the report from the pass — red.
func TestStackReconciler_ReportsAVMThatOutlivedItsStack(t *testing.T) {
	now := time.Now()
	db := orphanStackDB(t, now.Add(-time.Minute), now)
	r := NewStackReconciler("node-2", db)
	r.SetCleaner(&recordingStackCleaner{})
	r.ReconcileOnce(context.Background())
	row, open := outlivedCondition(t, db)
	if !open {
		t.Fatal("no condition for web, which outlived stack st's teardown")
	}
	var ev stackVMOrphanEvidence
	if err := json.Unmarshal([]byte(row.Evidence), &ev); err != nil {
		t.Fatal(err)
	}
	if ev.Stack != "st" || ev.Host != "node-2" || !strings.Contains(ev.Detail, "lv rm web") || !strings.Contains(ev.Detail, "lv compose up") {
		t.Errorf("evidence = %+v, want stack st, host node-2 and the remedy", ev)
	}
	if row.Severity != corrosion.SeverityWarning {
		t.Errorf("severity = %q, want warning", row.Severity)
	}

	if err := corrosion.DeleteVM(context.Background(), db, "web"); err != nil {
		t.Fatal(err)
	}
	r.ReconcileOnce(context.Background())
	if _, open := outlivedCondition(t, db); open {
		t.Error("the condition stayed open after the VM was deleted")
	}
}

// Deployed again, the stack takes the VM back: the condition resolves.
func TestStackReconciler_AVMOfAStackDeployedAgainIsNotReported(t *testing.T) {
	now := time.Now()
	db := orphanStackDB(t, now.Add(-time.Minute), now)
	r := NewStackReconciler("node-2", db)
	r.SetCleaner(&recordingStackCleaner{})
	r.ReconcileOnce(context.Background())
	if _, open := outlivedCondition(t, db); !open {
		t.Fatal("setup: no condition")
	}
	if err := corrosion.UpsertStack(context.Background(), db, corrosion.StackRecord{Name: "st", ComposeYAML: "name: st\n", State: "active"}); err != nil {
		t.Fatal(err)
	}
	r.ReconcileOnce(context.Background())
	if _, open := outlivedCondition(t, db); open {
		t.Error("the condition stayed open after the stack was deployed again")
	}
}

// A VM created after the teardown is a deploy of the same stack name in
// progress (the deploy writes the stack's record after its VMs): not
// reported.
//
// Mutation: report every live VM of a tombstoned stack — red.
func TestStackReconciler_AVMCreatedAfterTheTeardownIsNotReported(t *testing.T) {
	now := time.Now()
	db := orphanStackDB(t, now.Add(5*time.Second), now)
	r := NewStackReconciler("node-2", db)
	r.SetCleaner(&recordingStackCleaner{})
	r.ReconcileOnce(context.Background())
	if _, open := outlivedCondition(t, db); open {
		t.Error("a VM created after its stack's teardown (a deploy in progress) was reported")
	}
}

// Lab 2 2026-10-17, F2: on a host other than the VM's, a live row of a
// torn-down stack's VM may be a member whose tombstone has not replicated
// yet: the stack's tombstone came from the host that finished the teardown,
// the member's from its owner. Only the VM's own host judges it, and a
// condition its host raised is not resolved by a host that sees the VM too.
//
// Mutation: drop the own-host check — red.
func TestStackReconciler_AVMOnAnotherHostIsJudgedByItsHost(t *testing.T) {
	now := time.Now()
	db := orphanStackDB(t, now.Add(-time.Minute), now)
	elsewhere := NewStackReconciler("node-0", db)
	elsewhere.SetCleaner(&recordingStackCleaner{})
	elsewhere.ReconcileOnce(context.Background())
	if _, open := outlivedCondition(t, db); open {
		t.Fatal("node-0 reported web, which is node-2's VM: a live row here may be a delete not yet replicated")
	}

	own := NewStackReconciler("node-2", db)
	own.SetCleaner(&recordingStackCleaner{})
	own.ReconcileOnce(context.Background())
	if _, open := outlivedCondition(t, db); !open {
		t.Fatal("setup: node-2 did not report its own VM")
	}
	elsewhere.ReconcileOnce(context.Background())
	if _, open := outlivedCondition(t, db); !open {
		t.Error("node-0 resolved the condition while its replica still shows web outliving stack st")
	}
}

// Re-review 4 m-2: a host whose replica is not trusted (back from a fence,
// say) raises nothing, as its row may name it the host of a VM rekeyed
// away; it still leaves the condition its peers see open. Once trusted, it
// raises.
//
// Mutation: drop the trust gate on the raise — red. Gate the resolve as
// well — the stale host leaves a resolved VM's condition open, red.
func TestStackReconciler_AnUntrustedReplicaRaisesNothing(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	db := orphanStackDB(t, now.Add(-time.Minute), now)
	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{Name: "node-0", Address: "10.0.0.1", State: "active"}); err != nil {
		t.Fatal(err)
	}
	caught := false
	r := NewStackReconciler("node-2", db)
	r.SetCleaner(&recordingStackCleaner{})
	r.SetReplicaFreshness(func() (bool, string) { return caught, "not yet caught up (test)" })
	r.ReconcileOnce(ctx)
	if row, open := outlivedCondition(t, db); open {
		t.Fatalf("node-2 raised the condition from a replica not yet trusted: %s", row.Evidence)
	}

	caught = true
	r.ReconcileOnce(ctx)
	if _, open := outlivedCondition(t, db); !open {
		t.Fatal("node-2 did not raise the condition once its replica was trusted")
	}

	caught = false
	if err := corrosion.DeleteVM(ctx, db, "web"); err != nil {
		t.Fatal(err)
	}
	r.ReconcileOnce(ctx)
	if _, open := outlivedCondition(t, db); open {
		t.Error("an untrusted replica left open the condition of a VM it holds deleted")
	}
}
