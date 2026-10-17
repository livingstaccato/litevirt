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
	r := NewStackReconciler("node-0", db)
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
	r := NewStackReconciler("node-0", db)
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
	r := NewStackReconciler("node-0", db)
	r.SetCleaner(&recordingStackCleaner{})
	r.ReconcileOnce(context.Background())
	if _, open := outlivedCondition(t, db); open {
		t.Error("a VM created after its stack's teardown (a deploy in progress) was reported")
	}
}
