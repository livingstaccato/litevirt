package daemon

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// journalAgedCompletedOp journals a finished operation on vm, aged past any
// retention, so the reaper owes it a tombstone.
func journalAgedCompletedOp(t *testing.T, db *corrosion.Client, vm, id string) {
	t.Helper()
	ctx := context.Background()
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{Name: vm, HostName: "h1", State: "running", Spec: "{}"}, nil, nil); err != nil {
		t.Fatalf("InsertVM %s: %v", vm, err)
	}
	op := corrosion.OperationRecord{ID: id, Method: "UpdateVM", ResourceKind: "vm", ResourceID: vm,
		OperationKind: string(corrosion.OpResourceUpdateRunning), RequestHash: "h"}
	if _, err := db.BeginVMOperation(ctx, op, `{"cpu":2}`, 0, 0); err != nil {
		t.Fatalf("begin %s: %v", id, err)
	}
	if _, err := db.CompleteVMOperation(ctx, vm, id, 0, 1); err != nil {
		t.Fatalf("complete %s: %v", id, err)
	}
	if _, err := db.DB().Exec(`UPDATE operation_steps SET updated_at = '2020-01-01T00:00:00Z' WHERE operation_id = ?`, id); err != nil {
		t.Fatalf("age %s: %v", id, err)
	}
}

// An operation the reaper cannot reap is logged once per pass with its id and
// cause and raises operation_unreapable about this host, naming it and the
// remedy; the operations behind it are still reaped; the condition resolves on
// the first complete pass with no failure, and an incomplete pass never
// resolves it.
func TestReapTerminalOperations_UnreapableRaisesAndResolvesACondition(t *testing.T) {
	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	ctx := context.Background()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	d := &Daemon{db: db, cfg: &Config{HostName: "h1"}}
	journalAgedCompletedOp(t, db, "vm1", "op-a-poisoned")
	journalAgedCompletedOp(t, db, "vm2", "op-b-reapable")
	if _, err := db.DB().Exec(`CREATE TRIGGER poison_reap BEFORE UPDATE OF deleted_at ON operations
		WHEN OLD.id = 'op-a-poisoned' BEGIN SELECT RAISE(ABORT, 'poisoned tombstone'); END`); err != nil {
		t.Fatal(err)
	}

	cond := func() corrosion.HealthCondition {
		t.Helper()
		row, _, err := corrosion.GetHealthCondition(ctx, db, operationReaperEvaluator, CondOperationUnreapable, "host", "h1")
		if err != nil {
			t.Fatal(err)
		}
		return row
	}

	d.reapTerminalOperations(ctx, time.Hour)
	if got, _ := corrosion.GetOperation(ctx, db, "op-b-reapable"); got != nil {
		t.Error("the reapable operation behind the failing one was not reaped")
	}
	if n := strings.Count(logs.String(), "operation_id=op-a-poisoned"); n != 1 ||
		!strings.Contains(logs.String(), "poisoned tombstone") {
		t.Errorf("want one warning naming op-a-poisoned and its cause, got %d in:\n%s", n, logs.String())
	}
	row := cond()
	if row.Lifecycle != corrosion.ConditionConfirmed || row.Severity != corrosion.SeverityWarning ||
		!strings.Contains(row.Evidence, `"id":"op-a-poisoned"`) || !strings.Contains(row.Evidence, "poisoned tombstone") ||
		!strings.Contains(row.Evidence, `"remedy"`) || strings.Contains(row.Evidence, "op-b-reapable") {
		t.Fatalf("condition = %+v; want a confirmed warning naming only op-a-poisoned, its cause and the remedy", row)
	}

	// A pass that ends early (writes quarantined) proves nothing: it must not
	// resolve the open condition.
	if _, err := db.DB().Exec(`DROP TRIGGER poison_reap`); err != nil {
		t.Fatal(err)
	}
	// Quarantined for the first tombstone write (asked once, on entry) and the
	// reaper's own check after it; lifted after that, so a condition write the
	// daemon wrongly attempted would land and show.
	asked := 0
	db.SetWriteQuarantine(func() string {
		if asked++; asked <= 2 {
			return "test quarantine"
		}
		return ""
	})
	d.reapTerminalOperations(ctx, time.Hour)
	if asked < 2 {
		t.Fatalf("quarantine asked %d times; the pass did not reach a tombstone write", asked)
	}
	if row := cond(); row.Lifecycle != corrosion.ConditionConfirmed {
		t.Errorf("an incomplete pass resolved the condition: %+v", row)
	}

	db.SetWriteQuarantine(nil)
	d.reapTerminalOperations(ctx, time.Hour)
	if got, _ := corrosion.GetOperation(ctx, db, "op-a-poisoned"); got != nil {
		t.Error("the formerly poisoned operation was not reaped once its write could succeed")
	}
	if row := cond(); row.Lifecycle != corrosion.ConditionResolved {
		t.Errorf("condition after a clean pass = %+v; want resolved", row)
	}
}
