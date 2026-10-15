package fleet

import "testing"

// Staged catch-up must share admission's atomic application boundary. A failed
// prefix write cannot leave new history, receipt or anchor state committed.
func TestAutomationReplayStagedApplicationRollback(t *testing.T) {
	f := NewAutomationFixture(t, 3)
	f.Isolate(2)
	for _, id := range []string{"staged-two", "staged-three"} {
		if _, err := f.Engine(0).Submit(f.Context(), f.Barrier(0, id)); err != nil {
			t.Fatal(err)
		}
	}
	n := f.cluster.Nodes[2]
	before := f.Head(t, 2)
	record, found, err := f.cluster.Nodes[0].DB.AutomationRecord(f.Context(), 3)
	if err != nil || !found {
		t.Fatal(err)
	}
	if err := localExec(f.Context(), n.DB, `CREATE TRIGGER fail_staged_prefix BEFORE INSERT ON local_automation_prefix WHEN NEW.sequence>1 BEGIN SELECT RAISE(ABORT,'staged prefix failure'); END`); err != nil {
		t.Fatal(err)
	}
	f.Heal(2)
	if err := f.Engine(2).Install(f.Context(), record); err == nil {
		t.Fatal("staged application ignored transactional failure")
	}
	if h := f.Head(t, 2); h != before {
		t.Fatalf("failed staged prefix advanced: %+v", h)
	}
	for _, table := range []string{"local_automation_history", "local_automation_anchors"} {
		rows, err := n.DB.Query(f.Context(), "SELECT count(*) AS n FROM "+table+" WHERE sequence>1")
		if err != nil || rows[0].Int64("n") != 0 {
			t.Fatalf("%s leaked staged application: %v", table, err)
		}
	}
	rows, err := n.DB.Query(f.Context(), `SELECT count(*) AS n FROM local_automation_requests`)
	if err != nil || rows[0].Int64("n") != 1 {
		t.Fatalf("failed staged application retained receipt: %v", err)
	}
	if pending, err := n.DB.AutomationRecoveryPending(f.Context()); err != nil || !pending {
		t.Fatalf("failed recovery lost resumable checkpoint: %v", err)
	}
	if err := localExec(f.Context(), n.DB, `DROP TRIGGER fail_staged_prefix`); err != nil {
		t.Fatal(err)
	}
	if err := f.Engine(2).Recover(f.Context()); err != nil {
		t.Fatalf("staged application did not resume: %v", err)
	}
	f.Converge(t)
}
