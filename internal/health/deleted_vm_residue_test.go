package health

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// webSetAside: web failed over off node-a, node-a is back and has set its real
// disk aside. It returns the copy and web's created_at.
func webSetAside(t *testing.T) (*corrosion.Client, *Reconciler, string, string) {
	t.Helper()
	db, _, r, _, _ := strandedFixture(t)
	ctx := context.Background()
	recordWeb(t, db, time.Now())
	r.tendStrandedDisks(ctx)
	_, ev, _ := strandedRow(t, db, "web", "node-a")
	if len(ev.Disks) != 1 || ev.Disks[0].Copy == "" || !fileExists(ev.Disks[0].Copy) {
		t.Fatalf("setup: %+v", ev)
	}
	vm, err := corrosion.GetVM(ctx, db, "web")
	if err != nil || vm == nil || vm.CreatedAt == "" {
		t.Fatalf("web: %+v, %v", vm, err)
	}
	if ev.Disks[0].Incarnation != vm.CreatedAt {
		t.Fatalf("the entry is recorded for incarnation %q, want web's %q", ev.Disks[0].Incarnation, vm.CreatedAt)
	}
	return db, r, ev.Disks[0].Copy, vm.CreatedAt
}

func fileExists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}

func strandedOpen(t *testing.T, db *corrosion.Client) bool {
	t.Helper()
	row, _, ok := strandedRow(t, db, "web", "node-a")
	return ok && row.Lifecycle != corrosion.ConditionResolved
}

// A decision left by a delete that failed long before the one that deleted
// the VM is not that delete's: the copy is kept, and once the wait for a
// decision is over the record is resolved with the copy still there.
//
// Mutation: drop the decision's timing check (decisionBefore) — the copy is
// removed on the stale decision.
func TestTendDeletedVMStranded_IgnoresAStaleDecision(t *testing.T) {
	db, r, cp, createdAt := webSetAside(t)
	ctx := context.Background()
	if err := NoteStrandedDisksDeleted(ctx, db, "node-b", "web", createdAt, false, time.Now().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.DeleteVM(ctx, db, "web"); err != nil {
		t.Fatal(err)
	}
	r.tendStrandedDisks(ctx)
	if !fileExists(cp) {
		t.Fatal("a stale decision removed the copy")
	}
	if !strandedOpen(t, db) {
		t.Fatal("the record was resolved before the wait for the delete's own decision was over")
	}
	r.Now = func() time.Time { return time.Now().Add(strandedDeletionWindow + time.Minute) }
	r.tendStrandedDisks(ctx)
	if !fileExists(cp) {
		t.Fatal("the copy was removed with no decision of the delete that deleted the VM")
	}
	if strandedOpen(t, db) {
		t.Fatal("the record is still open after the wait")
	}
}

// The delete's decision can reach a host after its tombstone. The host waits
// for it rather than resolving the record on the tombstone alone, and removes
// the copy when it arrives.
//
// Mutation: resolve on a tombstone with no decision at once — the decision
// arrives at a resolved record and the copy stays.
func TestTendDeletedVMStranded_WaitsForADecisionBehindTheTombstone(t *testing.T) {
	db, r, cp, createdAt := webSetAside(t)
	ctx := context.Background()
	if err := corrosion.DeleteVM(ctx, db, "web"); err != nil {
		t.Fatal(err)
	}
	r.tendStrandedDisks(ctx)
	if !fileExists(cp) || !strandedOpen(t, db) {
		t.Fatalf("with no decision yet: copy %v, record open %v; want both", fileExists(cp), strandedOpen(t, db))
	}
	if err := NoteStrandedDisksDeleted(ctx, db, "node-b", "web", createdAt, false, time.Now().Add(-2*time.Second)); err != nil {
		t.Fatal(err)
	}
	r.tendStrandedDisks(ctx)
	if fileExists(cp) {
		t.Fatal("the copy is still there after the delete's decision arrived")
	}
	if strandedOpen(t, db) {
		t.Fatal("the record is still open with nothing left")
	}
}
