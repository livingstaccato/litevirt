package health

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// setStackUpdatedAt stamps the stack row's updated_at, the time its teardown
// began (SetStackState "deleting").
func setStackUpdatedAt(t *testing.T, db *corrosion.Client, name string, at time.Time) {
	t.Helper()
	if _, err := db.DB().ExecContext(context.Background(),
		`UPDATE stacks SET updated_at = ? WHERE name = ?`, at.UTC().Format(time.RFC3339Nano), name); err != nil {
		t.Fatal(err)
	}
}

// Lab 2 2026-10-17, anomaly 2: compose down marks the stack "deleting" before
// it deletes anything, and a reconciler on another host took the teardown up
// 0.1 s later and raced it member by member. A teardown that began less than
// stackTeardownGrace ago is left to the compose down running it; an older one
// is finished as before.
//
// Mutation: drop the in-flight skip — the fresh stack's VM is deleted, red.
func TestStackReconciler_LeavesATeardownInFlight(t *testing.T) {
	db := seedDeletingStack(t, true, false)
	now := time.Now()
	setStackUpdatedAt(t, db, "app", now)
	c := &recordingStackCleaner{}
	r := NewStackReconciler("node-0", db)
	r.SetCleaner(c)
	r.now = func() time.Time { return now }
	r.reconcile(context.Background())
	if len(c.vmReqs) != 0 {
		t.Fatalf("the reconciler deleted %d VMs of a teardown that began just now", len(c.vmReqs))
	}

	setStackUpdatedAt(t, db, "app", now.Add(-61*time.Second))
	r.reconcile(context.Background())
	if len(c.vmReqs) != 1 {
		t.Fatalf("VM deletes = %d of a teardown that began 61 s ago, want 1", len(c.vmReqs))
	}
}

// The age is read from a timestamp another host's clock wrote. One running
// ahead of this host's keeps the stamp young for longer than the grace; the
// reconciler still takes the teardown once it has itself seen the same stamp
// for the grace, so no clock skew strands a stack in "deleting".
//
// Mutation: judge by the stamp alone — the stack stays untouched, red.
func TestStackReconciler_TakesAStuckTeardownWhateverTheStampSays(t *testing.T) {
	db := seedDeletingStack(t, true, false)
	now := time.Now()
	setStackUpdatedAt(t, db, "app", now.Add(time.Hour)) // the coordinator's clock is an hour ahead
	c := &recordingStackCleaner{}
	r := NewStackReconciler("node-0", db)
	r.SetCleaner(c)
	r.now = func() time.Time { return now }
	r.reconcile(context.Background())
	if len(c.vmReqs) != 0 {
		t.Fatalf("first sighting: %d VM deletes, want none", len(c.vmReqs))
	}
	now = now.Add(stackTeardownGrace)
	r.reconcile(context.Background())
	if len(c.vmReqs) != 1 {
		t.Fatalf("VM deletes = %d after the teardown sat a grace unchanged, want 1", len(c.vmReqs))
	}
}

// A teardown begun again (a second compose down) restarts the grace: the new
// stamp is a new teardown in flight.
func TestStackReconciler_ATeardownBegunAgainRestartsTheGrace(t *testing.T) {
	db := seedDeletingStack(t, true, false)
	now := time.Now()
	setStackUpdatedAt(t, db, "app", now.Add(time.Hour))
	c := &recordingStackCleaner{}
	r := NewStackReconciler("node-0", db)
	r.SetCleaner(c)
	r.now = func() time.Time { return now }
	r.reconcile(context.Background())
	now = now.Add(stackTeardownGrace / 2)
	setStackUpdatedAt(t, db, "app", now.Add(time.Hour).Add(time.Second))
	r.reconcile(context.Background())
	now = now.Add(stackTeardownGrace / 2)
	r.reconcile(context.Background())
	if len(c.vmReqs) != 0 {
		t.Fatalf("VM deletes = %d, want none: the teardown began again %v ago", len(c.vmReqs), stackTeardownGrace/2)
	}
	now = now.Add(stackTeardownGrace / 2)
	r.reconcile(context.Background())
	if len(c.vmReqs) != 1 {
		t.Fatalf("VM deletes = %d a grace after the second teardown began, want 1", len(c.vmReqs))
	}
}
