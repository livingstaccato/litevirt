package health

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// keepDisksStack seeds a stack with one VM, app-web, and marks it "deleting"
// the way DeleteStack does: with the teardown's disk choice when
// cluster_policies may be written (gate). The stamp is then aged past the
// in-flight grace by the reconciler's clock, not by rewriting it, so the
// record still speaks for this teardown.
func keepDisksStack(t *testing.T, keepDisks, gate bool) (*corrosion.Client, *StackReconciler, *recordingStackCleaner) {
	t.Helper()
	db := seedDeletingStack(t, true, false)
	db.SetClusterPolicyGate(func() bool { return gate })
	if err := corrosion.MarkStackDeleting(context.Background(), db, "app", keepDisks, "node-0"); err != nil {
		t.Fatal(err)
	}
	c := &recordingStackCleaner{}
	r := NewStackReconciler("node-0", db)
	r.SetCleaner(c)
	r.SetClock(func() time.Time { return time.Now().Add(2 * stackTeardownGrace) })
	return db, r, c
}

// A stack delete with keep_disks that the reconciler finishes (it crashed, or a
// member's delete failed) keeps the disks, as the operator asked. The
// reconciler never set KeepDisks, so it deleted them.
//
// Mutation: drop KeepDisks from the reconciler's delete — red.
func TestStackReconciler_FinishesAKeepDisksTeardownKeepingTheDisks(t *testing.T) {
	_, r, c := keepDisksStack(t, true, true)
	r.ReconcileOnce(context.Background())
	if len(c.vmReqs) != 1 {
		t.Fatalf("VM deletes = %d, want 1", len(c.vmReqs))
	}
	if !c.vmReqs[0].GetKeepDisks() {
		t.Fatal("the reconciler deleted the disks of a keep_disks teardown")
	}
}

// A teardown that recorded it does not keep them deletes them.
//
// Mutation: always keep — red.
func TestStackReconciler_FinishesAPlainTeardownDeletingTheDisks(t *testing.T) {
	_, r, c := keepDisksStack(t, false, true)
	r.ReconcileOnce(context.Background())
	if len(c.vmReqs) != 1 || c.vmReqs[0].GetKeepDisks() {
		t.Fatalf("VM deletes = %+v, want one that deletes the disks", c.vmReqs)
	}
}

// What the reconciler cannot prove the operator let go, it keeps: no record
// (an older coordinator, or cluster_policies not writable yet), and a record
// of another teardown of the same stack name.
//
// Mutation: take a missing or stale record as "delete" — red.
func TestStackReconciler_KeepsDisksItCannotProveMayGo(t *testing.T) {
	t.Run("no record", func(t *testing.T) {
		_, r, c := keepDisksStack(t, false, false)
		r.ReconcileOnce(context.Background())
		if len(c.vmReqs) != 1 || !c.vmReqs[0].GetKeepDisks() {
			t.Fatalf("VM deletes = %+v, want one that keeps the disks", c.vmReqs)
		}
	})
	t.Run("another teardown's record", func(t *testing.T) {
		db, r, c := keepDisksStack(t, false, true)
		// The stack was marked "deleting" again by a writer that recorded no
		// choice (an older build): the record is the earlier teardown's.
		if err := corrosion.SetStackState(context.Background(), db, "app", "deleting"); err != nil {
			t.Fatal(err)
		}
		r.ReconcileOnce(context.Background())
		if len(c.vmReqs) != 1 || !c.vmReqs[0].GetKeepDisks() {
			t.Fatalf("VM deletes = %+v, want one that keeps the disks", c.vmReqs)
		}
	})
}

// Disks kept for want of proof are named where kept disks are (disk_leftover,
// through the cleaner), not only logged; disks the operator asked to keep,
// and a teardown that deletes them, name nothing (re-review m-A).
//
// Mutation: never name them — red.
func TestStackReconciler_NamesTheDisksItKeptForWantOfProof(t *testing.T) {
	for _, tc := range []struct {
		name            string
		keepDisks, gate bool
		named           bool
	}{
		{"no record", false, false, true},
		{"operator kept them", true, true, false},
		{"deleted", false, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, r, c := keepDisksStack(t, tc.keepDisks, tc.gate)
			r.ReconcileOnce(context.Background())
			if got := len(c.namedKept) == 1; got != tc.named {
				t.Fatalf("named = %v, want named %v", c.namedKept, tc.named)
			}
			if tc.named && !strings.Contains(c.namedKept[0], "app-web: the teardown recorded no disk choice") {
				t.Errorf("named %q, want app-web with the reason", c.namedKept[0])
			}
		})
	}
}
