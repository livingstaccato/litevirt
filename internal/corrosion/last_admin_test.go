package corrosion

import (
	"context"
	"testing"
)

// TestReinstateAdminIfNoneRemain is the CRDT half of the last-admin guard.
//
// grpcapi.DeleteUser checks OtherLiveAdminExists and then deletes, as two
// independent operations against replicated state. With two admins and one
// delete on each of two nodes, BOTH checks see the other admin alive, both
// pass, both tombstones replicate, and the cluster is left with no
// administrator and no way back in. Serializing on one node does not help:
// the two requests never meet.
//
// Nothing can make check-then-act atomic across LWW replicas, so the invariant
// is restored after the fact instead: a node that observes zero live admins
// undoes the most recent admin tombstone. Both racing nodes reach the same
// conclusion and pick the same row, and a duplicate reinstatement is harmless
// -- two admins is the state we were trying to preserve.
func TestReinstateAdminIfNoneRemain(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)

	for _, u := range []string{"alice", "bob"} {
		if err := InsertUser(ctx, db, u, "admin", "x"); err != nil {
			t.Fatalf("InsertUser %s: %v", u, err)
		}
	}

	// The race: each node's check passed, so both deletes land.
	if err := DeleteUser(ctx, db, "alice"); err != nil {
		t.Fatalf("DeleteUser alice: %v", err)
	}
	if err := DeleteUser(ctx, db, "bob"); err != nil {
		t.Fatalf("DeleteUser bob: %v", err)
	}

	reinstated, err := ReinstateAdminIfNoneRemain(ctx, db)
	if err != nil {
		t.Fatalf("ReinstateAdminIfNoneRemain: %v", err)
	}
	if reinstated == "" {
		t.Fatal("the cluster has no live admin and nothing was reinstated; there is no " +
			"way back into a cluster whose last administrator was deleted")
	}

	live, err := db.Query(ctx, `SELECT username FROM users WHERE role = 'admin' AND deleted_at IS NULL`)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(live) == 0 {
		t.Fatalf("reinstated %q but no live admin is visible", reinstated)
	}
}

// It must do nothing while an admin survives — a repair that fires on the
// healthy path would resurrect every deliberately deleted admin.
func TestReinstateAdminIfNoneRemain_NoopWhileAnAdminLives(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)

	for _, u := range []string{"alice", "bob"} {
		if err := InsertUser(ctx, db, u, "admin", "x"); err != nil {
			t.Fatalf("InsertUser %s: %v", u, err)
		}
	}
	if err := DeleteUser(ctx, db, "alice"); err != nil {
		t.Fatalf("DeleteUser alice: %v", err)
	}

	reinstated, err := ReinstateAdminIfNoneRemain(ctx, db)
	if err != nil {
		t.Fatalf("ReinstateAdminIfNoneRemain: %v", err)
	}
	if reinstated != "" {
		t.Fatalf("reinstated %q while bob is still a live admin; a deliberate deletion "+
			"must stay deleted", reinstated)
	}
}
