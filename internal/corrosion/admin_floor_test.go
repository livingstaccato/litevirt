package corrosion

import (
	"context"
	"testing"
	"time"
)

// zeroAdmins leaves c with two admin tombstones and no live admin: the state
// two racing deletes produce once both tombstones have arrived.
func zeroAdmins(t *testing.T, c *Client) {
	t.Helper()
	ctx := context.Background()
	for _, u := range []string{"alice", "bob"} {
		if err := InsertUser(ctx, c, u, "admin", u+"-hash"); err != nil {
			t.Fatalf("InsertUser %s: %v", u, err)
		}
	}
	for _, u := range []string{"alice", "bob"} {
		if err := DeleteUser(ctx, c, u); err != nil {
			t.Fatalf("DeleteUser %s: %v", u, err)
		}
	}
}

func floor(t *testing.T, c *Client, settle time.Duration) string {
	t.Helper()
	who, err := c.EnsureAdminFloor(context.Background(), settle)
	if err != nil {
		t.Fatalf("EnsureAdminFloor: %v", err)
	}
	return who
}

// A zero that persists is repaired, on the second sighting.
func TestAdminFloor_APersistentZeroIsRepaired(t *testing.T) {
	c := newTestDB(t)
	c.MarkReplicaCaughtUpForTests("peer")
	zeroAdmins(t, c)

	if who := floor(t, c, 0); who != "" {
		t.Fatalf("reinstated %q on the FIRST sighting of zero admins; a zero caused by apply "+
			"order is gone a push later, and acting on it resurrects a revoked admin", who)
	}
	if who := floor(t, c, 0); who == "" {
		t.Fatal("zero live admins persisted and nothing was reinstated")
	}
}

// The case periodic-not-on-apply exists for: a replica sees zero for an
// instant because a delete arrived before the create that made it legal. When
// the create lands before the next check, nothing is reinstated.
func TestAdminFloor_ATransientZeroIsNotRepaired(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	c.MarkReplicaCaughtUpForTests("peer")
	zeroAdmins(t, c)

	if who := floor(t, c, 0); who != "" {
		t.Fatalf("reinstated %q on the first sighting", who)
	}
	if err := InsertUser(ctx, c, "carol", "admin", "carol-hash"); err != nil {
		t.Fatal(err)
	}
	if who := floor(t, c, 0); who != "" {
		t.Fatalf("reinstated %q although carol is a live admin", who)
	}
	// And the earlier sighting does not linger: carol going away later starts
	// the clock again.
	if err := DeleteUser(ctx, c, "carol"); err != nil {
		t.Fatal(err)
	}
	if who := floor(t, c, 0); who != "" {
		t.Fatalf("reinstated %q on what is the first sighting of this zero", who)
	}
}

// A replica that has not caught up cannot tell "no admin" from "no admin yet".
func TestAdminFloor_AStaleReplicaDoesNotAct(t *testing.T) {
	c := newTestDB(t)
	zeroAdmins(t, c)
	for i := 0; i < 3; i++ {
		if who := floor(t, c, 0); who != "" {
			t.Fatalf("reinstated %q from a replica that has not caught up with any peer", who)
		}
	}
}

// The settle period is honoured: a second sighting inside it does not act.
func TestAdminFloor_SettleIsHonoured(t *testing.T) {
	c := newTestDB(t)
	c.MarkReplicaCaughtUpForTests("peer")
	zeroAdmins(t, c)
	floor(t, c, time.Hour)
	if who := floor(t, c, time.Hour); who != "" {
		t.Fatalf("reinstated %q inside the settle period", who)
	}
}
