package corrosion

import (
	"context"
	"testing"
	"time"
)

// HostProofGradeFence counts a proof-grade fence of the host as it is now,
// however old, and not one from before the host was last recorded as it is
// now (HostFenceLife): the machine removed under its name before `lv host add`
// gave the name to a new one, or the same machine before it came back.
//
// Mutations: dropping the cutoff from HostProofGradeFence fails every
// "earlier life" case; dropping the 'fenced' exemption fails the same-second
// confirmation whose state write's clock ran ahead; dropping fenceLifeSkew
// fails the `lv host fence` case, whose 'offline' write precedes its row.
func TestHostProofGradeFence_JudgedByTheHostsLife(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	row := func(t *testing.T, c *Client, id string, at time.Time) {
		t.Helper()
		if err := c.Execute(ctx,
			`INSERT OR IGNORE INTO fencing_log (id, host_name, method, result, timestamp, detail) VALUES (?, 'h1', 'manual', 'manual-confirmed', ?, '')`,
			id, at.Format(time.RFC3339)); err != nil {
			t.Fatal(err)
		}
	}
	// recorded sets h1's membership state as written at `at` (the writer's
	// HLC), as a state write would.
	recorded := func(t *testing.T, c *Client, state string, at time.Time) {
		t.Helper()
		if err := UpdateHostState(ctx, c, "h1", state); err != nil {
			t.Fatal(err)
		}
		if _, err := c.DB().Exec(`UPDATE host_membership SET updated_at = ? WHERE host_name = 'h1'`,
			at.Format(time.RFC3339Nano)); err != nil {
			t.Fatal(err)
		}
	}
	live := func(t *testing.T) *Client {
		t.Helper()
		c := testClient(t)
		seedHost(t, c, "h1")
		c.SetHostMembershipGate(func() bool { return true })
		if _, err := c.SplitHostMembership(ctx); err != nil || !c.HostMembershipLive() {
			t.Fatalf("split: live=%v err=%v", c.HostMembershipLive(), err)
		}
		return c
	}

	for _, tc := range []struct {
		name  string
		state string
		stateAt,
		rowAt time.Time
		counts bool
	}{
		{"earlier life of a joining host", HostStateJoining, now, now.Add(-time.Minute), false},
		{"earlier life of an active host", "active", now, now.Add(-time.Minute), false},
		{"earlier life of a host lost unfenced", "offline", now, now.Add(-time.Minute), false},
		{"earlier life of a drained host", "maintenance", now, now.Add(-time.Minute), false},
		{"a fence after the host was last recorded", "offline", now.Add(-time.Minute), now, true},
		// `lv host fence`: 'offline' is written, then the row; a peer a
		// little ahead puts the state write's HLC past the row's second.
		{"lv host fence, offline written just before its row", "offline", now.Add(2 * time.Second), now, true},
		// A 'fenced' write is a fence of the host as it is now; a confirmation
		// whose state write's clock ran well ahead still counts.
		{"fenced, its write's clock well ahead", "fenced", now.Add(time.Minute), now, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := live(t)
			recorded(t, c, tc.state, tc.stateAt)
			row(t, c, "f", tc.rowAt)
			rec, ok, err := HostProofGradeFence(ctx, c, "h1")
			if err != nil {
				t.Fatal(err)
			}
			if ok != tc.counts {
				t.Fatalf("state %s at %s, fence at %s: counts=%v (%+v), want %v",
					tc.state, tc.stateAt.Format(time.RFC3339), tc.rowAt.Format(time.RFC3339), ok, rec, tc.counts)
			}
		})
	}

	t.Run("a newer fence counts beside an older one", func(t *testing.T) {
		c := live(t)
		recorded(t, c, "offline", now.Add(-time.Minute))
		row(t, c, "old", now.Add(-10*time.Minute))
		row(t, c, "new", now)
		if rec, ok, err := HostProofGradeFence(ctx, c, "h1"); err != nil || !ok || rec.ID != "new" {
			t.Fatalf("got %+v ok=%v err=%v, want the new fence", rec, ok, err)
		}
	})

	t.Run("a node not reading host_membership judges as before", func(t *testing.T) {
		c := testClient(t)
		seedHost(t, c, "h1")
		if err := UpdateHostState(ctx, c, "h1", "offline"); err != nil {
			t.Fatal(err)
		}
		row(t, c, "old", now.Add(-time.Hour))
		if _, ok, err := HostProofGradeFence(ctx, c, "h1"); err != nil || !ok {
			t.Fatalf("ok=%v err=%v, want the fence counted", ok, err)
		}
	})

	t.Run("a removed host keeps its fence", func(t *testing.T) {
		c := live(t)
		recorded(t, c, "fenced", now.Add(-time.Hour))
		row(t, c, "f", now.Add(-time.Hour))
		if err := DeleteHost(ctx, c, "h1"); err != nil {
			t.Fatal(err)
		}
		if _, ok, err := HostProofGradeFence(ctx, c, "h1"); err != nil || !ok {
			t.Fatalf("ok=%v err=%v: RemovedHostEvidence reads a removed host's fence", ok, err)
		}
	})
}
