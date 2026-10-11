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

// RemovedHostProvedOff is FenceRecordProvesOff bounded by the host's last
// life (HostFenceLife), read through the tombstone: the membership row
// survives DeleteHost, so a removed name's proof-grade fence from before its
// last membership change is about an earlier life and proves nothing (review
// R4-I1). A confirmation recorded after the removal, a fence of the last
// life, and a name with no membership row (judged as before) still count.
//
// Mutation "no life bound" (RemovedHostProvedOff reads every row) — red on
// "an earlier life's fence".
func TestRemovedHostProvedOff_JudgedByTheHostsLastLife(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	row := func(t *testing.T, c *Client, id, method, result string, at time.Time) {
		t.Helper()
		if err := c.Execute(ctx,
			`INSERT OR IGNORE INTO fencing_log (id, host_name, method, result, timestamp, detail) VALUES (?, 'h1', ?, ?, ?, '')`,
			id, method, result, at.Format(time.RFC3339)); err != nil {
			t.Fatal(err)
		}
	}
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
		name   string
		prep   func(t *testing.T, c *Client)
		proved bool
	}{
		{"an earlier life's confirmation", func(t *testing.T, c *Client) {
			row(t, c, "old", "manual", "manual-confirmed", now.Add(-time.Hour))
			recorded(t, c, "active", now.Add(-time.Minute))
		}, false},
		{"an earlier life's IPMI fence", func(t *testing.T, c *Client) {
			row(t, c, "old", "ipmi", "fenced", now.Add(-time.Hour))
			recorded(t, c, "active", now.Add(-time.Minute))
		}, false},
		{"a confirmation after the removal", func(t *testing.T, c *Client) {
			row(t, c, "old", "manual", "manual-confirmed", now.Add(-time.Hour))
			recorded(t, c, "active", now.Add(-time.Minute))
			row(t, c, "new", "manual", "manual-confirmed", now)
		}, true},
		{"a confirmation in the last life, recorded fenced", func(t *testing.T, c *Client) {
			recorded(t, c, "fenced", now.Add(-time.Minute))
			row(t, c, "f", "manual", "manual-confirmed", now.Add(-time.Minute))
		}, true},
		{"a weaker fence in the last life over an older proof", func(t *testing.T, c *Client) {
			recorded(t, c, "offline", now.Add(-time.Hour))
			row(t, c, "p", "ipmi", "fenced", now.Add(-30*time.Minute))
			row(t, c, "s", "ssh", "fenced", now.Add(-time.Minute))
		}, false},
		{"no fence at all", func(t *testing.T, c *Client) {
			recorded(t, c, "active", now.Add(-time.Minute))
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := live(t)
			tc.prep(t, c)
			if err := DeleteHost(ctx, c, "h1"); err != nil {
				t.Fatal(err)
			}
			got, err := RemovedHostProvedOff(ctx, c, "h1")
			if err != nil || got != tc.proved {
				t.Fatalf("RemovedHostProvedOff = %v, %v; want %v", got, err, tc.proved)
			}
		})
	}

	t.Run("a name with no membership row is judged as before", func(t *testing.T) {
		c := testClient(t)
		row(t, c, "old", "ipmi", "fenced", now.Add(-time.Hour))
		if got, err := RemovedHostProvedOff(ctx, c, "h1"); err != nil || !got {
			t.Fatalf("RemovedHostProvedOff = %v, %v; want the fence counted", got, err)
		}
	})
}
