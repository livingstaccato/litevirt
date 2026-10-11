package corrosion

import (
	"context"
	"strings"
	"testing"
	"time"
)

// HostProofGradeFence of a REMOVED host reads its life as RemovedHostProvedOff
// does: only a fence of the host's last life counts, the life read through
// the tombstone (the membership row survives DeleteHost). It used to count a removed name's proof-grade fence of any age, so
// the coordinator recovered a removed host's workloads, and a claim decided
// for it moved on, on the confirmation of the machine removed under the name
// before it was given to another. RemovedHostEvidence and the coordinator's
// removed-host pass read it. A confirmation recorded after the removal — the
// remedy, `lv host fence-confirm` — and a fence of the last life still count.
//
// Mutation "live-only life" (HostFenceLife's live read, as before) — red on
// the earlier-life rows, in HostProofGradeFence and RemovedHostEvidence.
func TestHostProofGradeFence_ARemovedHostsEarlierLifeDoesNotCount(t *testing.T) {
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
	for _, tc := range []struct {
		name    string
		prep    func(t *testing.T, c *Client)
		removed bool
		counts  bool
	}{
		{"an earlier life's IPMI fence, removed", func(t *testing.T, c *Client) {
			row(t, c, "old", "ipmi", "fenced", now.Add(-time.Hour))
			recorded(t, c, "active", now.Add(-time.Minute))
		}, true, false},
		{"an earlier life's confirmation, removed", func(t *testing.T, c *Client) {
			row(t, c, "old", "manual", "manual-confirmed", now.Add(-time.Hour))
			recorded(t, c, "active", now.Add(-time.Minute))
		}, true, false},
		{"a confirmation after the removal", func(t *testing.T, c *Client) {
			row(t, c, "old", "manual", "manual-confirmed", now.Add(-time.Hour))
			recorded(t, c, "active", now.Add(-time.Minute))
			row(t, c, "new", "manual", "manual-confirmed", now)
		}, true, true},
		{"a fence of the last life, recorded fenced, removed", func(t *testing.T, c *Client) {
			recorded(t, c, "fenced", now.Add(-time.Minute))
			row(t, c, "f", "ipmi", "fenced", now.Add(-time.Minute))
		}, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := testClient(t)
			seedHost(t, c, "h1")
			c.SetHostMembershipGate(func() bool { return true })
			if _, err := c.SplitHostMembership(ctx); err != nil || !c.HostMembershipLive() {
				t.Fatalf("split: live=%v err=%v", c.HostMembershipLive(), err)
			}
			tc.prep(t, c)
			if tc.removed {
				if err := DeleteHost(ctx, c, "h1"); err != nil {
					t.Fatal(err)
				}
			}
			rec, ok, err := HostProofGradeFence(ctx, c, "h1")
			if err != nil || ok != tc.counts {
				t.Fatalf("HostProofGradeFence = %+v, %v, %v; want counts=%v", rec, ok, err, tc.counts)
			}
			if !tc.removed {
				return
			}
			// RemovedHostEvidence reads it first: an uncounted fence is its
			// refusal; a counted one goes on to the revocation check.
			eerr := RemovedHostEvidence(ctx, c, t.TempDir(), "h1")
			if got := eerr != nil && strings.Contains(eerr.Error(), "no proof-grade fence"); got == tc.counts {
				t.Errorf("RemovedHostEvidence = %v; want the fence refusal %v", eerr, !tc.counts)
			}
		})
	}
}
