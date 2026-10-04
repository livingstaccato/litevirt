package failover

import (
	"context"
	"testing"
	"time"
)

// TestFenceStillStands_ReadsTheRunStartAVerdictCarries is drill 3 on the
// kvm003 lab (main-e004c250): a host fenced ten seconds into its outage, and a
// successor asking ten minutes later whether that fence still stands. The
// observer's run advanced one count every ~2.85 s — a probe of a powered-off
// host runs out its dial timeout — so (n−1) × ProbeInterval back from
// updated_at put the run's start minutes after the fence, and the resume was
// declined: "no observer has watched the host stay down".
//
// A failing verdict now carries when its run began (last_seen), and that is
// what the run is measured from. A verdict without one — an older build's —
// keeps the count's lower bound, which declines here; the margin applies to a
// carried start exactly as it did to the estimate.
//
// Mutation: ignore last_seen in observerStreakSpans — carried-start-before-the-
// fence goes red.
func TestFenceStillStands_ReadsTheRunStartAVerdictCarries(t *testing.T) {
	ctx := context.Background()
	at := time.Date(2026, 10, 4, 5, 37, 0, 0, time.UTC) // the fence
	now := at.Add(10 * time.Minute)
	upd := now.Add(-time.Second) // fresh
	const cadence = 2850 * time.Millisecond

	for _, tc := range []struct {
		name  string
		began time.Duration // the run's real start, relative to at
		carry bool          // the verdict carries it (this build's checker)
		want  bool
	}{
		{name: "carried-start-before-the-fence", began: -10 * time.Second, carry: true, want: true},
		{name: "carried-start-inside-the-margin", began: -3 * time.Second, carry: true, want: false},
		{name: "carried-start-after-the-fence", began: 30 * time.Second, carry: true, want: false},
		{name: "older-build-verdict", began: -10 * time.Second, want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := newTestDB(t)
			began := at.Add(tc.began)
			n := int(upd.Sub(began)/cadence) + 1
			var lastSeen interface{}
			if tc.carry {
				lastSeen = began.Format(time.RFC3339Nano)
			}
			if err := db.Execute(ctx,
				`INSERT OR REPLACE INTO host_health (observer, target, status, consecutive_failures, last_seen, updated_at)
				 VALUES ('o1', 'bad', 'suspect', ?, ?, ?)`, n, lastSeen, upd.Format(time.RFC3339Nano)); err != nil {
				t.Fatal(err)
			}
			c := NewCoordinator("me", db)
			c.Now = func() time.Time { return now }
			why, got := c.fenceStillStands(ctx, "bad", at)
			if got != tc.want {
				t.Errorf("fenceStillStands = %v (%s), want %v", got, why, tc.want)
			}
		})
	}
}
