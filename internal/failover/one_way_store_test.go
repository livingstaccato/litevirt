package failover

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// seedOneWay writes the host_health rows of TestPartitionPause_OneWayIsMadeVisible:
// both observers have failed "down" for a minute and still do, and "down"
// marked them healthy at now+offset.
func seedOneWay(t *testing.T, db *corrosion.Client, now time.Time, offset time.Duration) {
	t.Helper()
	ctx := context.Background()
	for _, o := range []string{"coordinator", "alive"} {
		if err := db.Execute(ctx,
			`INSERT OR REPLACE INTO host_health (observer, target, status, consecutive_failures, last_seen, updated_at)
			 VALUES (?, 'down', 'suspect', 30, NULL, ?)`, o, now.UTC().Format(time.RFC3339Nano)); err != nil {
			t.Fatal(err)
		}
	}
	at := now.Add(offset).UTC().Format(time.RFC3339Nano)
	for _, peer := range []string{"coordinator", "alive"} {
		if err := db.Execute(ctx,
			`INSERT OR REPLACE INTO host_health (observer, target, status, consecutive_failures, last_seen, updated_at)
			 VALUES ('down', ?, 'healthy', 0, NULL, ?)`, peer, at); err != nil {
			t.Fatal(err)
		}
	}
}

func oneWayRow(t *testing.T, db *corrosion.Client) (corrosion.HealthCondition, bool) {
	t.Helper()
	row, ok, err := corrosion.GetHealthCondition(context.Background(), db, corrosion.PartitionPauseEvaluator,
		corrosion.CondPartitionOneWay, "host", "down")
	if err != nil {
		t.Fatal(err)
	}
	return row, ok && row.Lifecycle != corrosion.ConditionResolved
}

// partition_one_way is resolved by whichever coordinator holds the lease once
// the one-way case is gone, not only by the one that raised it. Its raiser's
// memory was the only thing that resolved it: a coordinator that raised it and
// then died, restarted or lost the lease left it CRITICAL for hours (lab 1,
// 2026-10-16: raised by node-1 at 10:38:36 for node-2, node-1 powered off 14 s
// later, resolved at 13:03:20 only because node-1 happened to raise it again).
//
// Both ways the case can go: the host is no longer a fence candidate (the
// quorum reaches it again), or it still is and is no longer one-way (it has
// stopped seeing a majority).
//
// Mutation: drop syncOneWay — the successor never resolves the row and both
// cases go red.
func TestPartitionPause_OneWayRaisedByAPreviousHolderIsResolvedByTheNext(t *testing.T) {
	for _, tc := range []struct {
		name string
		gone func(t *testing.T, db *corrosion.Client, now time.Time)
	}{
		{"no longer a candidate", func(t *testing.T, db *corrosion.Client, now time.Time) {
			for _, o := range []string{"coordinator", "alive"} {
				if err := db.Execute(context.Background(),
					`INSERT OR REPLACE INTO host_health (observer, target, status, consecutive_failures, last_seen, updated_at)
					 VALUES (?, 'down', 'healthy', 0, NULL, ?)`, o, now.UTC().Format(time.RFC3339Nano)); err != nil {
					t.Fatal(err)
				}
			}
		}},
		{"still a candidate, no longer one-way", func(t *testing.T, db *corrosion.Client, now time.Time) {
			seedOneWay(t, db, now, -2*time.Minute) // its healthy rows predate the streaks
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, db, ctx, mono := pauseCoordinator(t, true)
			ensureVoter(t, db, "down")
			seedOneWay(t, db, c.now(), -20*time.Second)
			c.run(ctx)
			if row, raised := oneWayRow(t, db); !raised || row.Reporter != "coordinator" {
				t.Fatalf("setup: partition_one_way not raised by the first holder: %+v", row)
			}

			// The first holder is gone; the next one holds no memory of it.
			if err := db.Execute(ctx, `DELETE FROM leader_election`); err != nil {
				t.Fatal(err)
			}
			succ := newTestCoordinator("alive", db)
			succ.SetFencer(fencerReturning("best-effort-ssh", true))
			succ.Mono = mono.Now
			succ.PartitionPauseEnforced = func(context.Context) bool { return true }
			succ.PeerPausesOnLoss = func(string) bool { return true }
			tc.gone(t, db, succ.now())
			succ.run(ctx)
			row, raised := oneWayRow(t, db)
			if raised {
				t.Fatalf("partition_one_way raised by a previous holder is still open after the case went: %+v", row)
			}
			if row.Reporter != "alive" {
				t.Fatalf("resolved by %q, want the holder now, alive: %+v", row.Reporter, row)
			}
		})
	}
}

// A holder that raised partition_one_way, and whose row another holder has
// since resolved, raises it again when the case returns: its memory that it
// raised the row must not stand in for the row.
//
// Mutation: keep the in-memory map when the store says the row is resolved
// (syncOneWay only adds) — the second raise never happens and this goes red.
func TestPartitionPause_OneWayResolvedElsewhereIsRaisedAgain(t *testing.T) {
	c, db, ctx, _ := pauseCoordinator(t, true)
	ensureVoter(t, db, "down")
	seedOneWay(t, db, c.now(), -20*time.Second)
	c.run(ctx)
	row, raised := oneWayRow(t, db)
	if !raised {
		t.Fatalf("setup: partition_one_way not raised: %+v", row)
	}
	// Another holder, in between, saw it go and resolved it.
	row.Lifecycle, row.ResolvedAt, row.Reporter = corrosion.ConditionResolved, c.now().UTC().Format(time.RFC3339), "alive"
	if err := corrosion.UpsertHealthCondition(ctx, db, row); err != nil {
		t.Fatal(err)
	}
	seedOneWay(t, db, c.now(), -20*time.Second)
	c.run(ctx)
	if row, raised := oneWayRow(t, db); !raised {
		t.Fatalf("partition_one_way not raised again once the case returned: %+v", row)
	}
}
