package failover

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// A failing run that began after a fence reads as its observer having seen
// the host answer after it (restartedSinceObserversIn), except a run its
// observer recorded as silent through a stall of its own that began before
// the fence: it has seen no answer since before the fence. The record must
// name that very run (its start, exactly as last_seen) and a stall that began
// more than fenceSkewMargin before the fence; anything else still refuses.
//
// Mutations: drop the silentThroughStall excuse — "silent since before the
// fence" goes red; ignore the run start in health.SilentSince — "another run"
// goes red; compare silent_since without the margin — "silent since just
// before the fence" goes red.
func TestRestartedSince_ARunSilentThroughAStallBeforeTheFenceIsExcused(t *testing.T) {
	fence := time.Now().Add(-time.Minute).UTC().Truncate(time.Millisecond)
	runStart := fence.Add(20 * time.Second).UTC().Format(time.RFC3339Nano)
	for _, tc := range []struct {
		name     string
		record   bool
		recorded string        // the run start the record names
		since    time.Duration // silent_since, relative to the fence
		refused  bool
	}{
		{"no record", false, "", 0, true},
		{"silent since before the fence", true, runStart, -30 * time.Second, false},
		{"another run", true, fence.Add(19 * time.Second).UTC().Format(time.RFC3339Nano), -30 * time.Second, true},
		{"silent since after the fence", true, runStart, 10 * time.Second, true},
		{"silent since just before the fence", true, runStart, -fenceSkewMargin + time.Second, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := newTestDB(t)
			ctx := context.Background()
			if err := db.Execute(ctx,
				`INSERT OR REPLACE INTO host_health (observer, target, status, consecutive_failures, last_seen, updated_at)
				 VALUES ('thawed', 'down', 'suspect', 6, ?, ?)`,
				runStart, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
				t.Fatal(err)
			}
			if tc.record {
				ev, _ := json.Marshal(map[string]any{
					"detail": "stalled", "gap_seconds": 40,
					"silent_runs": map[string]any{"down": map[string]string{
						"run_start":    tc.recorded,
						"silent_since": fence.Add(tc.since).UTC().Format(time.RFC3339Nano),
					}},
				})
				if err := corrosion.UpsertHealthCondition(ctx, db, corrosion.HealthCondition{
					Evaluator: health.StallEvaluator, Code: health.CondObserverStalled,
					SubjectKind: "host", SubjectID: "thawed", Lifecycle: corrosion.ConditionResolved,
					Severity: corrosion.SeverityWarning, Evidence: string(ev), Reporter: "thawed",
					FirstSeen: fence.Format(time.RFC3339), LastSeen: fence.Format(time.RFC3339),
				}); err != nil {
					t.Fatal(err)
				}
			}
			c := newTestCoordinator("coordinator", db)
			got := restartedSinceObserversIn(c.readHostHealth(ctx, "down"), "down", fence)
			if refused := len(got) > 0; refused != tc.refused {
				t.Fatalf("refused = %v (%v), want %v", refused, got, tc.refused)
			}
		})
	}
}
