package failover

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/fence"
)

// Re-review 5 m1: the manual gate's stands check is reachable on the afresh
// path. The confirmation passes confirmationFencesAfresh; then, before the
// gate (here during the fence call), an observer's failing run begins after
// the confirmation. The life is unknown there (the host is recorded fenced),
// so only the gate's own stands check (confirmedOffNow) refuses, naming the
// confirmation and the remedy.
//
// Mutation: drop the confirmationStands check from confirmedOffNow, keeping
// the life check — the VM moves to alive.
func TestManualGateStandsOnAfreshPath(t *testing.T) {
	db, ctx := seedDownHost(t, "manual", nil)
	lengthenStreak(t, db, ctx, 2*time.Minute)
	confirmAgo(t, db, ctx, 30*time.Second)
	c := newTestCoordinator("coordinator", db)
	fences := 0
	c.SetFencer(func(ctx context.Context, h fence.HostConfig) fence.Result {
		fences++
		failingSince(t, db, "alive", time.Now(), time.Now())
		return manualFencer()(ctx, h)
	})
	c.run(ctx)
	if fences != 1 {
		t.Fatalf("fences = %d, want 1 (afresh path not taken)", fences)
	}
	if got := vmHost(t, db, ctx); got != "down" {
		t.Fatalf("VM moved to %q although an observer's run began after the confirmation (hold %q)", got, c.holdReason["down"])
	}
	hold := c.holdReason["down"]
	for _, want := range []string{"operator-down", "lv host fence-confirm down' again"} {
		if !strings.Contains(hold, want) {
			t.Fatalf("hold %q does not name %q", hold, want)
		}
	}
}
