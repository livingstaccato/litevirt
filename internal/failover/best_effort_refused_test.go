package failover

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/fence"
)

// A best-effort fence whose SSH path is refused (a target with no fence ssh
// row once release_2026_12_v1 has latched) was never attempted, so it is not
// a fence: the coordinator records it failed, moves nothing, holds the
// recovery with the ways out (fence-confirm after a power-off, ipmi or
// redfish), and retries it under best-effort, so a refusal that clears (the
// host's first sync) fences it then. Both spellings of the strategy: the
// default "" and an explicit "best-effort", which the split-brain guard used
// to wave through on a failed fence.
//
// Mutation: report a refused lenient fence as best-effort's assumed success
// (fence.sshNotAttempted) — the VM moves, red. Mutation: restore the guard's
// "best-effort" proceed-anyway case — the explicit spelling moves, red.
// Mutation: leave best-effort out of retryableFenceMethod — no retry, red.
func TestFailover_RefusedBestEffortFenceHoldsWithTheWayOut(t *testing.T) {
	for _, strategy := range []string{"", "best-effort"} {
		t.Run("strategy="+strategy, func(t *testing.T) {
			db, ctx := seedDownHost(t, strategy, nil)
			c := newTestCoordinator("coordinator", db)
			c.FenceSSH = func(context.Context, string) fence.SSHFence {
				return fence.SSHFence{Refusal: "down has published no fence ssh row"}
			}
			var ran []string
			c.SetFencer(func(ctx context.Context, h fence.HostConfig) fence.Result {
				ran = append(ran, h.FenceStrategy)
				return fence.Execute(ctx, h) // refused: dials nothing
			})
			c.run(ctx)
			if len(ran) != 1 {
				t.Fatalf("fences = %v, want one", ran)
			}
			if got := vmHost(t, db, ctx); got != "down" {
				t.Fatalf("VM moved to %q on a refused best-effort fence", got)
			}
			rows, err := db.Query(ctx, `SELECT method, result, detail FROM fencing_log WHERE host_name = 'down'`)
			if err != nil || len(rows) != 1 {
				t.Fatalf("fencing_log = %v (%v), want one row", rows, err)
			}
			if m, r := rows[0].String("method"), rows[0].String("result"); m != "best-effort-ssh" || r != fence.LogPartial {
				t.Fatalf("fencing_log row = %s/%s, want best-effort-ssh/partial", m, r)
			}
			hold := c.holdReason["down"]
			for _, want := range []string{"lv host fence-confirm down", "ipmi or redfish"} {
				if !strings.Contains(hold, want) {
					t.Fatalf("hold reason %q does not name %q", hold, want)
				}
			}

			ageFenceRows(t, db, ctx, fenceRetryBase+time.Second)
			c.lastFenceAt = nil
			c.run(ctx)
			if len(ran) != 2 || ran[1] != "best-effort" {
				t.Fatalf("fences = %v, want a best-effort retry", ran)
			}
			if got := vmHost(t, db, ctx); got != "down" {
				t.Fatalf("VM moved to %q on a refused retry", got)
			}
		})
	}
}
