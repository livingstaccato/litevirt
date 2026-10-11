package failover

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/fence"
)

// A failed redfish fence is retried on the backoff, as a failed ipmi fence is,
// and a successful retry recovers the host's workloads. The retry is the
// verified power-off it was meant to be: a redfish fence of a BMC that was
// unreachable for a moment must not strand the host.
func TestFenceWake_AFailedRedfishFenceIsRetried(t *testing.T) {
	db, ctx := seedDownHost(t, "redfish", nil)
	c := newTestCoordinator("coordinator", db)
	var strategies []string
	c.SetFencer(func(_ context.Context, h fence.HostConfig) fence.Result {
		strategies = append(strategies, h.FenceStrategy)
		if len(strategies) == 1 {
			return fence.Result{Method: "redfish", Success: false, Detail: "BMC unreachable"}
		}
		return fence.Result{Method: "redfish", Success: true, Detail: "PowerState Off observed"}
	})
	c.run(ctx)
	if got := vmHost(t, db, ctx); got == "alive" {
		t.Fatalf("VM moved on a failed redfish fence")
	}
	ageFenceRows(t, db, ctx, fenceRetryBase+time.Second)
	c.lastFenceAt = nil
	c.run(ctx)
	if len(strategies) != 2 || strategies[1] != "redfish" {
		t.Fatalf("fence strategies = %v, want the failed redfish fence retried with redfish", strategies)
	}
	if got := vmHost(t, db, ctx); got != "alive" {
		t.Errorf("VM still on %q after the redfish retry succeeded", got)
	}
}

// An operator who fixes a host whose watchdog fence failed by configuring
// Redfish has the next retry run redfish: the retry runs the operator's
// current strategy when a retry can run it.
func TestFenceWake_SwitchingAWatchdogHostToRedfishIsRetried(t *testing.T) {
	db, ctx := seedDownHost(t, "watchdog", nil)
	c := newTestCoordinator("coordinator", db)
	var strategies []string
	c.SetFencer(func(_ context.Context, h fence.HostConfig) fence.Result {
		strategies = append(strategies, h.FenceStrategy)
		if h.FenceStrategy == "redfish" {
			return fence.Result{Method: "redfish", Success: true, Detail: "PowerState Off observed"}
		}
		return fence.Result{Method: "watchdog", Success: false, Detail: "watchdog fence only for the local node"}
	})
	c.run(ctx)
	if err := db.Execute(ctx, `UPDATE hosts SET fence_strategy = 'redfish' WHERE name = 'down'`); err != nil {
		t.Fatalf("switch strategy: %v", err)
	}
	ageFenceRows(t, db, ctx, fenceRetryBase+time.Second)
	c.lastFenceAt = nil
	c.run(ctx)
	if len(strategies) != 2 || strategies[1] != "redfish" {
		t.Fatalf("fence strategies = %v, want the operator's redfish retried after the failed watchdog fence", strategies)
	}
	if got := vmHost(t, db, ctx); got != "alive" {
		t.Errorf("VM still on %q after the redfish retry succeeded", got)
	}
}
