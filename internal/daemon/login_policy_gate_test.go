package daemon

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// TestAdminFloor_LoginRulesOnlyThroughTheReleaseGate: the admin floor's
// reinstatement writes the login rules' durable cut-offs only through this
// node's release-feature gate (the login_policy feature), and records the use
// before it does. Before the release token latches it reinstates all the same,
// as the previous release does, with none of that data and no use recorded.
// This is the test that fails if the daemon's floor wiring is deleted.
func TestAdminFloor_LoginRulesOnlyThroughTheReleaseGate(t *testing.T) {
	ctx := context.Background()
	for _, latched := range []bool{false, true} {
		d := zeroAdminDaemon(t)
		d.cfg.HostName = "host-a"
		d.cfg.DataDir = t.TempDir()
		if err := corrosion.RegisterHost(ctx, d.db, corrosion.HostRecord{
			Name: "host-a", Address: "10.0.0.1", State: "active", Role: "worker",
		}); err != nil {
			t.Fatalf("register host: %v", err)
		}
		d.db.SetClusterPolicyGate(func() bool { return true })
		checker := health.NewChecker("host-a", "/etc/litevirt/pki", d.db)
		checker.SetActivationMarker(health.ActivationMarkerBase(d.cfg.DataDir))
		checker.SetPeerPinger(func(context.Context, string) ([]string, time.Time, error) {
			return capabilities.Supported(), time.Time{}, nil
		})
		d.checker = checker
		if latched && (!checker.Enforced(ctx, capabilities.ReleaseToken) || !checker.DurablyLatched(capabilities.ReleaseToken)) {
			t.Fatal("the release token did not latch durably with the only host advertising it; the rest is vacuous")
		}

		d.checkAdminFloor(ctx, 0) // arms
		d.checkAdminFloor(ctx, 0) // acts
		if u, err := corrosion.GetUser(ctx, d.db, "alice"); err != nil || u == nil {
			t.Fatalf("latched=%v: the floor did not reinstate alice: %+v %v", latched, u, err)
		}
		life, err := corrosion.GetUserLifecycle(ctx, d.db, "alice")
		if err != nil {
			t.Fatal(err)
		}
		used, err := corrosion.ReleaseFeatureUsed(ctx, d.db, capabilities.ReleaseToken, string(capabilities.FeatureLoginPolicy))
		if err != nil {
			t.Fatal(err)
		}
		if !latched {
			if life.TokensNotBefore != "" || used {
				t.Fatalf("before the latch: tokens_not_before=%q used=%v, want neither written", life.TokensNotBefore, used)
			}
			continue
		}
		if life.TokensNotBefore == "" {
			t.Error("after the latch the floor wrote no durable token cut-off: its login rules did not go through the gate")
		}
		if !used {
			t.Error("the floor wrote the login rules' data with no login_policy use recorded")
		}
	}
}
