package daemon

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// TestWireSGProjectsGate_TracksTheDurableLatch: corrosion writes a project
// security group once sg_projects_v1 has durably latched and not before. An unwired gate reads false and looks
// exactly like a mid-roll, so this is the test that fails if the wiring goes.
func TestWireSGProjectsGate_TracksTheDurableLatch(t *testing.T) {
	ctx := context.Background()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("init schema: %v", err)
	}
	if err := corrosion.RegisterHost(ctx, db, corrosion.HostRecord{
		Name: "host-a", Address: "10.0.0.1", State: "active", Role: "worker",
	}); err != nil {
		t.Fatalf("register host: %v", err)
	}

	dataDir := t.TempDir()
	checker := health.NewChecker("host-a", "/etc/litevirt/pki", db)
	checker.SetActivationMarker(health.ActivationMarkerBase(dataDir))
	checker.SetPeerPinger(func(context.Context, string) ([]string, time.Time, error) {
		return capabilities.Supported(), time.Time{}, nil
	})

	d := &Daemon{db: db, checker: checker, cfg: &Config{DataDir: dataDir}}
	d.wireSGProjectsGate()

	if db.SGProjectsOn() {
		t.Fatal("project security groups are writable before sg_projects_v1 has durably latched")
	}
	if !checker.Enforced(ctx, capabilities.SGProjectsV1) || !checker.DurablyLatched(capabilities.SGProjectsV1) {
		t.Fatal("sg_projects_v1 did not latch durably with the only host advertising it; the rest is vacuous")
	}
	if !db.SGProjectsOn() {
		t.Error("the daemon's sg_projects gate stayed closed after sg_projects_v1 durably latched")
	}
}
