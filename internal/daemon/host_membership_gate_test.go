package daemon

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// TestWireHostMembershipGate_TracksTheDurableLatch: the host_membership gate
// follows the REAL durable latch, closed before and open after. Every other
// test of the split injects the gate directly, so this is the only test that
// fails if the production wiring is deleted — and an unwired gate is silent,
// because it fails closed and looks exactly like a mid-roll.
//
// The daemon wires it from the activation marker on disk rather than from the
// checker, because the boot state is written before the checker exists. So the
// checker writes the marker here and the gate must see it.
func TestWireHostMembershipGate_TracksTheDurableLatch(t *testing.T) {
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
	d.wireHostMembershipGate()

	if db.MayWriteHostMembership() {
		t.Fatal("the host membership gate is open before host_membership_split_v1 has durably latched")
	}
	if !checker.Enforced(ctx, capabilities.HostMembershipSplitV1) || !checker.DurablyLatched(capabilities.HostMembershipSplitV1) {
		t.Fatal("host_membership_split_v1 did not latch durably with the only host advertising it; the rest is vacuous")
	}
	if !db.MayWriteHostMembership() {
		t.Error("the daemon's host membership gate stayed closed after host_membership_split_v1 durably latched")
	}
}
