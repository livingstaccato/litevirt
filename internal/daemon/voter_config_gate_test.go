package daemon

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// TestWireVoterConfigGate_TracksTheDurableLatch: the voter_configs write gate
// follows the REAL durable voter_config_v1 latch, closed before and open
// after. Every fleet and unit test injects the gate directly, so this is the
// only one that fails if the production wiring is deleted — and an unwired
// gate is silent: it fails closed, genesis never runs, and the cluster keeps
// colonelpanik/litevirt#251's derived voter set forever.
//
// Mutation: delete the d.wireVoterConfigGate() call's body — the gate stays
// closed after the latch.
func TestWireVoterConfigGate_TracksTheDurableLatch(t *testing.T) {
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
	d.wireVoterConfigGate()

	if db.MayWriteVoterConfigs() {
		t.Fatal("the voter_configs gate is open before voter_config_v1 has durably latched")
	}
	if !checker.Enforced(ctx, capabilities.VoterConfigV1) || !checker.DurablyLatched(capabilities.VoterConfigV1) {
		t.Fatal("voter_config_v1 did not latch durably with the only host advertising it; the rest is vacuous")
	}
	if !db.MayWriteVoterConfigs() {
		t.Error("the daemon's voter_configs gate stayed closed after voter_config_v1 durably latched")
	}
}
