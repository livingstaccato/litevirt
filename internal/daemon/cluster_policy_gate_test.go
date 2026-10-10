package daemon

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// TestWireClusterPolicyGate_TracksTheDurableLatch: cluster_policies is
// writable once failover_scope_v1 has durably latched and not before. Every
// other test of the policy opens the gate directly, so this is the one that
// fails if the production wiring is deleted — an unwired gate fails closed and
// looks exactly like a mid-roll, so nothing else would notice.
func TestWireClusterPolicyGate_TracksTheDurableLatch(t *testing.T) {
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
	d.wireClusterPolicyGate()

	if db.MayWriteClusterPolicy() {
		t.Fatal("the cluster policy gate is open before failover_scope_v1 has durably latched")
	}
	if !checker.Enforced(ctx, capabilities.FailoverScopeV1) || !checker.DurablyLatched(capabilities.FailoverScopeV1) {
		t.Fatal("failover_scope_v1 did not latch durably with the only host advertising it; the rest is vacuous")
	}
	if !db.MayWriteClusterPolicy() {
		t.Error("the daemon's cluster policy gate stayed closed after failover_scope_v1 durably latched")
	}
}

// TestWireRelayHealthGate_TracksBothDurableLatches: a relay demotion row is
// writable only once relay_health_v1 has durably latched (every recipient
// reads it) AND failover_scope_v1 has (every recipient decodes the shape).
// The failover tests open the gate directly, so this is the one that fails if
// the production wiring is deleted (colonelpanik/litevirt#175).
//
// Mutation: wire the relay gate to failover_scope_v1 only — the demotion
// gate opens before relay_health_v1 latches, red.
func TestWireRelayHealthGate_TracksBothDurableLatches(t *testing.T) {
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
	d.wireClusterPolicyGate()

	if !checker.Enforced(ctx, capabilities.FailoverScopeV1) || !checker.DurablyLatched(capabilities.FailoverScopeV1) {
		t.Fatal("failover_scope_v1 did not latch durably; the rest is vacuous")
	}
	if db.MayWriteRelayDemotion() {
		t.Fatal("relay demotions writable before relay_health_v1 has durably latched")
	}
	if !checker.Enforced(ctx, capabilities.RelayHealthV1) || !checker.DurablyLatched(capabilities.RelayHealthV1) {
		t.Fatal("relay_health_v1 did not latch durably with the only host advertising it")
	}
	if !db.MayWriteRelayDemotion() {
		t.Error("relay demotions stayed unwritable after relay_health_v1 and failover_scope_v1 durably latched")
	}
}
