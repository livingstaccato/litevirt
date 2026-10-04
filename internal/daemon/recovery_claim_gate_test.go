package daemon

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// TestWireRecoveryClaimGate_TracksTheDurableLatch: the claim_certificate
// emission gate follows the REAL durable recovery_claim_v1 latch — closed
// before, open after. Every fleet and unit test injects it directly, so this
// is the only test that fails if the production wiring is deleted, and an
// unwired gate fails closed: every certified proof is refused as not yet
// emittable, which under enforcement refuses every recovery.
//
// Mutation: delete the body of wireRecoveryClaimGate — the gate stays closed
// after the latch.
func TestWireRecoveryClaimGate_TracksTheDurableLatch(t *testing.T) {
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
	d.wireRecoveryClaimGate()

	if db.MayEmitClaimCertificate() {
		t.Fatal("the claim_certificate gate is open before recovery_claim_v1 has durably latched")
	}
	if !checker.Enforced(ctx, capabilities.RecoveryClaimV1) || !checker.DurablyLatched(capabilities.RecoveryClaimV1) {
		t.Fatal("recovery_claim_v1 did not latch durably with the only host advertising it; the rest is vacuous")
	}
	if !db.MayEmitClaimCertificate() {
		t.Error("the daemon's claim_certificate gate stayed closed after recovery_claim_v1 durably latched")
	}
}
