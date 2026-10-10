package daemon

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// TestWireCredentialsClearGate_TracksTheDurableLatch: the gate that empties the
// old secret columns follows the REAL durable latch of credentials_clear_v1,
// closed before and open after, and only together with the split gate. Every
// other test injects the gate directly, so this is the test that fails if the
// production wiring is deleted — an unwired gate is silent: it fails closed and
// looks exactly like a mid-roll.
//
// It also pins CredentialsClearLatchedOnDisk, the gate `lv user reset-admin`
// uses, so the CLI empties the old column exactly when the daemon would.
func TestWireCredentialsClearGate_TracksTheDurableLatch(t *testing.T) {
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

	d := &Daemon{db: db, checker: checker, cfg: &Config{}}
	d.wireCredentialsSplitGate()
	d.wireCredentialsClearGate()
	onDisk := CredentialsClearLatchedOnDisk(dataDir)

	if db.MayClearCredentialColumns() || onDisk() {
		t.Fatal("the credentials clear gate is open before credentials_clear_v1 has durably latched")
	}
	if !checker.Enforced(ctx, capabilities.CredentialsClearV1) || !checker.DurablyLatched(capabilities.CredentialsClearV1) {
		t.Fatal("credentials_clear_v1 did not latch durably with the only host advertising it; the rest is vacuous")
	}
	if db.MayClearCredentialColumns() {
		t.Error("the clear gate opened before credentials_split_v1 latched; a node must never empty " +
			"the column that is its only copy")
	}
	if !checker.Enforced(ctx, capabilities.CredentialsSplitV1) {
		t.Fatal("credentials_split_v1 did not latch; the rest is vacuous")
	}
	if !db.MayClearCredentialColumns() {
		t.Error("the daemon's credentials clear gate stayed closed after both tokens durably latched")
	}
	if !onDisk() {
		t.Error("CredentialsClearLatchedOnDisk does not see the marker the checker wrote; " +
			"`lv user reset-admin` would write the secret into the old column after the clear")
	}
}
