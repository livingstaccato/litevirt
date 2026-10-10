package daemon

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// TestWireLoginPolicyGate_TracksTheDurableLatch: user_lifecycle and the
// second-factor policy are writable once login_policy_v1 has durably latched
// and not before. Every other test opens the gate directly, so this is the one
// that fails if the production wiring is deleted — an unwired gate fails
// closed and looks exactly like a mid-roll. The on-disk form `lv user
// reset-admin` uses must agree with it.
func TestWireLoginPolicyGate_TracksTheDurableLatch(t *testing.T) {
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
	d.wireLoginPolicyGate()
	onDisk := LoginPolicyLatchedOnDisk(dataDir)

	if db.MayWriteLoginPolicy() || onDisk() {
		t.Fatal("the login policy gate is open before login_policy_v1 has durably latched")
	}
	if !checker.Enforced(ctx, capabilities.LoginPolicyV1) || !checker.DurablyLatched(capabilities.LoginPolicyV1) {
		t.Fatal("login_policy_v1 did not latch durably with the only host advertising it; the rest is vacuous")
	}
	if !db.MayWriteLoginPolicy() {
		t.Error("the daemon's login policy gate stayed closed after login_policy_v1 durably latched")
	}
	if !onDisk() {
		t.Error("LoginPolicyLatchedOnDisk stayed closed after login_policy_v1 durably latched")
	}
}
