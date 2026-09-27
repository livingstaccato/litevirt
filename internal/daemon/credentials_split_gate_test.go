package daemon

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// TestWireCredentialsSplitGate_TracksTheDurableLatch: the credential-table
// gate follows the REAL durable latch, closed before and open after. Every
// other test of the split injects the gate directly, so this is the only test
// that fails if the production wiring is deleted — and an unwired gate is
// silent, because it fails closed and looks exactly like a mid-roll.
//
// It also pins CredentialsSplitLatchedOnDisk, the gate `lv user reset-admin`
// uses: it must agree with the checker on the same marker, or the CLI would
// write a password only to the column the daemon has stopped reading.
func TestWireCredentialsSplitGate_TracksTheDurableLatch(t *testing.T) {
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
	checker.SetActivationMarker(filepath.Join(dataDir, activationMarkerPrefix))
	checker.SetPeerPinger(func(context.Context, string) ([]string, time.Time, error) {
		return capabilities.Supported(), time.Time{}, nil
	})

	d := &Daemon{db: db, checker: checker, cfg: &Config{}}
	d.wireCredentialsSplitGate()
	onDisk := CredentialsSplitLatchedOnDisk(dataDir)

	if db.MayWriteCredentialTables() || onDisk() {
		t.Fatal("the credentials split gate is open before credentials_split_v1 has durably latched")
	}
	if !checker.Enforced(ctx, capabilities.CredentialsSplitV1) || !checker.DurablyLatched(capabilities.CredentialsSplitV1) {
		t.Fatal("credentials_split_v1 did not latch durably with the only host advertising it; the rest is vacuous")
	}
	if !db.MayWriteCredentialTables() {
		t.Error("the daemon's credentials split gate stayed closed after credentials_split_v1 durably latched")
	}
	if !onDisk() {
		t.Error("CredentialsSplitLatchedOnDisk does not see the marker the checker wrote; " +
			"`lv user reset-admin` would write only the old column after the split")
	}
}
