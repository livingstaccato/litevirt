package daemon

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// TestWireHostRuntimeGate_TracksTheDurableLatch: the host_runtime gate follows
// the REAL durable latch of host_runtime_split_v1, closed before and open
// after, read from the marker on disk because the boot report is written
// before the checker exists. Every other test of the split injects the gate
// directly, so this is the one that fails if the production wiring goes.
func TestWireHostRuntimeGate_TracksTheDurableLatch(t *testing.T) {
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
	d.wireHostRuntimeGate()

	if db.MayWriteHostRuntime() {
		t.Fatal("the host runtime gate is open before host_runtime_split_v1 has durably latched")
	}
	if !checker.Enforced(ctx, capabilities.HostRuntimeSplitV1) || !checker.DurablyLatched(capabilities.HostRuntimeSplitV1) {
		t.Fatal("host_runtime_split_v1 did not latch durably with the only host advertising it; the rest is vacuous")
	}
	if !HostRuntimeLatchedOnDisk(dataDir)() {
		t.Error("HostRuntimeLatchedOnDisk does not see the marker the checker wrote")
	}
	if !db.MayWriteHostRuntime() {
		t.Error("the daemon's host runtime gate stayed closed after host_runtime_split_v1 durably latched")
	}
}

// TestRunWiresTheHostRuntimeGate: see TestRunWiresEveryCredentialGate.
func TestRunWiresTheHostRuntimeGate(t *testing.T) {
	assertRunCalls(t, "wireHostRuntimeGate", "runHostRuntimeSplit")
}
