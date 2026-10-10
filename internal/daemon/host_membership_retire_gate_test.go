package daemon

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// TestWireHostMembershipRetireGate_TracksTheDurableLatch: the gate that stops
// writing the hosts copy follows the REAL durable latch of
// host_membership_retire_v1, read from the marker on disk like the split gate
// (it must be wired before the checker exists).
func TestWireHostMembershipRetireGate_TracksTheDurableLatch(t *testing.T) {
	ctx := context.Background()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("init schema: %v", err)
	}
	for _, h := range []string{"host-a", "host-b"} {
		if err := corrosion.RegisterHost(ctx, db, corrosion.HostRecord{
			Name: h, Address: "10.0.0.1", State: "active", Role: "worker",
		}); err != nil {
			t.Fatalf("register host: %v", err)
		}
	}
	dataDir := t.TempDir()
	checker := health.NewChecker("host-a", "/etc/litevirt/pki", db)
	checker.SetActivationMarker(health.ActivationMarkerBase(dataDir))
	checker.SetPeerPinger(func(context.Context, string) ([]string, time.Time, error) {
		return capabilities.Supported(), time.Time{}, nil
	})
	d := &Daemon{db: db, checker: checker, cfg: &Config{DataDir: dataDir}}
	d.wireHostMembershipGate()
	d.wireHostMembershipRetireGate()

	hostsTS := func() string {
		rows, err := db.Query(ctx, `SELECT updated_at FROM hosts WHERE name = 'host-b'`)
		if err != nil || len(rows) != 1 {
			t.Fatal(err)
		}
		return rows[0].String("updated_at")
	}
	for _, tok := range []string{capabilities.HostMembershipSplitV1, capabilities.HostMembershipRetireV1} {
		if !checker.Enforced(ctx, tok) || !checker.DurablyLatched(tok) {
			t.Fatalf("%s did not latch durably; the rest is vacuous", tok)
		}
	}
	if _, err := db.SplitHostMembership(ctx); err != nil || !db.HostMembershipLive() {
		t.Fatalf("split pass: %v", err)
	}
	if !HostMembershipRetireLatchedOnDisk(dataDir)() {
		t.Error("HostMembershipRetireLatchedOnDisk does not see the marker the checker wrote")
	}
	before := hostsTS()
	if err := corrosion.UpdateHostState(ctx, db, "host-b", "draining"); err != nil {
		t.Fatal(err)
	}
	if hostsTS() != before {
		t.Error("the daemon's retire gate stayed closed after host_membership_retire_v1 durably latched: " +
			"a state change still wrote the hosts row")
	}
}
