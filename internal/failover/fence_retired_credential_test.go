package failover

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fence"
)

// The coordinator fences with what GetHost reads, and hands a retired fence
// credential on as retired, never as the old hosts.ipmi_pass column.
//
// Mutation: drop IPMICredentialRetired from the coordinator's HostConfig — red.
func TestFailover_RetiredFenceCredentialReachesTheFence(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	now := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
		Name: "h1", Address: "10.0.0.1", SSHUser: "root", SSHPort: 22,
		GRPCPort: 7443, State: "active", FenceStrategy: "ipmi",
	}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}
	if _, err := db.DB().Exec(`UPDATE hosts SET ipmi_address = '192.0.2.11', ipmi_user = 'probe',
		ipmi_pass = 'Old-Machine-Pass' WHERE name = 'h1'`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB().Exec(`INSERT INTO host_fence_credentials (host_name, ipmi_pass, updated_at, deleted_at)
		VALUES ('h1', '', '2026-06-01T00:00:00Z', '2026-06-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}

	c := NewCoordinator("me", db)
	c.Now = func() time.Time { return now }
	seedLease(t, db, "me", now.Add(leaseDuration))
	var got fence.HostConfig
	called := false
	c.SetFencer(func(_ context.Context, h fence.HostConfig) fence.Result {
		got, called = h, true
		return fence.Result{Method: "ipmi", Detail: "stub", Success: false}
	})
	h, _ := corrosion.GetHost(ctx, db, "h1")
	c.failover(ctx, h)

	if !called {
		t.Fatal("the fencer never ran")
	}
	if got.IPMIPass != "" || !got.IPMICredentialRetired {
		t.Errorf("fence HostConfig has IPMIPass set %v, retired %v; want no password and retired",
			got.IPMIPass != "", got.IPMICredentialRetired)
	}
}
