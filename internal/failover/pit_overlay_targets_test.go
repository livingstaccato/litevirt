package failover

import (
	"context"
	"slices"
	"testing"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// P2 of the #256 re-review 5: once the pit_overlay feature is in use, a VM is
// never restarted on a host recorded as isolated (rolled back below a latched
// token, WAL-quarantined: possibly a build that knows nothing of overlays and
// would start the VM on the bare disk, dropping the window's writes). Before
// any use, nothing is filtered: recovery is as it was.
//
// Mutations "filter ignores the isolation" and "filter before any use" — red.
func TestPITOverlaySafeTargets_AnIsolatedHostOnlyOnceOverlaysAreInUse(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	db.SetClusterPolicyGate(func() bool { return true })
	for _, h := range []string{"h1", "h2", "rolled-back"} {
		if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
			Name: h, Address: "10.0.0.1", SSHUser: "root", SSHPort: 22, GRPCPort: 7443, State: "active", FenceStrategy: "manual",
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := corrosion.IsolateHost(ctx, db, "h1", "rolled-back", corrosion.IsolationRolledBackLatch); err != nil {
		t.Fatal(err)
	}
	all, err := corrosion.ListHosts(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	names := func(hs []corrosion.HostRecord) []string {
		var out []string
		for _, h := range hs {
			out = append(out, h.Name)
		}
		slices.Sort(out)
		return out
	}
	c := newTestCoordinator("h1", db)
	if got := names(c.pitOverlaySafeTargets(ctx, all)); !slices.Equal(got, []string{"h1", "h2", "rolled-back"}) {
		t.Fatalf("before pit_overlay is used: %v, want every candidate", got)
	}
	if err := corrosion.RecordReleaseFeatureUse(ctx, db, capabilities.ReleaseToken, string(capabilities.FeaturePITOverlay), "h2", true); err != nil {
		t.Fatal(err)
	}
	if got := names(c.pitOverlaySafeTargets(ctx, all)); !slices.Equal(got, []string{"h1", "h2"}) {
		t.Fatalf("with pit_overlay in use: %v, want the isolated host left out", got)
	}
}
