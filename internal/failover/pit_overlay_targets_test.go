package failover

import (
	"context"
	"slices"
	"strings"
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

// I1 and m2 of the switch review: a peer whose own Ping says it is
// WAL-quarantined is no recovery target once pit_overlay is used, before the
// HA monitor has recorded it isolated — in the batch placement and in the
// check of an adopted claim's destination (vmFitsOn).
//
// Mutations "reported quarantine ignored" and "vmFitsOn unfiltered" — red.
func TestPITOverlaySafeTargets_AReportedQuarantineIsNoTargetBeforeItsIsolation(t *testing.T) {
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
	all, _ := corrosion.ListHosts(ctx, db)
	c := newTestCoordinator("h1", db)
	asked := 0
	c.PeerWALQuarantined = func(_ context.Context, peer string) bool { asked++; return peer == "rolled-back" }
	var rolled corrosion.HostRecord
	for _, h := range all {
		if h.Name == "rolled-back" {
			rolled = h
		}
	}
	vm := corrosion.VMRecord{Name: "web", HostName: "h2", State: "running", Spec: `{"name":"web","cpu":1,"memory_mib":256}`}
	if p := c.vmFitsOn(ctx, vm, "h2", rolled); strings.Contains(p, "WAL-quarantined") {
		t.Fatalf("before pit_overlay is used the destination is refused: %q", p)
	}
	if asked != 0 {
		t.Fatalf("peers were asked %d time(s) before pit_overlay is used", asked)
	}
	if err := corrosion.RecordReleaseFeatureUse(ctx, db, capabilities.ReleaseToken, string(capabilities.FeaturePITOverlay), "h2", true); err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, h := range c.pitOverlaySafeTargets(ctx, all) {
		names = append(names, h.Name)
	}
	slices.Sort(names)
	if !slices.Equal(names, []string{"h1", "h2"}) {
		t.Fatalf("with pit_overlay in use: %v, want the self-reported quarantined host left out", names)
	}
	if p := c.vmFitsOn(ctx, vm, "h2", rolled); !strings.Contains(p, "WAL-quarantined") {
		t.Fatalf("an adopted destination that reports itself quarantined: %q, want refused", p)
	}
}
