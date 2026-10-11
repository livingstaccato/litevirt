package firewall

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestCorrosionPlanLoader_ContainerGuardFollowsMigration (re-review m-f): a
// container NIC's guard record is keyed by the host the container was created
// on. A container that migrated or was relocated keeps its guard on its new
// host, found by its name and MAC.
func TestCorrosionPlanLoader_ContainerGuardFollowsMigration(t *testing.T) {
	ctx := context.Background()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	db.SetClusterPolicyGate(func() bool { return true })
	if err := corrosion.UpsertContainer(ctx, db, corrosion.ContainerRecord{HostName: "host-b", Name: "ct-web", State: "running"}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpsertContainerInterface(ctx, db, corrosion.ContainerInterfaceRecord{
		HostName: "host-b", CtName: "ct-web", NetworkName: "prod", MAC: "52:00:00:00:00:10", IP: "10.0.0.11", VethDevice: "lvc0abc",
	}); err != nil {
		t.Fatal(err)
	}
	// Created on host-a; the record stayed under host-a's name.
	if err := corrosion.PutNICGuard(ctx, db, capabilities.GrantForTest(t, capabilities.FeatureNICGuards), corrosion.NICGuardRecord{
		VMName: corrosion.ContainerGuardOwner("host-a", "ct-web"), MAC: "52:00:00:00:00:10", Mode: corrosion.NICGuardOn,
	}, "t"); err != nil {
		t.Fatal(err)
	}
	// Another container's record under the same name on another host, with
	// another MAC, must not be picked up.
	if err := corrosion.PutNICGuard(ctx, db, capabilities.GrantForTest(t, capabilities.FeatureNICGuards), corrosion.NICGuardRecord{
		VMName: corrosion.ContainerGuardOwner("host-c", "ct-web"), MAC: "52:00:00:00:00:99", Mode: corrosion.NICGuardOff,
	}, "t"); err != nil {
		t.Fatal(err)
	}
	plan, err := CorrosionPlanLoader(db, "host-b", Plan{}, LoaderOptions{})(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.NICs) != 1 || plan.NICs[0].Guard == nil {
		t.Fatalf("the migrated container's NIC is unguarded: %+v", plan.NICs)
	}
}

// TestCorrosionPlanLoader_LBSourcesIncludePeerHosts (re-review m-d, m6):
// haproxy runs on the LB's hosts, which may not be the backend's; it reaches a
// backend here from its own host's address, which must be an allowed LB
// source — and no other host's is.
func TestCorrosionPlanLoader_LBSourcesIncludePeerHosts(t *testing.T) {
	ctx := context.Background()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{Name: "lb-host", Address: "192.0.2.21", State: "active"}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{Name: "other", Address: "192.0.2.22", State: "active"}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpsertLBConfig(ctx, db, corrosion.LBConfigRecord{Name: "web", VIP: "10.0.0.100", Hosts: `["lb-host"]`, Ports: `[{"target":8080}]`, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpsertLBBackend(ctx, db, corrosion.LBBackendRecord{LBName: "web", Name: "b1", Address: "10.0.0.20", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	plan, err := CorrosionPlanLoader(db, "backend-host", Plan{}, LoaderOptions{})(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, s := range plan.LBSources {
		found = found || s == "192.0.2.21"
	}
	if !found || len(plan.LBBackends) != 1 {
		t.Errorf("LB sources %v (backends %v) lack the LB host's address", plan.LBSources, plan.LBBackends)
	}
	// Only the hosts the LB runs on (re-review m6): any other host's address
	// would let its masqueraded guests reach a backend past its group.
	for _, s := range plan.LBSources {
		if s == "192.0.2.22" {
			t.Errorf("a host the LB does not run on is an LB source: %v", plan.LBSources)
		}
	}
}
