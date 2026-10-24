package health

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// A relocated container does not take another workload's live address, under
// any spelling, even one its own released lease once held; it falls back to DHCP.
func TestContainerCheck_RelocateRecreate_RefusesAnotherWorkloadsAddress(t *testing.T) {
	db := testLogicDB(t)
	ctx := context.Background()
	rt := newFakeCtRuntime()
	if err := db.Execute(ctx,
		`INSERT INTO ip_allocations (network, ip, mac, vm_name, owner_kind, owner_host, allocated_at, updated_at)
		 VALUES ('lxtnet', '172.16.77.50', 'mac-4', 'lxt4', 'ct', 'node9', '2026-10-01T00:00:00Z', ?)`, db.NowTS()); err != nil {
		t.Fatal(err)
	}
	if err := db.Execute(ctx,
		`INSERT INTO ip_allocations (network, ip, mac, vm_name, owner_kind, owner_host, allocated_at, updated_at)
		 VALUES ('lxtnet', '172.16.77.50/24', 'mac-3', 'lxt3', 'ct', 'node1', '2026-09-01T00:00:00Z', ?)`, db.NowTS()); err != nil {
		t.Fatal(err)
	}
	spec := corrosion.EncodeCreateSpec(corrosion.ContainerCreateSpec{
		Networks: []corrosion.ContainerNetwork{{Name: "eth0", NetworkName: "lxtnet", Bridge: "br-lxt", IP: "172.16.77.50/24", MAC: "mac-3"}},
	})
	insertCt(t, db, corrosion.ContainerRecord{
		HostName: "node1", Name: "lxt3", State: "pending",
		StateDetail: corrosion.ContainerRelocateRecreateDetail,
		Image:       "alpine:3.19", CreateSpec: spec,
	})
	c := NewContainerChecker("node1", db, rt)
	c.checkContainer(ctx, mustGetCt(t, db, "lxt3"), time.Now())
	if len(rt.lastCreate.Network) != 1 || rt.lastCreate.Network[0].IP != "" {
		t.Fatalf("recreated NIC = %+v, want DHCP (no claim on lxt4's address)", rt.lastCreate.Network)
	}
}
