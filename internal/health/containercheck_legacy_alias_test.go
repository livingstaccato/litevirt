package health

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// M1: a container whose static address was already shared with another
// workload before this release (lease "172.16.77.50" for lxt4 beside its own
// "172.16.77.50/24") keeps that address when failover recreates it here,
// instead of being dropped to DHCP.
func TestContainerCheck_RelocateRecreate_KeepsPreexistingAliasedIP(t *testing.T) {
	db := testLogicDB(t)
	ctx := context.Background()
	rt := newFakeCtRuntime()
	if err := db.Execute(ctx,
		`INSERT INTO ip_allocations (network, ip, mac, vm_name, owner_kind, owner_host, allocated_at, updated_at)
		 VALUES ('lxtnet', '172.16.77.50', 'mac-4', 'lxt4', 'ct', 'node9', '2026-10-01T00:00:00Z', ?)`, db.NowTS()); err != nil {
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

	if len(rt.lastCreate.Network) != 1 || rt.lastCreate.Network[0].IP != "172.16.77.50/24" {
		t.Fatalf("recreated NIC = %+v, want it to keep 172.16.77.50/24", rt.lastCreate.Network)
	}
}
