package health

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/storage"
)

// A relocation recreate reads the template the container was created from on
// a host that never judged it. The protected places are refused there too
// (storage.CheckReadDir), whoever created the container: the row stays pending
// and nothing is copied.
func TestContainerCheck_RelocateRecreate_ProtectedTemplatePathRefused(t *testing.T) {
	db := testLogicDB(t)
	ctx := context.Background()
	rt := newFakeCtRuntime()
	insertCt(t, db, corrosion.ContainerRecord{
		HostName: "node1", Name: "ct1", State: "pending",
		StateDetail: corrosion.ContainerRelocateRecreateDetail,
		Image:       "x",
		CreateSpec:  corrosion.EncodeCreateSpec(corrosion.ContainerCreateSpec{Template: "rootfs:/etc"}),
	})
	c := NewContainerChecker("node1", db, rt)
	c.checkContainer(ctx, mustGetCt(t, db, "ct1"), time.Now())
	if rt.lastCreate.Name != "" {
		t.Fatalf("recreated from a protected host path: %+v", rt.lastCreate)
	}
	fresh := mustGetCt(t, db, "ct1")
	if fresh.State != "pending" || fresh.StateDetail != corrosion.ContainerRelocateRecreateDetail {
		t.Fatalf("row = %q/%q, want it left pending for the operator", fresh.State, fresh.StateDetail)
	}
}

// A relocation recreate rebuilds a managed NIC from the spec's bare address;
// like a create, the runtime NIC carries the network's prefix and gateway.
func TestContainerCheck_RelocateRecreate_ManagedNICCarriesPrefixAndGateway(t *testing.T) {
	db := testLogicDB(t)
	ctx := context.Background()
	rt := newFakeCtRuntime()
	if err := corrosion.UpsertNetwork(ctx, db, corrosion.NetworkRecord{
		Name: "lxtnet", Type: "bridge", Config: `{"Interface":"br-lxt","Subnet":"172.16.77.0/24"}`,
	}); err != nil {
		t.Fatal(err)
	}
	insertCt(t, db, corrosion.ContainerRecord{
		HostName: "node1", Name: "ct1", State: "pending",
		StateDetail: corrosion.ContainerRelocateRecreateDetail,
		Image:       "alpine:3.19",
		CreateSpec: corrosion.EncodeCreateSpec(corrosion.ContainerCreateSpec{
			Template: "download", Distro: "alpine",
			Networks: []corrosion.ContainerNetwork{{Name: "eth0", NetworkName: "lxtnet", IP: "172.16.77.9", MAC: "52:54:00:00:00:09"}},
		}),
	})
	c := NewContainerChecker("node1", db, rt)
	c.checkContainer(ctx, mustGetCt(t, db, "ct1"), time.Now())
	if len(rt.lastCreate.Network) != 1 {
		t.Fatalf("recreate NICs = %+v", rt.lastCreate.Network)
	}
	if n := rt.lastCreate.Network[0]; n.IP != "172.16.77.9/24" || n.Gateway != "172.16.77.1" {
		t.Fatalf("recreated NIC = %+v, want 172.16.77.9/24 via 172.16.77.1", n)
	}
}

// A container an Admin created from a template in the LXC store is recreated
// from it after a host loss, as on main.
func TestContainerCheck_RelocateRecreate_TemplateInTheLXCStore(t *testing.T) {
	store := t.TempDir()
	restore := storage.SetSecretRootsForTest([]string{"/etc", store})
	defer restore()
	tpl := filepath.Join(store, "base", "rootfs")
	if err := os.MkdirAll(filepath.Join(tpl, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	db := testLogicDB(t)
	rt := newFakeCtRuntime()
	insertCt(t, db, corrosion.ContainerRecord{
		HostName: "node1", Name: "ct1", State: "pending",
		StateDetail: corrosion.ContainerRelocateRecreateDetail, Image: "x",
		CreateSpec: corrosion.EncodeCreateSpec(corrosion.ContainerCreateSpec{Template: tpl}),
	})
	c := NewContainerChecker("node1", db, rt)
	c.SetContainerLxcpath(store)
	c.checkContainer(context.Background(), mustGetCt(t, db, "ct1"), time.Now())
	if rt.lastCreate.Template != tpl {
		t.Fatalf("not recreated from the LXC-store template: %+v", rt.lastCreate)
	}
}
