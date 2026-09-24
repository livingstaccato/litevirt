package fleet

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/network"
)

// A VM restarted on a new host after a failover gets its networks provisioned
// on that host, and its domain sits on the bridge provisioning made. This is
// the reconciler's pending-start path (internal/health), not CreateVM: the
// VM row simply arrives on the survivor as state=pending.
func TestFleet_FailoverStartProvisionsTheVMsNetworkOnTheNewHost(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	a, survivor := c.Nodes[0], c.Nodes[1]
	ctx := context.Background()

	if _, err := c.SelfClient(a).CreateNetwork(ctx, &pb.CreateNetworkRequest{
		Name: "hc", Type: "isolated", Subnet: "172.16.50.0/24", Dhcp: true,
	}); err != nil {
		t.Fatalf("CreateNetwork: %v", err)
	}

	disk := filepath.Join(t.TempDir(), "root.qcow2")
	if err := os.WriteFile(disk, nil, 0o600); err != nil {
		t.Fatalf("stage disk: %v", err)
	}
	if err := corrosion.InsertVM(ctx, a.DB, corrosion.VMRecord{
		Name: "db", HostName: survivor.Name, Spec: `{"name":"db"}`, State: "pending", CPUActual: 1, MemActual: 512,
	}, []corrosion.InterfaceRecord{
		{VMName: "db", NetworkName: "hc", Ordinal: 0, MAC: "52:54:00:aa:bb:01"},
	}, []corrosion.DiskRecord{
		{VMName: "db", DiskName: "root", HostName: survivor.Name, Path: disk},
	}); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	rec := health.NewReconciler(survivor.Name, t.TempDir(), survivor.DB, survivor.Virt)
	rec.SetNetworkProvision(survivor.Net.Provision)
	rec.ReconcileOnce(ctx)

	want := network.IsolatedBridgeName("hc")
	if dev, ok := survivor.Net.Up("hc"); !ok || dev != want {
		t.Errorf("%s: hc provisioned=%v on %q by the failover start, want %s", survivor.Name, ok, dev, want)
	}
	if got := domainBridges(survivor.Virt.DefinedXML("db")); len(got) != 1 || got[0] != want {
		t.Errorf("db's domain on %s attaches to %v, want [%s]", survivor.Name, got, want)
	}
}
