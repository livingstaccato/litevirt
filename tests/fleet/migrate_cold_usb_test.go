// Fleet scenario: a cold migration of a VM with a mapped USB device defines it
// on the target with the TARGET's device.
//
// A USB resource mapping says, per host, which device stands in for one name:
// here a Logitech receiver on the source and a CH340 serial adapter on the
// target. The source's domain definition names the source's device, and that
// definition is what a cold migration ships. Only the target can say which
// device it has (a bus-port is read from its own sysfs), so the target
// re-resolves the VM's USB devices before it defines the domain. Multi-node by
// construction: the define runs in the target daemon, over real gRPC.

package fleet

import (
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

func migrateUSB(t *testing.T, c *Cluster, src *Node, vm, target string, strategy pb.MigrateStrategy) error {
	t.Helper()
	st, err := c.SelfClient(src).MigrateVM(context.Background(), &pb.MigrateVMRequest{
		VmName: vm, TargetHost: target, Strategy: strategy,
	})
	if err != nil {
		return err
	}
	for {
		if _, rerr := st.Recv(); rerr == io.EOF {
			return nil
		} else if rerr != nil {
			return rerr
		}
	}
}

func TestFleet_ColdMigrationReResolvesMappedUSBOnTheTarget(t *testing.T) {
	c := New(t, Options{Nodes: 3, SharedCRDT: true})
	t.Cleanup(c.Stop)
	ctx := context.Background()
	src, dst, other := c.Nodes[0], c.Nodes[1], c.Nodes[2]

	if err := corrosion.CreateResourceMapping(ctx, src.DB, "dongle", "per-host USB stand-in"); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.AddMappingDevice(ctx, src.DB, "dongle", src.Name, "usb:046d:c52b", "", ""); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.AddMappingDevice(ctx, src.DB, "dongle", dst.Name, "usb:1a86:7523", "", ""); err != nil {
		t.Fatal(err)
	}

	spec, _ := json.Marshal(&pb.VMSpec{Name: "u1", Cpu: 1, MemoryMib: 256,
		UsbDevices: []*pb.USBDeviceSpec{{Mapping: "dongle"}}})
	if err := corrosion.InsertVM(ctx, src.DB, corrosion.VMRecord{
		Name: "u1", HostName: src.Name, State: "stopped", Spec: string(spec), CPUActual: 1, MemActual: 256,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	if err := src.Virt.DefineDomain(`<domain type='kvm'><name>u1</name><uuid>11111111-2222-4333-8444-666666666666</uuid><devices>` +
		`<hostdev mode='subsystem' type='usb' managed='yes'><source><vendor id='0x046d'/><product id='0xc52b'/></source></hostdev>` +
		`</devices></domain>`); err != nil {
		t.Fatalf("define source domain: %v", err)
	}

	// A host the mapping has no device on is refused too.
	if err := migrateUSB(t, c, src, "u1", other.Name, pb.MigrateStrategy_MIGRATE_COLD); status.Code(err) != codes.FailedPrecondition ||
		!strings.Contains(err.Error(), "dongle") {
		t.Fatalf("cold migrate to a host outside the mapping = %v; want a refusal naming the mapping", err)
	}

	if err := migrateUSB(t, c, src, "u1", dst.Name, pb.MigrateStrategy_MIGRATE_COLD); err != nil {
		t.Fatalf("cold migrate: %v", err)
	}
	x, err := dst.Virt.DumpXMLInactive("u1")
	if err != nil {
		t.Fatalf("target has no domain: %v", err)
	}
	if !strings.Contains(x, `0x1a86`) || !strings.Contains(x, `0x7523`) {
		t.Fatalf("target domain does not name the target's mapped device:\n%s", x)
	}
	if strings.Contains(x, `0x046d`) {
		t.Fatalf("target domain still names the SOURCE's device:\n%s", x)
	}
	vm, _ := corrosion.GetVM(ctx, dst.DB, "u1")
	if vm == nil || vm.HostName != dst.Name {
		t.Fatalf("VM row not handed to the target: %+v", vm)
	}
}
