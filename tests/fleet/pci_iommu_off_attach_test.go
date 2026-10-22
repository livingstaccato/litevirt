// Fleet scenario: a PCI attach on a host with the IOMMU off is refused, with
// the reason, over the real AttachDevice path (gRPC over mTLS into
// attachPCIEntry → executePCIAttach → resolveDeviceSpec → checkIOMMUConflict).
//
// The device is in the inventory with no IOMMU group, which is what a scan
// records on a host whose kernel has the IOMMU off. The check used to read that
// as "no conflict possible" and let the device through.

package fleet

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pci"
)

func TestFleet_PCIAttachRefusedWhenIOMMUOff(t *testing.T) {
	c := New(t, Options{Nodes: 2})
	ctx := context.Background()
	gates := gateAll(t, c)
	latchOperationProtocol(t, c, gates)

	const (
		vmName  = "vm-iommu-off"
		pciAddr = "0000:41:00.0"
	)
	owner := c.Nodes[0]

	// A fake sysfs whose kernel lists no IOMMU groups: the IOMMU is off.
	root := t.TempDir()
	groups := filepath.Join(root, "kernel", "iommu_groups")
	devices := filepath.Join(root, "bus", "pci", "devices")
	for _, d := range []string{groups, filepath.Join(devices, pciAddr)} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(pci.SetSysIOMMUGroups(groups))
	t.Cleanup(pci.SetSysDevices(devices))

	if err := corrosion.InsertVM(ctx, owner.DB, corrosion.VMRecord{
		Name: vmName, HostName: owner.Name, Spec: "{}", State: "stopped",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	if err := corrosion.UpsertPCIDevice(ctx, owner.DB, corrosion.PCIDeviceRecord{
		HostName: owner.Name, Address: pciAddr,
		VendorID: "10de", DeviceID: "1eb8", Type: "gpu", IOMMUGroup: -1,
	}); err != nil {
		t.Fatalf("UpsertPCIDevice: %v", err)
	}
	if err := owner.Virt.DefineDomain(
		`<domain type='kvm'><name>` + vmName + `</name><devices></devices></domain>`); err != nil {
		t.Fatalf("DefineDomain: %v", err)
	}
	// Latch hardware_v2 so the stopped-VM attach is not refused by its gate first.
	backfillAll(t, c)
	for _, n := range c.Nodes {
		eventually(t, 10*time.Second, "hardware_v2 to latch on "+n.Name, func() bool {
			return gates[n.Name].Enforced(ctx, capabilities.HardwareV2)
		})
	}

	_, err := c.SelfClient(owner).AttachDevice(ctx, &pb.AttachDeviceRequest{
		VmName:    vmName,
		PciDevice: &pb.DeviceSpec{Address: pciAddr},
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("attach on an IOMMU-off host: got %v, want a FailedPrecondition refusal", err)
	}
	for _, want := range []string{"IOMMU is off", groups, "intel_iommu=on", "amd_iommu=off", "iommu=off", "lv host rescan " + owner.Name} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal %q does not name %q", err.Error(), want)
		}
	}

	// Refused before anything was taken: the device is unowned and the VM holds
	// no PCI intent.
	devs, lerr := corrosion.ListPCIDevices(ctx, owner.DB, owner.Name, "")
	if lerr != nil {
		t.Fatalf("ListPCIDevices: %v", lerr)
	}
	for _, d := range devs {
		if d.Address == pciAddr && d.VMName != "" {
			t.Fatalf("device %s owned by %q after a refused attach", pciAddr, d.VMName)
		}
	}
	intents, ierr := corrosion.ListVMPCIIntents(ctx, owner.DB, vmName)
	if ierr != nil {
		t.Fatalf("ListVMPCIIntents: %v", ierr)
	}
	if len(intents) != 0 {
		t.Fatalf("VM holds %d PCI intent(s) after a refused attach: %+v", len(intents), intents)
	}
}
