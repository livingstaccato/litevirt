package fleet

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/vfio"
)

// A compose PCI device named by address alone is placed on the host that has
// that device. The planner used to build its placement request from the
// device's type, count, vendor, sriov and parent only, so the address was
// dropped, the request carried no selector, and every host refused it: on lab 1
// (2026-10-13) `devices: [{address: "0000:01:10.2"}]` failed with
// `no eligible host for VM "hwv": node-5: devices` while the VF was free.
//
// No placement pin: only the device puts hwv on node-1, so a planner that
// ignores the address cannot land it there by luck.

const composePCIAddress = `name: pclhw

vms:
  hwv:
    image: test
    cpu: 1
    memory: 512
    devices:
      - address: "0000:01:10.2"
`

// vfioBoundSysfs is a sysfs in which every PCI device is already on vfio-pci
// (bound by ID: no driver_override) and nothing else exists, so the owner's
// bind and release are the operator's-device no-ops and no test ever reaches
// the real /sys of the machine it runs on.
type vfioBoundSysfs struct{}

func (vfioBoundSysfs) ReadFile(p string) ([]byte, error) {
	if strings.HasSuffix(p, "/driver_override") {
		return []byte("(null)\n"), nil
	}
	return nil, os.ErrNotExist
}
func (vfioBoundSysfs) WriteFile(string, []byte, os.FileMode) error { return nil }
func (vfioBoundSysfs) ReadDir(string) ([]os.DirEntry, error)       { return nil, os.ErrNotExist }
func (vfioBoundSysfs) Readlink(p string) (string, error) {
	if strings.HasSuffix(p, "/driver") {
		return "../../../bus/pci/drivers/vfio-pci", nil
	}
	return "", os.ErrNotExist
}

func TestFleet_ComposeAddressOnlyPCIDeviceIsPlacedWhereItIs(t *testing.T) {
	const addr = "0000:01:10.2"
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	ctx := context.Background()
	serving, holder := c.Nodes[0], c.Nodes[1]
	defer vfio.SetFS(vfioBoundSysfs{})()

	if err := corrosion.InsertImage(ctx, serving.DB, corrosion.ImageRecord{
		Name: "test", Format: "qcow2", SourceURL: "file:///dev/null", Checksum: "deadbeef", SizeBytes: 1024,
	}); err != nil {
		t.Fatalf("seed image: %v", err)
	}
	for _, n := range c.Nodes {
		if err := writeEmptyImageFile(n.Server.ImagePathForTests("test")); err != nil {
			t.Fatalf("stage image file on %s: %v", n.Name, err)
		}
		if err := corrosion.InsertImageHost(ctx, n.DB, corrosion.ImageHostRecord{
			ImageName: "test", HostName: n.Name, Path: n.Server.ImagePathForTests("test"), Status: "ready",
		}); err != nil {
			t.Fatalf("seed image host %s: %v", n.Name, err)
		}
	}
	// The VF exists on node-1 only, free.
	if err := corrosion.UpsertPCIDevice(ctx, holder.DB, corrosion.PCIDeviceRecord{
		HostName: holder.Name, Address: addr, VendorID: "8086", DeviceID: "10ed",
		Type: "network", Driver: "igbvf", IOMMUGroup: 14,
	}); err != nil {
		t.Fatalf("seed PCI device: %v", err)
	}

	msgs := deployCollect(t, ctx, c.SelfClient(serving), composePCIAddress)
	if p := errorPhaseFor(msgs, "hwv"); p != nil {
		t.Fatalf("deploy of an address-only PCI device failed: %s", p.Error)
	}
	for _, p := range msgs {
		if p.Phase == "error" {
			t.Fatalf("deploy failed: %s: %s", p.VmName, p.Error)
		}
	}

	eventually(t, 10*time.Second, "hwv to be created on "+holder.Name, func() bool {
		vm, err := corrosion.GetVM(ctx, holder.DB, "hwv")
		return err == nil && vm != nil && vm.HostName == holder.Name
	})

	// It holds the device it named: the inventory row is its own ...
	devs, err := corrosion.ListPCIDevices(ctx, holder.DB, holder.Name, "")
	if err != nil {
		t.Fatalf("ListPCIDevices: %v", err)
	}
	owner := ""
	for _, d := range devs {
		if d.Address == addr {
			owner = d.VMName
		}
	}
	if owner != "hwv" {
		t.Errorf("%s is owned by %q after the deploy, want hwv", addr, owner)
	}
	// ... the domain on node-1 passes it through ...
	xml := holder.Virt.DefinedXML("hwv")
	hostdev := ""
	if i := strings.Index(xml, "<hostdev"); i >= 0 {
		hostdev = xml[i:]
	}
	if !strings.Contains(hostdev, `bus="0x01"`) || !strings.Contains(hostdev, `slot="0x10"`) || !strings.Contains(hostdev, `function="0x2"`) {
		t.Errorf("hwv's domain does not pass %s through:\n%s", addr, xml)
	}
	// ... and its stored spec still names it by address, so a re-apply of the
	// same file compares equal (no device change, nothing to recreate).
	spec := storedSpec(t, ctx, holder, "hwv")
	if len(spec.Devices) != 1 || spec.Devices[0].Address != addr || spec.Devices[0].Type != "" {
		t.Errorf("stored devices = %+v, want one address-only %s", spec.Devices, addr)
	}
	before := len(holder.Virt.EventLog())
	deployClean(t, ctx, c.SelfClient(serving), composePCIAddress)
	for _, e := range holder.Virt.EventLog()[before:] {
		if e.Domain == "hwv" && (e.Op == "undefine" || e.Op == "destroy" || e.Op == "define") {
			t.Errorf("re-applying the unchanged file touched hwv: %s", e.Op)
		}
	}
}

const composeOwnGPU = `name: gpus

vms:
  ml:
    image: test
    cpu: 1
    memory: 512
    devices:
      - type: gpu
        mapping: accel
`

// An update of a type+mapping GPU VM on a host whose only GPU it holds itself
// is planned onto that GPU. With the VM's own device counted as taken, the
// planner found no free GPU for the update and refused even a label change.
func TestFleet_ComposeUpdateOfAGPUVMReusesItsOwnDevice(t *testing.T) {
	const gpu = "0000:41:00.0"
	_, node, client := newComposeFailNode(t)
	ctx := context.Background()
	defer vfio.SetFS(vfioBoundSysfs{})()

	if err := corrosion.UpsertPCIDevice(ctx, node.DB, corrosion.PCIDeviceRecord{
		HostName: node.Name, Address: gpu, VendorID: "10de", DeviceID: "2236",
		Type: "gpu", Driver: "nvidia", IOMMUGroup: 7,
	}); err != nil {
		t.Fatalf("seed GPU: %v", err)
	}
	if err := corrosion.CreateResourceMapping(ctx, node.DB, "accel", ""); err != nil {
		t.Fatalf("CreateResourceMapping: %v", err)
	}
	if err := corrosion.AddMappingDevice(ctx, node.DB, "accel", node.Name, gpu, "10de", ""); err != nil {
		t.Fatalf("AddMappingDevice: %v", err)
	}

	deployClean(t, ctx, client, composeOwnGPU)
	waitRunning(t, ctx, node, "ml")
	owner := func() string {
		devs, err := corrosion.ListPCIDevices(ctx, node.DB, node.Name, "")
		if err != nil {
			t.Fatalf("ListPCIDevices: %v", err)
		}
		for _, d := range devs {
			if d.Address == gpu {
				return d.VMName
			}
		}
		return ""
	}
	if o := owner(); o != "ml" {
		t.Fatalf("GPU owned by %q after the deploy, want ml", o)
	}

	labelled := edit(t, composeOwnGPU, "    devices:\n", "    labels:\n      tier: gpu\n    devices:\n")
	before := len(node.Virt.EventLog())
	deployClean(t, ctx, client, labelled)
	for _, e := range node.Virt.EventLog()[before:] {
		if e.Domain == "ml" && (e.Op == "undefine" || e.Op == "destroy") {
			t.Errorf("a label change recreated ml: %s", e.Op)
		}
	}
	if got := storedSpec(t, ctx, node, "ml").Labels["tier"]; got != "gpu" {
		t.Errorf("label tier = %q after the update, want gpu", got)
	}
	if o := owner(); o != "ml" {
		t.Errorf("GPU owned by %q after the update, want ml", o)
	}
}
