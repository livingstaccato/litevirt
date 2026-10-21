package fleet

import (
	"context"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/vfio"
)

// seedPCI puts devs into node's inventory.
func seedPCI(t *testing.T, ctx context.Context, node *Node, devs ...corrosion.PCIDeviceRecord) {
	t.Helper()
	for _, d := range devs {
		d.HostName = node.Name
		if err := corrosion.UpsertPCIDevice(ctx, node.DB, d); err != nil {
			t.Fatalf("seed PCI %s: %v", d.Address, err)
		}
	}
}

func pciOwners(t *testing.T, ctx context.Context, node *Node) map[string]string {
	t.Helper()
	devs, err := corrosion.ListPCIDevices(ctx, node.DB, node.Name, "")
	if err != nil {
		t.Fatalf("ListPCIDevices: %v", err)
	}
	out := map[string]string{}
	for _, d := range devs {
		out[d.Address] = d.VMName
	}
	return out
}

const composeGPUsAndVF = `name: pair

vms:
  mix:
    image: test
    cpu: 1
    memory: 512
    devices:
      - type: gpu
        count: 2
      - address: "0000:81:00.1"
`

// A `count: 2` GPU entry followed by an address-only VF. The deploy paired
// the planner's assignments with the spec's devices by position, so the VF
// entry was given the second GPU's address, and an address entry is bound
// exactly: the VM got three GPUs and no VF.
func TestFleet_ComposeCountedGPUsThenAVFGetTheVF(t *testing.T) {
	_, node, client := newComposeFailNode(t)
	ctx := context.Background()
	defer vfio.SetFS(vfioBoundSysfs{})()
	// One IOMMU group per device, as on a host with the IOMMU on. A group of -1
	// (no IOMMU) is refused for passthrough.
	seedPCI(t, ctx, node,
		corrosion.PCIDeviceRecord{Address: "0000:41:00.0", Type: "gpu", VendorID: "10de", IOMMUGroup: 41},
		corrosion.PCIDeviceRecord{Address: "0000:42:00.0", Type: "gpu", VendorID: "10de", IOMMUGroup: 42},
		corrosion.PCIDeviceRecord{Address: "0000:43:00.0", Type: "gpu", VendorID: "10de", IOMMUGroup: 43},
		corrosion.PCIDeviceRecord{Address: "0000:81:00.1", Type: "network", VendorID: "8086", IOMMUGroup: 81},
	)

	deployClean(t, ctx, client, composeGPUsAndVF)
	waitRunning(t, ctx, node, "mix")

	owners := pciOwners(t, ctx, node)
	gpus := 0
	for _, a := range []string{"0000:41:00.0", "0000:42:00.0", "0000:43:00.0"} {
		if owners[a] == "mix" {
			gpus++
		}
	}
	if owners["0000:81:00.1"] != "mix" || gpus != 2 {
		t.Fatalf("mix holds %d GPUs and the VF owned by %q (%v), want 2 GPUs and the VF", gpus, owners["0000:81:00.1"], owners)
	}
	xml := node.Virt.DefinedXML("mix")
	if n := strings.Count(xml, "<hostdev"); n != 3 || !strings.Contains(xml, `bus="0x81"`) {
		t.Fatalf("mix's domain has %d hostdevs (want 3, the VF on bus 0x81 among them):\n%s", n, xml)
	}
}

const composeGPUMapping = `name: gpus

vms:
  ml:
    image: IMG
    cpu: 1
    memory: 512
    devices:
      - type: gpu
        mapping: accel
`

// setupMappedGPU deploys ml holding the node's only GPU through mapping accel;
// the GPU shares IOMMU group 7 with a second device, free at the deploy.
func setupMappedGPU(t *testing.T) (context.Context, *Node, pb.LiteVirtClient) {
	t.Helper()
	_, node, client := newComposeFailNode(t)
	ctx := context.Background()
	t.Cleanup(vfio.SetFS(vfioBoundSysfs{}))
	seedPCI(t, ctx, node,
		corrosion.PCIDeviceRecord{Address: "0000:41:00.0", Type: "gpu", VendorID: "10de", IOMMUGroup: 7},
		corrosion.PCIDeviceRecord{Address: "0000:41:00.1", Type: "audio", VendorID: "10de", IOMMUGroup: 7},
	)
	if err := corrosion.CreateResourceMapping(ctx, node.DB, "accel", ""); err != nil {
		t.Fatalf("CreateResourceMapping: %v", err)
	}
	if err := corrosion.AddMappingDevice(ctx, node.DB, "accel", node.Name, "0000:41:00.0", "10de", ""); err != nil {
		t.Fatalf("AddMappingDevice: %v", err)
	}
	if err := corrosion.InsertImage(ctx, node.DB, corrosion.ImageRecord{Name: "test2", Format: "qcow2", SourceURL: "file:///dev/null", Checksum: "deadbeef", SizeBytes: 1024}); err != nil {
		t.Fatalf("seed image: %v", err)
	}
	if err := writeEmptyImageFile(node.Server.ImagePathForTests("test2")); err != nil {
		t.Fatalf("stage image file: %v", err)
	}
	deployClean(t, ctx, client, strings.Replace(composeGPUMapping, "IMG", "test", 1))
	waitRunning(t, ctx, node, "ml")
	if o := pciOwners(t, ctx, node)["0000:41:00.0"]; o != "ml" {
		t.Fatalf("GPU owned by %q after the deploy, want ml", o)
	}
	return ctx, node, client
}

// An image change recreates ml: deleted, then created again on the GPU it
// held. The planner and the pre-delete check both count that GPU as ml's own.
func TestFleet_ComposeRecreateOfAGPUVMRetakesItsOwnGPU(t *testing.T) {
	ctx, node, client := setupMappedGPU(t)
	before, _ := corrosion.GetVM(ctx, node.DB, "ml")

	deployClean(t, ctx, client, strings.Replace(composeGPUMapping, "IMG", "test2", 1))
	waitRunning(t, ctx, node, "ml")
	after, _ := corrosion.GetVM(ctx, node.DB, "ml")
	if after == nil || before == nil || after.CreatedAt == before.CreatedAt {
		t.Fatalf("ml before %+v after %+v: want it recreated", before, after)
	}
	if got := storedSpec(t, ctx, node, "ml").Image; got != "test2" {
		t.Errorf("image = %q after the recreate, want test2", got)
	}
	if o := pciOwners(t, ctx, node)["0000:41:00.0"]; o != "ml" {
		t.Errorf("GPU owned by %q after the recreate, want ml", o)
	}
}

// A recreate the create would refuse is refused before the VM is deleted.
// The GPU's IOMMU-group sibling has since been taken by another VM; the
// planner cannot see it (it plans against free devices), but the create's
// placement does, and refused the recreate with ml already gone.
//
// Both recreate paths: the inline one (the default strategy) and the rolling
// engine's (recreateAs).
func TestFleet_ComposeRecreateTheCreateWouldRefuseDeletesNothing(t *testing.T) {
	for _, strategy := range []string{"", "rolling"} {
		t.Run("strategy="+strategy, func(t *testing.T) {
			recreateTheCreateWouldRefuse(t, strategy)
		})
	}
}

func recreateTheCreateWouldRefuse(t *testing.T, strategy string) {
	ctx, node, client := setupMappedGPU(t)
	seedPCI(t, ctx, node, corrosion.PCIDeviceRecord{Address: "0000:41:00.1", Type: "audio", VendorID: "10de", IOMMUGroup: 7, VMName: "other"})
	before, _ := corrosion.GetVM(ctx, node.DB, "ml")
	from := len(node.Virt.EventLog())

	next := strings.Replace(composeGPUMapping, "IMG", "test2", 1)
	if strategy != "" {
		next += "    update:\n      strategy: " + strategy + "\n"
	}
	// Inline reports the refusal in-band, the rolling engine ends the stream.
	if err := deployErr(t, ctx, client, next); err == nil || !strings.Contains(err.Error(), "nothing was deleted") {
		t.Fatalf("recreate of ml = %v, want a refusal that deleted nothing", err)
	}
	after, _ := corrosion.GetVM(ctx, node.DB, "ml")
	if after == nil || after.CreatedAt != before.CreatedAt {
		t.Fatalf("ml after the refused recreate = %+v, want it untouched", after)
	}
	for _, e := range node.Virt.EventLog()[from:] {
		if e.Domain == "ml" && (e.Op == "undefine" || e.Op == "destroy") {
			t.Errorf("the refused recreate tore ml down: %s", e.Op)
		}
	}
	if o := pciOwners(t, ctx, node)["0000:41:00.0"]; o != "ml" {
		t.Errorf("GPU owned by %q after the refused recreate, want ml", o)
	}
}
