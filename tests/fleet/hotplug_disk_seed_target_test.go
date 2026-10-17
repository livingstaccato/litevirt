package fleet

// A sata or scsi disk hot-plugged onto a VM CreateVM gave a cloud-init seed
// was allocated its target from vm_disks alone. The seed CD-ROM is in no
// table, so the disk was handed the seed's sdb: a live attach collides with
// it, and the stopped-VM attach patches a second sdb into the definition.

import (
	"context"
	"encoding/xml"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

type hotplugTargetDisk struct {
	Device string
	File   string
	Dev    string
}

func hotplugTargetDisks(t *testing.T, domXML string) []hotplugTargetDisk {
	t.Helper()
	var dom struct {
		Disks []struct {
			Device string `xml:"device,attr"`
			Source struct {
				File string `xml:"file,attr"`
			} `xml:"source"`
			Target struct {
				Dev string `xml:"dev,attr"`
			} `xml:"target"`
		} `xml:"devices>disk"`
	}
	if err := xml.Unmarshal([]byte(domXML), &dom); err != nil {
		t.Fatalf("parse domain XML: %v\n%s", err, domXML)
	}
	var out []hotplugTargetDisk
	for _, d := range dom.Disks {
		out = append(out, hotplugTargetDisk{Device: d.Device, File: d.Source.File, Dev: d.Target.Dev})
	}
	return out
}

// assertNoTargetCollision fails if two devices of the definition share a
// target, or the named disk's recorded target is a CD-ROM's.
func assertNoTargetCollision(t *testing.T, step, domXML, diskTarget string) {
	t.Helper()
	seen := map[string]bool{}
	for _, d := range hotplugTargetDisks(t, domXML) {
		if seen[d.Dev] {
			t.Fatalf("%s: target %s is defined twice:\n%s", step, d.Dev, domXML)
		}
		seen[d.Dev] = true
		if d.Device == "cdrom" && d.Dev == diskTarget {
			t.Fatalf("%s: the hot-plugged disk was allocated %s, CD-ROM %s's target:\n%s", step, diskTarget, d.File, domXML)
		}
	}
}

func recordedTarget(t *testing.T, n *Node, vm, disk string) string {
	t.Helper()
	disks, err := corrosion.GetVMDisks(context.Background(), n.DB, vm)
	if err != nil {
		t.Fatalf("GetVMDisks: %v", err)
	}
	for _, d := range disks {
		if d.DiskName == disk {
			return d.TargetDev
		}
	}
	t.Fatalf("no vm_disks row for %s/%s: %+v", vm, disk, disks)
	return ""
}

// Mutation: drop the domain's targets from attachDiskOwner's occupied set —
// both subtests go red on sdb.
func TestFleet_HotplugSataDiskDoesNotTakeTheSeedTarget(t *testing.T) {
	stageFakeGenisoimage(t)
	c := New(t, Options{Nodes: 1})
	n := c.Nodes[0]
	ctx := context.Background()
	importImageOn(t, c, n, "ubuntu")
	client := c.SelfClient(n)

	for _, name := range []string{"ci-live", "ci-cold"} {
		if _, err := client.CreateVM(ctx, &pb.CreateVMRequest{Spec: &pb.VMSpec{
			Name: name, Image: "ubuntu", Cpu: 1, MemoryMib: 256,
			CloudInit: &pb.CloudInitSpec{Userdata: "#cloud-config\nhostname: " + name + "\n"},
			Placement: &pb.PlacementSpec{Host: n.Name},
		}}); err != nil {
			t.Fatalf("CreateVM %s: %v", name, err)
		}
		seedTarget := ""
		for _, d := range hotplugTargetDisks(t, n.Virt.DefinedXML(name)) {
			if d.Device == "cdrom" {
				seedTarget = d.Dev
			}
		}
		if seedTarget != "sdb" {
			t.Fatalf("setup: CreateVM's seed CD-ROM target on %s is %q, want sdb:\n%s", name, seedTarget, n.Virt.DefinedXML(name))
		}
	}

	// hardware_v2 (with operation_protocol_v1) is what a stopped attach
	// needs, and every disk attach needs the protocol.
	latchHardwareV2(t, c, gateAll(t, c))

	// attachTwo hot-plugs two disks on bus: the first sd* disk takes sda, the
	// second is the one the old allocator handed the seed's sdb.
	attachTwo := func(t *testing.T, vm, bus string) {
		t.Helper()
		for _, disk := range []string{"d1", "d2"} {
			if _, err := client.AttachDevice(ctx, &pb.AttachDeviceRequest{
				VmName: vm, Disk: &pb.DiskSpec{Name: disk, Size: "1G", Bus: bus},
			}); err != nil {
				t.Fatalf("AttachDevice %s/%s: %v", vm, disk, err)
			}
			got := recordedTarget(t, n, vm, disk)
			if got == "sdb" {
				t.Fatalf("%s/%s was recorded at the seed's target sdb", vm, disk)
			}
			assertNoTargetCollision(t, vm+"/"+disk, n.Virt.DefinedXML(vm), got)
		}
	}

	// Running: a live attach.
	t.Run("running", func(t *testing.T) { attachTwo(t, "ci-live", "sata") })

	// Stopped: the attach patches the inactive definition.
	t.Run("stopped", func(t *testing.T) {
		if _, err := client.StopVM(ctx, &pb.StopVMRequest{Name: "ci-cold", Force: true}); err != nil {
			t.Fatalf("StopVM: %v", err)
		}
		attachTwo(t, "ci-cold", "scsi")
	})
}
