package fleet

// A full regenerate of a VM's domain built it without the cloud-init seed
// CreateVM attached: the seed is not a vm_disks row and only the create set
// it on the domain config. The VM booted next without its NoCloud datasource
// — no hostname, no network-config, no config for a hot-plugged NIC. Both
// regenerates are driven here through the real RPCs a user reaches them by:
// UpdateVM (`lv update --guest-agent`) and a stopped-VM disk attach on a VM
// that owns a passthrough device by ownership alone, which the reconcile
// primitive regenerates rather than patches.

import (
	"context"
	"encoding/xml"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

type seedCDROM struct {
	File, Dev, Bus string
	ReadOnly       bool
}

// domainDevices reads the CD-ROMs, the disk targets and the hostdev count of
// a domain definition.
func domainDevices(t *testing.T, domXML string) (cdroms []seedCDROM, diskDevs []string, hostdevs int) {
	t.Helper()
	var dom struct {
		Disks []struct {
			Device string `xml:"device,attr"`
			Source struct {
				File string `xml:"file,attr"`
			} `xml:"source"`
			Target struct {
				Dev string `xml:"dev,attr"`
				Bus string `xml:"bus,attr"`
			} `xml:"target"`
			ReadOnly *struct{} `xml:"readonly"`
		} `xml:"devices>disk"`
		Hostdevs []struct{} `xml:"devices>hostdev"`
	}
	if err := xml.Unmarshal([]byte(domXML), &dom); err != nil {
		t.Fatalf("parse domain XML: %v\n%s", err, domXML)
	}
	for _, d := range dom.Disks {
		if d.Device == "cdrom" {
			cdroms = append(cdroms, seedCDROM{File: d.Source.File, Dev: d.Target.Dev, Bus: d.Target.Bus, ReadOnly: d.ReadOnly != nil})
			continue
		}
		diskDevs = append(diskDevs, d.Target.Dev)
	}
	return cdroms, diskDevs, len(dom.Hostdevs)
}

// Mutation: drop the keepCDROMs call from UpdateVM's regenerate — the
// UpdateVM step goes red; from reconcileDomainDefinition's — the attach step
// goes red.
func TestFleet_RegenerateKeepsTheSeedCDROM(t *testing.T) {
	stageFakeGenisoimage(t)
	c := New(t, Options{Nodes: 1})
	n := c.Nodes[0]
	ctx := context.Background()
	importImageOn(t, c, n, "ubuntu")
	client := c.SelfClient(n)

	if _, err := client.CreateVM(ctx, &pb.CreateVMRequest{Spec: &pb.VMSpec{
		Name: "ci", Image: "ubuntu", Cpu: 1, MemoryMib: 256,
		CloudInit: &pb.CloudInitSpec{Userdata: "#cloud-config\nhostname: ci\n"},
		Placement: &pb.PlacementSpec{Host: n.Name},
	}}); err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	seed := filepath.Join(c.tmpRoot, n.Name, "data", "cloudinit", "ci.iso")
	created, _, _ := domainDevices(t, n.Virt.DefinedXML("ci"))
	if len(created) != 1 || created[0].File != seed || created[0].Bus != "sata" || !created[0].ReadOnly {
		t.Fatalf("setup: CreateVM defined CD-ROMs %+v, want the read-only sata seed %s", created, seed)
	}
	if _, err := client.StopVM(ctx, &pb.StopVMRequest{Name: "ci", Force: true}); err != nil {
		t.Fatalf("StopVM: %v", err)
	}

	// UpdateVM: a guest-agent toggle is never patched in place.
	if _, err := client.UpdateVM(ctx, &pb.UpdateVMRequest{Name: "ci", GuestAgent: proto.Bool(true)}); err != nil {
		t.Fatalf("UpdateVM: %v", err)
	}
	got, _, _ := domainDevices(t, n.Virt.DefinedXML("ci"))
	if len(got) != 1 || got[0] != created[0] {
		t.Fatalf("after UpdateVM's regenerate the CD-ROMs are %+v, want CreateVM's %+v", got, created)
	}

	// reconcileDomainDefinition: a passthrough device the VM owns with no
	// intent has no alias the patcher can match, so the stopped-VM disk
	// attach regenerates the definition.
	gates := gateAll(t, c)
	latchHardwareV2(t, c, gates)
	if err := corrosion.UpsertPCIDevice(ctx, n.DB, corrosion.PCIDeviceRecord{
		HostName: n.Name, Address: "0000:00:1f.0", VendorID: "10de", DeviceID: "1eb8", Type: "gpu", Driver: "vfio-pci",
	}); err != nil {
		t.Fatalf("UpsertPCIDevice: %v", err)
	}
	if ok, err := corrosion.ClaimPCIDevice(ctx, n.DB, n.Name, "0000:00:1f.0", "ci"); err != nil || !ok {
		t.Fatalf("ClaimPCIDevice: ok=%v err=%v", ok, err)
	}
	if _, err := client.AttachDevice(ctx, &pb.AttachDeviceRequest{
		VmName: "ci", Disk: &pb.DiskSpec{Name: "data", Size: "1G"},
	}); err != nil {
		t.Fatalf("AttachDevice disk: %v", err)
	}
	after := n.Virt.DefinedXML("ci")
	got, diskDevs, hostdevs := domainDevices(t, after)
	if hostdevs != 1 || len(diskDevs) != 2 {
		t.Fatalf("setup: the attach did not regenerate with the owned device and both disks (hostdevs=%d disks=%v):\n%s", hostdevs, diskDevs, after)
	}
	// The seed is the create's file on the create's bus; its target follows
	// the disks before it, as the create's did, so it cannot take a disk's.
	if len(got) != 1 || got[0].File != seed || got[0].Bus != "sata" || !got[0].ReadOnly || got[0].Dev == "" {
		t.Fatalf("after the attach's regenerate the CD-ROMs are %+v, want the read-only sata seed %s\n%s", got, seed, after)
	}
	for _, d := range diskDevs {
		if strings.EqualFold(d, got[0].Dev) {
			t.Fatalf("the seed's target %s is a disk's too: %v", got[0].Dev, diskDevs)
		}
	}
}
