package grpcapi

import (
	"errors"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// seedCDROMDomain is a definition with the root disk and the cloud-init seed
// on sata sdb, as CreateVM defines a VM with a single root disk.
const seedCDROMDomain = "<domain type='kvm'><name>vm1</name><devices>" +
	"<disk type='file' device='disk'><source file='/x/vm1-root.qcow2'/><target dev='vda' bus='virtio'/></disk>" +
	"<disk type='file' device='cdrom'><source file='/x/cloudinit/vm1.iso'/><target dev='sdb' bus='sata'/><readonly/></disk>" +
	"</devices></domain>"

// A sata or scsi hot-plug was allocated a target from vm_disks alone, which
// does not hold the seed CD-ROM, so it was handed sdb: a live attach fails on
// the duplicate, and a stopped VM's patched definition holds two sdb.
//
// Mutation: drop the domain's targets from the occupied set in attachDiskOwner
// — every subtest goes red with target sdb.
func TestAttachDevice_DiskTargetSkipsTheSeedCDROM(t *testing.T) {
	for _, state := range []string{"running", "stopped"} {
		for _, bus := range []string{"sata", "scsi"} {
			t.Run(state+"/"+bus, func(t *testing.T) {
				s := hotplugDiskServer(t)
				enableHardwareV2(t, s)
				ctx := adminCtx()
				seedDiskVM(t, s, "vm1", state)
				fake := s.virt.(*libvirtfake.Fake)
				fake.SetInactiveXML("vm1", seedCDROMDomain)

				// The first sd* disk takes sda; the second is the one the old
				// allocator handed sdb.
				for _, name := range []string{"data1", "data2"} {
					if _, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
						VmName: "vm1", Disk: &pb.DiskSpec{Name: name, Size: "1G", Bus: bus},
					}); err != nil {
						t.Fatalf("attach %s: %v", name, err)
					}
					if got := diskTargetDev(t, ctx, s, "vm1", name); got == "sdb" {
						t.Fatalf("the %s disk %s was allocated sdb, the seed CD-ROM's target", bus, name)
					}
				}
				targets, err := libvirt.DomainDiskTargets(fake.DefinedXML("vm1"))
				if err != nil {
					t.Fatal(err)
				}
				seen := map[string]bool{}
				for _, dev := range targets {
					if seen[dev] {
						t.Fatalf("the definition holds target %s twice: %v\n%s", dev, targets, fake.DefinedXML("vm1"))
					}
					seen[dev] = true
				}
			})
		}
	}
}

// A definition that cannot be read refuses the attach before anything is
// written, rather than allocating a target the domain may already use.
//
// Mutation: treat the read error as an empty target set — the attach succeeds.
func TestAttachDevice_DiskTargetUnreadableDefinitionRefuses(t *testing.T) {
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	ctx := adminCtx()
	seedDiskVM(t, s, "vm1", "stopped")
	fake := s.virt.(*libvirtfake.Fake)
	fake.SetInactiveXML("vm1", seedCDROMDomain)
	fake.FailDumpXMLInactive = func(string) error { return errors.New("connection reset by peer") }

	if _, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
		VmName: "vm1", Disk: &pb.DiskSpec{Name: "data", Size: "1G", Bus: "sata"},
	}); err == nil {
		t.Fatal("an attach whose definition could not be read must refuse")
	}
	disks, _ := corrosion.GetVMDisks(ctx, s.db, "vm1")
	if hasDiskName(disks, "data") {
		t.Fatalf("a refused attach wrote a row: %+v", disks)
	}
	if vm := mustGetVM(t, s, "vm1"); vm.ActiveOperationID != "" {
		t.Fatalf("a refused attach left the barrier set: %q", vm.ActiveOperationID)
	}
}
