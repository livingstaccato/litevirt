package grpcapi

import (
	"bytes"
	"os"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/cloudinit"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// attachSeedCDROM gives vm's domain on s a definition whose cdrom is iso, as
// a start that attached the seed leaves it.
func attachSeedCDROM(t *testing.T, s *Server, vm, iso string) {
	t.Helper()
	s.virt.(*libvirtfake.Fake).SetInactiveXML(vm, "<domain type='kvm'><name>"+vm+"</name><memory unit='MiB'>4096</memory><vcpu>2</vcpu><devices>"+
		"<disk type='file' device='cdrom'><driver name='qemu' type='raw'/><source file='"+iso+"'/><target dev='sdb' bus='sata'/><readonly/></disk>"+
		"</devices></domain>")
}

func seedStamped(t *testing.T, iso string) bool {
	t.Helper()
	_, stamped, err := cloudinit.SeedOwner(iso)
	if err != nil {
		t.Fatal(err)
	}
	return stamped
}

// Re-review 2 N4: VM x (another project's, its user-data holding that
// project's secrets) was deleted while this host kept its unstamped seed. A
// new x, whose spec has no cloud-init (an imported disk), runs here. A NIC
// attach must neither rebuild that seed nor stamp it as the new x's — a stamp
// is what every later start trusts, and the new guest would boot the old
// user-data. It is left byte for byte, unstamped and not reloaded, with an
// event naming the file, whether or not the new x's domain attaches it (an
// earlier release's start attached any file at the path).
//
// Mutation: OwnSeed without the cloud-init check — both cases go red; without
// the cdrom check — "not attached" goes red.
func TestNICHotplug_ANoCloudInitVMNeverTakesALeftoverSeed(t *testing.T) {
	needGenisoimage(t)
	for _, attached := range []bool{false, true} {
		name := "not attached"
		if attached {
			name = "attached by its domain"
		}
		t.Run(name, func(t *testing.T) {
			s := hotplugDiskServer(t)
			enableHardwareV2(t, s)
			spec := &pb.VMSpec{Name: "x", Uuid: "uuid-new", Cpu: 2, MemoryMib: 4096,
				Network: []*pb.NetworkAttachment{{Name: "lan", Mac: "52:54:00:73:00:01"}}}
			iso := r2VM(t, s, spec, []corrosion.InterfaceRecord{{VMName: "x", NetworkName: "lan", MAC: "52:54:00:73:00:01"}}, "running",
				cloudinit.Config{InstanceID: "x", LocalHostname: "x", UserData: "#cloud-config\npassword: theirs\n"}, "")
			if attached {
				attachSeedCDROM(t, s, "x", iso)
			}
			before, _ := os.ReadFile(iso)
			if _, err := s.AttachDevice(adminCtx(), &pb.AttachDeviceRequest{VmName: "x", Nic: &pb.NetworkAttachment{Name: "lan2", Mac: "52:54:00:73:00:02"}}); err != nil {
				t.Fatalf("attach: %v", err)
			}
			if after, _ := os.ReadFile(iso); !bytes.Equal(before, after) {
				t.Error("a deleted VM's seed was rewritten for a VM without cloud-init")
			}
			if seedStamped(t, iso) {
				t.Error("a deleted VM's seed was stamped as the new VM's")
			}
			if n := cdromReloads(s, "x"); n != 0 {
				t.Errorf("reloaded %d times", n)
			}
			if evs := vmEventsOf(t, s, "x", "seed.not_rebuilt"); len(evs) != 1 || !strings.Contains(evs[0].Detail, iso) {
				t.Errorf("want one seed.not_rebuilt event naming %s: %+v", iso, evs)
			}
		})
	}
}

// Re-review 2 N4: a VM with cloud-init and an unstamped seed of its name that
// its domain does not attach — a deleted VM of the name left it, and this VM
// runs on a seed elsewhere or none — is not its own: left byte for byte,
// unstamped, with the event. The instance-id alone is not proof.
//
// Mutation: OwnSeed without the cdrom check — the seed is rebuilt and stamped.
func TestNICHotplug_AnUnattachedUnstampedSeedIsLeftAlone(t *testing.T) {
	needGenisoimage(t)
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	spec := &pb.VMSpec{Name: "x", Uuid: "uuid-new", Image: "ubuntu", Cpu: 2, MemoryMib: 4096,
		CloudInit: &pb.CloudInitSpec{Userdata: "#cloud-config\npassword: mine\n"},
		Network:   []*pb.NetworkAttachment{{Name: "lan", Mac: "52:54:00:74:00:01"}}}
	iso := r2VM(t, s, spec, []corrosion.InterfaceRecord{{VMName: "x", NetworkName: "lan", MAC: "52:54:00:74:00:01"}}, "running",
		cloudinit.Config{InstanceID: "x", LocalHostname: "x", UserData: "#cloud-config\npassword: theirs\n"}, "")
	before, _ := os.ReadFile(iso)
	if _, err := s.AttachDevice(adminCtx(), &pb.AttachDeviceRequest{VmName: "x", Nic: &pb.NetworkAttachment{Name: "lan2", Mac: "52:54:00:74:00:02"}}); err != nil {
		t.Fatalf("attach: %v", err)
	}
	if after, _ := os.ReadFile(iso); !bytes.Equal(before, after) {
		t.Error("an unstamped seed the VM's domain does not attach was rewritten")
	}
	if seedStamped(t, iso) {
		t.Error("an unstamped seed the VM's domain does not attach was stamped")
	}
	if evs := vmEventsOf(t, s, "x", "seed.not_rebuilt"); len(evs) != 1 || !strings.Contains(evs[0].Detail, iso) {
		t.Errorf("want one seed.not_rebuilt event naming %s: %+v", iso, evs)
	}
}

// Re-review 2 N4 (migration source): a legacy VM whose NICs cannot be told
// apart, with an unstamped seed of its name here that its domain does not
// attach, sends the target the disabled network-config — never that seed's
// network-config, which may be a deleted VM's.
//
// Mutation: OwnSeed without the cdrom check — the seed's network-config is
// sent.
func TestEnsureCloudInit_AmbiguousSourceDoesNotSendAnUnattachedSeed(t *testing.T) {
	needGenisoimage(t)
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	r2VM(t, s, legacySpec(), []corrosion.InterfaceRecord{
		{VMName: "lg", NetworkName: "lan0", Ordinal: 0, MAC: "52:54:00:75:00:01", IP: "10.0.0.99"},
		{VMName: "lg", NetworkName: "lan1", Ordinal: 1, MAC: "52:54:00:75:00:02", IP: "10.1.0.50"},
	}, "running", cloudinit.Config{InstanceID: "lg", LocalHostname: "lg", NetworkConfig: "version: 1\nconfig: []\n"}, "")
	vm, err := corrosion.GetVM(adminCtx(), s.db, "lg")
	if err != nil || vm == nil {
		t.Fatal(err)
	}
	req := s.ensureCloudInitRequest(adminCtx(), vm)
	if req == nil || req.Networkconfig != cloudinit.NetworkConfigDisabled || req.Vendordata == nil || *req.Vendordata != cloudinit.NetworkUpdatesOffVendorData {
		t.Fatalf("request = %+v", req)
	}
}
