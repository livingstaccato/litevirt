package grpcapi

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/cloudinit"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
)

// Re-review N2: a VM's seed written before seeds were stamped (every VM of a
// released cluster) is the VM's own when its domain attaches it as its cdrom
// (re-review 2 N4), its instance-id is one the VM's create wrote and its
// user-data is its spec's (re-review 3 N5). An attach rebuilds it keeping meta-data and user-data byte for
// byte — a replaced VM keeps its <name>-next instance-id, so no guest runs
// first boot again — and stamps it.
//
// Mutation: treat an unstamped seed as not the VM's — it is left as it was
// (no attached NIC in it, no stamp); regenerate it from the spec — the
// instance-id becomes the VM's name.
func TestNICHotplug_UnstampedOwnSeedIsRebuiltInPlace(t *testing.T) {
	needGenisoimage(t)
	for _, instanceID := range []string{"x", "x-next"} {
		t.Run(instanceID, func(t *testing.T) {
			s := hotplugDiskServer(t)
			enableHardwareV2(t, s)
			spec := &pb.VMSpec{Name: "x", Uuid: "uuid-x", Image: "ubuntu", Cpu: 2, MemoryMib: 4096,
				CloudInit: &pb.CloudInitSpec{Userdata: "#cloud-config\npassword: seed\n"},
				Network:   []*pb.NetworkAttachment{{Name: "lan", Mac: "52:54:00:6e:00:01"}, {Name: "lan3", Mac: "52:54:00:6e:00:03"}}}
			iso := r2VM(t, s, spec, []corrosion.InterfaceRecord{
				{VMName: "x", NetworkName: "lan", MAC: "52:54:00:6e:00:01"},
				{VMName: "x", NetworkName: "lan3", Ordinal: 1, MAC: "52:54:00:6e:00:03"}}, "running",
				cloudinit.Config{InstanceID: instanceID, LocalHostname: instanceID, UserData: "#cloud-config\npassword: seed\n"}, "")
			attachSeedCDROM(t, s, "x", iso)
			if _, err := s.AttachDevice(adminCtx(), &pb.AttachDeviceRequest{VmName: "x", Nic: &pb.NetworkAttachment{Name: "lan2", Mac: "52:54:00:6e:00:02"}}); err != nil {
				t.Fatalf("attach: %v", err)
			}
			sd := mustReadSeed(t, iso)
			if sd.InstanceID() != instanceID || sd.UserData != "#cloud-config\npassword: seed\n" {
				t.Errorf("meta-data or user-data changed: %q %q", sd.MetaData, sd.UserData)
			}
			if !strings.Contains(sd.NetworkConfig, "52:54:00:6e:00:02") {
				t.Errorf("the attached NIC is not in the seed:\n%s", sd.NetworkConfig)
			}
			if !cloudinit.SeedIsFor(iso, "uuid-x") {
				t.Error("the VM's own seed was not stamped for it")
			}
			if n := cdromReloads(s, "x"); n != 1 {
				t.Errorf("reloaded %d times, want 1", n)
			}
		})
	}
}

// Re-review N2: an unstamped seed whose instance-id the VM's create never
// wrote (a deleted VM of another name, a renamed VM) is left untouched, with
// an event naming the file — even attached as the VM's cdrom.
//
// Mutation: take every unstamped seed as the VM's — it is rewritten.
func TestNICHotplug_UnstampedForeignSeedIsLeftAlone(t *testing.T) {
	needGenisoimage(t)
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	spec := &pb.VMSpec{Name: "x", Uuid: "uuid-x", Image: "ubuntu", Cpu: 2, MemoryMib: 4096,
		Network: []*pb.NetworkAttachment{{Name: "lan", Mac: "52:54:00:6f:00:01"}, {Name: "lan3", Mac: "52:54:00:6f:00:03"}}}
	iso := r2VM(t, s, spec, []corrosion.InterfaceRecord{
		{VMName: "x", NetworkName: "lan", MAC: "52:54:00:6f:00:01"},
		{VMName: "x", NetworkName: "lan3", Ordinal: 1, MAC: "52:54:00:6f:00:03"}}, "running",
		cloudinit.Config{InstanceID: "other", LocalHostname: "other", UserData: "#cloud-config\n{}\n"}, "")
	attachSeedCDROM(t, s, "x", iso)
	before, _ := os.ReadFile(iso)
	if _, err := s.AttachDevice(adminCtx(), &pb.AttachDeviceRequest{VmName: "x", Nic: &pb.NetworkAttachment{Name: "lan2", Mac: "52:54:00:6f:00:02"}}); err != nil {
		t.Fatalf("attach: %v", err)
	}
	if after, _ := os.ReadFile(iso); !bytes.Equal(before, after) {
		t.Error("an unstamped seed of another instance was rewritten")
	}
	if evs := vmEventsOf(t, s, "x", "seed.not_rebuilt"); len(evs) != 1 || !strings.Contains(evs[0].Detail, iso) {
		t.Errorf("want one seed.not_rebuilt event naming %s: %+v", iso, evs)
	}
}

// Re-review N1/N2, the lab-shaped sequence up to the failover: a legacy VM
// (MAC-less spec, unstamped seed) gets a clean rebuild with the vendor-data on
// an attach; `lv config --ip` then makes X's entry undecidable; the next detach
// leaves the VM's own seed byte for byte (its network-config is the only
// record of which NIC is static) and stamps it.
//
// Mutation: treat an unstamped seed as not the VM's and write it again with
// no network-config — the seed loses X's static address.
func TestNICHotplug_LegacyUnstampedSeedSurvivesAmbiguity(t *testing.T) {
	needGenisoimage(t)
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	ctx := adminCtx()
	const macX, macA, macC = "52:54:00:70:00:01", "52:54:00:70:00:02", "52:54:00:70:00:03"
	spec := legacySpec()
	iso := r2VM(t, s, spec, []corrosion.InterfaceRecord{
		{VMName: "lg", NetworkName: "lan0", Ordinal: 0, MAC: macX, IP: "10.0.0.10"},
		{VMName: "lg", NetworkName: "lan1", Ordinal: 1, MAC: macA, IP: "10.1.0.50"},
	}, "running", cloudinit.Config{InstanceID: "lg", LocalHostname: "lg", UserData: "#cloud-config\n{}\n",
		NetworkConfig: cloudinit.BuildV1([]cloudinit.StaticIface{{MAC: macX, Address: "10.0.0.10/24"}, {MAC: macA, Address: "10.1.0.50/24"}})}, "")
	attachSeedCDROM(t, s, "lg", iso)
	// 1. A clean attach: the seed gains C and the vendor-data, and is stamped.
	if _, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{VmName: "lg", Nic: &pb.NetworkAttachment{Name: "lan2", Mac: macC}}); err != nil {
		t.Fatalf("attach: %v", err)
	}
	sd := mustReadSeed(t, iso)
	if !strings.Contains(sd.NetworkConfig, "10.0.0.10/24") || sd.VendorData != cloudinit.NetworkUpdatesVendorData || !cloudinit.SeedIsFor(iso, "uuid-lg") {
		t.Fatalf("clean rebuild: %+v stamped=%v", sd, cloudinit.SeedIsFor(iso, "uuid-lg"))
	}
	// 2. `lv config --ip` records another address for X: undecidable.
	if _, err := s.SetVMIP(ctx, &pb.SetVMIPRequest{Name: "lg", Ip: "10.0.0.99", NetworkName: "lan0"}); err != nil {
		t.Fatalf("SetVMIP: %v", err)
	}
	before, _ := os.ReadFile(iso)
	// 3. A detach: the seed is left exactly as it is.
	if _, err := s.DetachDevice(ctx, &pb.DetachDeviceRequest{VmName: "lg", NicMac: macC}); err != nil {
		t.Fatalf("detach: %v", err)
	}
	if after, _ := os.ReadFile(iso); !bytes.Equal(before, after) {
		t.Errorf("the seed changed on an undecidable rebuild:\n%s", mustReadSeed(t, iso).NetworkConfig)
	}
	if evs := vmEventsOf(t, s, "lg", "seed.not_rebuilt"); len(evs) != 1 {
		t.Errorf("want one seed.not_rebuilt event: %+v", evs)
	}
}

// Re-review N3: EnsureCloudInit writes a seed — user-data and vendor-data the
// guest runs as root — and stamps it as the VM's, so it is the target half of
// a migration a source daemon drives: a user holding vm.migrate is refused.
// Every source, this release's and every earlier one's, calls it through its
// peer client (ensureCloudInitOnTarget, peerClient).
//
// Mutation: drop requirePeerCert — the operator's call writes the seed.
func TestEnsureCloudInit_IsAPeerCall(t *testing.T) {
	stageGenisoimage(t)
	s := testServer(t)
	s.dataDir = t.TempDir()
	insertTestVM(t, adminCtx(), s.db, "pc", "src-host", "running")
	_, err := s.EnsureCloudInit(adminCtx(), &pb.EnsureCloudInitRequest{VmName: "pc", Userdata: "#cloud-config\nbootcmd: [touch /pwned]\n"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("operator call: %v, want PermissionDenied", err)
	}
	if _, err := os.Stat(lv.CloudInitISOPath(s.dataDir, "pc")); !os.IsNotExist(err) {
		t.Errorf("the operator's call wrote a seed: %v", err)
	}
	if _, err := s.EnsureCloudInit(diskPeerCtx(t, s), &pb.EnsureCloudInitRequest{VmName: "pc"}); err != nil {
		t.Fatalf("peer call: %v", err)
	}
}

// Re-review N2: a legacy VM whose spec NICs cannot be told apart, with its
// own seed from before seeds were stamped: an attach leaves that seed byte for
// byte (its network-config is the only record of which NIC is static), and
// stamps it as the VM's.
//
// Mutation: treat the unstamped seed as not the VM's and write it again with
// no network-config — X's static address is gone from the seed.
func TestNICHotplug_UnstampedAmbiguousSeedIsKept(t *testing.T) {
	needGenisoimage(t)
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	const macX, macA = "52:54:00:71:00:01", "52:54:00:71:00:02"
	iso := r2VM(t, s, legacySpec(), []corrosion.InterfaceRecord{
		{VMName: "lg", NetworkName: "lan0", Ordinal: 0, MAC: macX, IP: "10.0.0.99"}, // `lv config --ip` rewrote it
		{VMName: "lg", NetworkName: "lan1", Ordinal: 1, MAC: macA, IP: "10.1.0.50"},
	}, "running", cloudinit.Config{InstanceID: "lg", LocalHostname: "lg", UserData: "#cloud-config\n{}\n",
		NetworkConfig: cloudinit.BuildV1([]cloudinit.StaticIface{{MAC: macX, Address: "10.0.0.10/24"}, {MAC: macA, Address: "10.1.0.50/24"}})}, "")
	attachSeedCDROM(t, s, "lg", iso)
	before, _ := os.ReadFile(iso)
	if _, err := s.AttachDevice(adminCtx(), &pb.AttachDeviceRequest{VmName: "lg", Nic: &pb.NetworkAttachment{Name: "lan2", Mac: "52:54:00:71:00:03"}}); err != nil {
		t.Fatalf("attach: %v", err)
	}
	if after, _ := os.ReadFile(iso); !bytes.Equal(before, after) {
		t.Errorf("the VM's own seed changed on an undecidable rebuild:\n%s", mustReadSeed(t, iso).NetworkConfig)
	}
	if !cloudinit.SeedIsFor(iso, "uuid-lg") {
		t.Error("the VM's own seed was not stamped for it")
	}
	if n := cdromReloads(s, "lg"); n != 0 {
		t.Errorf("reloaded %d times", n)
	}
}

// Re-review N1 / m-N1 (migration): a source that cannot tell the VM's NICs and
// holds no seed of the VM's (here a seed of another instance) sends the target
// a network-config cloud-init reads as disabled and the vendor-data that turns
// the re-render off — never an empty network-config, never that seed's.
//
// Mutation: send "" — red; take the foreign seed as the VM's — its
// network-config is sent.
func TestEnsureCloudInit_AmbiguousSourceWithoutItsSeedDisablesRendering(t *testing.T) {
	needGenisoimage(t)
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	r2VM(t, s, legacySpec(), []corrosion.InterfaceRecord{
		{VMName: "lg", NetworkName: "lan0", Ordinal: 0, MAC: "52:54:00:72:00:01", IP: "10.0.0.99"},
		{VMName: "lg", NetworkName: "lan1", Ordinal: 1, MAC: "52:54:00:72:00:02", IP: "10.1.0.50"},
	}, "running", cloudinit.Config{InstanceID: "other", LocalHostname: "other", NetworkConfig: "version: 1\nconfig: []\n"}, "")
	vm, err := corrosion.GetVM(adminCtx(), s.db, "lg")
	if err != nil || vm == nil {
		t.Fatal(err)
	}
	req := s.ensureCloudInitRequest(adminCtx(), vm)
	if req == nil || req.Networkconfig != cloudinit.NetworkConfigDisabled || req.Vendordata == nil || *req.Vendordata != cloudinit.NetworkUpdatesOffVendorData {
		t.Fatalf("request = %+v", req)
	}
}
