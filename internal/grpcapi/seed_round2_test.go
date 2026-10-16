package grpcapi

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/cloudinit"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// useSeedISOWriter lets the test write and read back real seeds on a host
// without genisoimage (cloudinit.UseGoISOWithoutGenisoimage).
func useSeedISOWriter(t *testing.T) {
	t.Helper()
	cloudinit.UseGoISOWithoutGenisoimage(t)
}

// r2VM inserts VM name with spec and NIC rows (both tables, as a create and,
// for a VM from before vm_nics, the backfill write them), its domain in
// state, and a seed on this host written from seed with instance-id
// "<name>-first", stamped for stamp ("" leaves it unstamped).
func r2VM(t *testing.T, s *Server, spec *pb.VMSpec, ifaces []corrosion.InterfaceRecord, state string, seed cloudinit.Config, stamp string) string {
	t.Helper()
	ctx := adminCtx()
	var nics []corrosion.NICRecord
	for _, i := range ifaces {
		nics = append(nics, corrosion.NICRecord{VMName: spec.Name, ID: corrosion.DeterministicNICID(spec.Name, i.MAC),
			NetworkName: i.NetworkName, MAC: i.MAC, Ordinal: i.Ordinal, IP: i.IP})
	}
	if err := corrosion.InsertVMWithHardware(ctx, s.db, corrosion.VMRecord{
		Name: spec.Name, HostName: "test-host", State: state, CPUActual: 2, MemActual: 4096, Spec: seedSpecJSON(t, spec),
	}, ifaces, nil, nics, nil, true); err != nil {
		t.Fatal(err)
	}
	switch state {
	case "running":
		s.virt.(*libvirtfake.Fake).SetState(spec.Name, libvirtfake.StateRunning)
	case "paused":
		s.virt.(*libvirtfake.Fake).SetState(spec.Name, libvirtfake.StatePaused)
	}
	iso := lv.CloudInitISOPath(s.dataDir, spec.Name)
	if seed.InstanceID == "" {
		seed.InstanceID, seed.LocalHostname = spec.Name+"-first", spec.Name
	}
	if err := cloudinit.GenerateISO(seed, iso); err != nil {
		t.Fatal(err)
	}
	if stamp != "" {
		if err := cloudinit.StampSeed(iso, stamp); err != nil {
			t.Fatal(err)
		}
	}
	return iso
}

func mustReadSeed(t *testing.T, iso string) cloudinit.Seed {
	t.Helper()
	sd, err := cloudinit.ReadSeed(iso)
	if err != nil {
		t.Fatalf("read seed: %v", err)
	}
	return sd
}

func vmEventsOf(t *testing.T, s *Server, vm, typ string) []corrosion.VMEventRecord {
	t.Helper()
	evs, err := corrosion.ListVMEvents(adminCtx(), s.db, vm, 100, "")
	if err != nil {
		t.Fatal(err)
	}
	var out []corrosion.VMEventRecord
	for _, e := range evs {
		if e.Type == typ {
			out = append(out, e)
		}
	}
	return out
}

func cdromReloads(s *Server, vm string) int {
	n := 0
	for _, e := range s.virt.(*libvirtfake.Fake).EventLog() {
		if e.Op == "reload-cdrom" && e.Domain == vm {
			n++
		}
	}
	return n
}

// legacySpec is a VM created before the spec recorded generated MACs:
// X(lan0, 10.0.0.10) and A(lan1, 10.1.0.50), both static, MAC-less.
func legacySpec() *pb.VMSpec {
	return &pb.VMSpec{Name: "lg", Uuid: "uuid-lg", Image: "ubuntu", Cpu: 2, MemoryMib: 4096,
		Network: []*pb.NetworkAttachment{{Name: "lan0", Ip: "10.0.0.10"}, {Name: "lan1", Ip: "10.1.0.50"}}}
}

// Review C-1, the lab's C3 on a VM from before 256d0395: detach the static
// NIC A, attach C on A's network. The rebuilt seed keeps X's static address:
// C takes an ordinal no NIC of the VM ever had, so it cannot land on A's
// spec entry's position, and is written as the new NIC it is.
//
// Mutation: number the attach by the count of NICs left (len(existing)) and
// treat the ambiguous result as "" — the seed loses its network-config and
// X its address.
func TestNICHotplug_LegacySpecDetachAttachKeepsTheStaticNIC(t *testing.T) {
	useSeedISOWriter(t)
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	ctx := adminCtx()
	const macX, macA, macC = "52:54:00:6a:00:01", "52:54:00:6a:00:02", "52:54:00:6a:00:03"
	spec := legacySpec()
	ifaces := []corrosion.InterfaceRecord{
		{VMName: "lg", NetworkName: "lan0", Ordinal: 0, MAC: macX, IP: "10.0.0.10"},
		{VMName: "lg", NetworkName: "lan1", Ordinal: 1, MAC: macA, IP: "10.1.0.50"},
	}
	iso := r2VM(t, s, spec, ifaces, "running", cloudinit.Config{UserData: "#cloud-config\n{}\n",
		NetworkConfig: cloudinit.BuildV1([]cloudinit.StaticIface{{MAC: macX, Address: "10.0.0.10/24"}, {MAC: macA, Address: "10.1.0.50/24"}})}, "uuid-lg")
	if _, err := s.DetachDevice(ctx, &pb.DetachDeviceRequest{VmName: "lg", NicMac: macA}); err != nil {
		t.Fatalf("detach: %v", err)
	}
	if _, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{VmName: "lg", Nic: &pb.NetworkAttachment{Name: "lan1", Mac: macC}}); err != nil {
		t.Fatalf("attach: %v", err)
	}
	sd := mustReadSeed(t, iso)
	if !strings.Contains(sd.NetworkConfig, "10.0.0.10/24") || !strings.Contains(sd.NetworkConfig, macX) {
		t.Errorf("X lost its static address:\n%s", sd.NetworkConfig)
	}
	if strings.Contains(sd.NetworkConfig, "10.1.0.50") || strings.Contains(sd.NetworkConfig, macA) {
		t.Errorf("the detached NIC is in the seed:\n%s", sd.NetworkConfig)
	}
	if !strings.Contains(sd.NetworkConfig, macC) {
		t.Errorf("the attached NIC is not in the seed:\n%s", sd.NetworkConfig)
	}
	nics, _ := corrosion.MergedVMNICs(ctx, s.db, "lg")
	for _, n := range nics {
		if strings.EqualFold(n.MAC, macC) && n.Ordinal < 2 {
			t.Errorf("C took ordinal %d, a position a spec entry or an earlier NIC held", n.Ordinal)
		}
	}
}

// Review C-1: where a rebuild cannot tell a MAC-less spec entry from the NIC
// at its position (here X's row records another address than its spec
// entry, as `lv config --ip` leaves it), the seed's network-config and
// vendor-data stay exactly as they were — no seed without network-config, no
// vendor-data added — and a VM event says why and what to do.
//
// Mutation: treat the ambiguous result as "" — the network-config goes and
// vendor-data is added; drop the event — red.
func TestNICHotplug_AmbiguousNICsLeaveTheSeedAlone(t *testing.T) {
	useSeedISOWriter(t)
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	ctx := adminCtx()
	const macX, macA = "52:54:00:6b:00:01", "52:54:00:6b:00:02"
	spec := legacySpec()
	ifaces := []corrosion.InterfaceRecord{
		{VMName: "lg", NetworkName: "lan0", Ordinal: 0, MAC: macX, IP: "10.0.0.77"}, // not the spec's .10
		{VMName: "lg", NetworkName: "lan1", Ordinal: 1, MAC: macA, IP: "10.1.0.50"},
	}
	nc := cloudinit.BuildV1([]cloudinit.StaticIface{{MAC: macX, Address: "10.0.0.10/24"}, {MAC: macA, Address: "10.1.0.50/24"}})
	iso := r2VM(t, s, spec, ifaces, "running", cloudinit.Config{UserData: "#cloud-config\n{}\n", NetworkConfig: nc}, "uuid-lg")
	before, err := os.ReadFile(iso)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{VmName: "lg", Nic: &pb.NetworkAttachment{Name: "lan2", Mac: "52:54:00:6b:00:03"}}); err != nil {
		t.Fatalf("attach: %v", err)
	}
	after, err := os.ReadFile(iso)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		sd := mustReadSeed(t, iso)
		t.Errorf("the seed changed on an ambiguous rebuild: network-config %q vendor-data %q", sd.NetworkConfig, sd.VendorData)
	}
	if n := cdromReloads(s, "lg"); n != 0 {
		t.Errorf("the seed cdrom was reloaded %d times for a seed left as it was", n)
	}
	evs := vmEventsOf(t, s, "lg", "seed.not_rebuilt")
	if len(evs) != 1 || !strings.Contains(evs[0].Detail, "MAC") || !strings.Contains(evs[0].Detail, "configure") {
		t.Errorf("want one seed.not_rebuilt event naming the MAC-less spec NICs and the remedy: %+v", evs)
	}
}

// Review I-1: the first hot attach to a one-NIC VM (no network-config: the
// guest named its NIC itself) renames nothing — the kept NIC is matched by
// MAC alone — and the attached NIC is eth1, its ordinal.
//
// Mutation: name a kept NIC the prior seed does not list by its create name
// — the kept NIC gets set-name eth0.
func TestNICHotplug_FirstAttachToAOneNICVMRenamesNothing(t *testing.T) {
	useSeedISOWriter(t)
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	ctx := adminCtx()
	iso := hpSeededVM(t, s, "running") // one DHCP NIC 52:54:00:5e:02:01, no network-config
	if sd := mustReadSeed(t, iso); sd.NetworkConfig != "" {
		t.Fatalf("setup: %q", sd.NetworkConfig)
	}
	const macB = "52:54:00:5e:02:09"
	if _, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{VmName: "hp", Nic: &pb.NetworkAttachment{Name: "lan2", Mac: macB}}); err != nil {
		t.Fatalf("attach: %v", err)
	}
	sd := mustReadSeed(t, iso)
	if strings.Count(sd.NetworkConfig, "set-name:") != 1 || !strings.Contains(sd.NetworkConfig, "macaddress: \""+macB+"\"\n    set-name: eth1\n") {
		t.Errorf("want only the attached NIC named (eth1):\n%s", sd.NetworkConfig)
	}
	if sd.VendorData != cloudinit.NetworkUpdatesVendorData {
		t.Errorf("a seed with litevirt's network-config lacks the vendor-data: %q", sd.VendorData)
	}
}

// Review I-2: a seed at the VM's path that is stamped for another VM — a
// deleted VM of the same name left it — is never rewritten from, nor
// rewritten: it is left alone (no reload, no false seed.reload_failed) with an
// event naming it, for a VM with or without cloud-init.
//
// Mutation: take every seed at the path as the VM's — the leftover is
// rewritten with its user-data kept, and reloaded.
func TestNICHotplug_ALeftoverSeedIsNotRebuiltFrom(t *testing.T) {
	useSeedISOWriter(t)
	leftover := cloudinit.Config{InstanceID: "x", LocalHostname: "x", UserData: "#cloud-config\npassword: theirs\n",
		NetworkConfig: "version: 1\nconfig: []\n"}

	t.Run("no cloud-init", func(t *testing.T) {
		s := hotplugDiskServer(t)
		enableHardwareV2(t, s)
		spec := &pb.VMSpec{Name: "x", Uuid: "uuid-new", Cpu: 2, MemoryMib: 4096,
			Network: []*pb.NetworkAttachment{{Name: "lan", Mac: "52:54:00:6c:00:01"}, {Name: "lan3", Mac: "52:54:00:6c:00:03"}}}
		iso := r2VM(t, s, spec, []corrosion.InterfaceRecord{
			{VMName: "x", NetworkName: "lan", MAC: "52:54:00:6c:00:01"},
			{VMName: "x", NetworkName: "lan3", Ordinal: 1, MAC: "52:54:00:6c:00:03"}}, "running", leftover, "uuid-old")
		before, _ := os.ReadFile(iso)
		if _, err := s.AttachDevice(adminCtx(), &pb.AttachDeviceRequest{VmName: "x", Nic: &pb.NetworkAttachment{Name: "lan2", Mac: "52:54:00:6c:00:02"}}); err != nil {
			t.Fatalf("attach: %v", err)
		}
		if after, _ := os.ReadFile(iso); !bytes.Equal(before, after) {
			t.Error("a leftover seed of another VM was rewritten")
		}
		if n := cdromReloads(s, "x"); n != 0 || len(vmEventsOf(t, s, "x", "seed.reload_failed")) != 0 {
			t.Errorf("a reload was attempted for a seed that is not this VM's (%d)", n)
		}
		if evs := vmEventsOf(t, s, "x", "seed.not_rebuilt"); len(evs) != 1 || !strings.Contains(evs[0].Detail, iso) || !strings.Contains(evs[0].Detail, "has no cloud-init") {
			t.Errorf("want one seed.not_rebuilt event naming %s: %+v", iso, evs)
		}
	})

	t.Run("cloud image", func(t *testing.T) {
		// Re-review N2: a seed that is not this VM's is left untouched for a VM
		// with cloud-init too — never written again live (that would give the
		// running guest a new instance-id); the next start writes it.
		s := hotplugDiskServer(t)
		enableHardwareV2(t, s)
		spec := &pb.VMSpec{Name: "x", Uuid: "uuid-new", Image: "ubuntu", Cpu: 2, MemoryMib: 4096,
			CloudInit: &pb.CloudInitSpec{Userdata: "#cloud-config\npassword: mine\n"},
			Network:   []*pb.NetworkAttachment{{Name: "lan", Mac: "52:54:00:6c:00:01"}, {Name: "lan3", Mac: "52:54:00:6c:00:03"}}}
		iso := r2VM(t, s, spec, []corrosion.InterfaceRecord{
			{VMName: "x", NetworkName: "lan", MAC: "52:54:00:6c:00:01"},
			{VMName: "x", NetworkName: "lan3", Ordinal: 1, MAC: "52:54:00:6c:00:03"}}, "running", leftover, "uuid-old")
		before, _ := os.ReadFile(iso)
		if _, err := s.AttachDevice(adminCtx(), &pb.AttachDeviceRequest{VmName: "x", Nic: &pb.NetworkAttachment{Name: "lan2", Mac: "52:54:00:6c:00:02"}}); err != nil {
			t.Fatalf("attach: %v", err)
		}
		if after, _ := os.ReadFile(iso); !bytes.Equal(before, after) {
			t.Error("a seed stamped for another VM was rewritten")
		}
		if n := cdromReloads(s, "x"); n != 0 {
			t.Errorf("reloaded %d times", n)
		}
		if evs := vmEventsOf(t, s, "x", "seed.not_rebuilt"); len(evs) != 1 || !strings.Contains(evs[0].Detail, iso) || !strings.Contains(evs[0].Detail, "stamped for another VM") {
			t.Errorf("want one seed.not_rebuilt event naming %s: %+v", iso, evs)
		}
	})
}

// Review m3: a rebuild that fails leaves the seed as it was and says so: a
// seed.rebuild_failed event naming what to do.
//
// Mutation: only log the failure — red.
func TestNICHotplug_AFailedRebuildIsReported(t *testing.T) {
	useSeedISOWriter(t)
	if os.Geteuid() == 0 {
		t.Skip("root writes into a read-only directory")
	}
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	iso := hpSeededVM(t, s, "running")
	dir := filepath.Dir(iso)
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o700) })
	if _, err := s.AttachDevice(adminCtx(), &pb.AttachDeviceRequest{VmName: "hp", Nic: &pb.NetworkAttachment{Name: "lan2", Mac: "52:54:00:5e:02:0a"}}); err != nil {
		t.Fatalf("attach failed on a seed rebuild failure: %v", err)
	}
	if evs := vmEventsOf(t, s, "hp", "seed.rebuild_failed"); len(evs) != 1 || !strings.Contains(evs[0].Detail, "attach or detach") {
		t.Errorf("want one seed.rebuild_failed event naming the remedy: %+v", evs)
	}
}

// Review m4: a paused domain (a partition pause keeps the row "running")
// holds its seed open as a running one does, and its cdrom is reloaded too;
// whether to reload is libvirt's answer, not the row's.
//
// Mutation: reload only a domain libvirt calls running — no reload.
func TestNICHotplug_PausedVMSeedIsReloaded(t *testing.T) {
	useSeedISOWriter(t)
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	hpSeededVM(t, s, "running")
	s.virt.(*libvirtfake.Fake).SetState("hp", libvirtfake.StatePaused)
	if _, err := s.AttachDevice(adminCtx(), &pb.AttachDeviceRequest{VmName: "hp", Nic: &pb.NetworkAttachment{Name: "lan2", Mac: "52:54:00:5e:02:0b"}}); err != nil {
		t.Fatalf("attach: %v", err)
	}
	if n := cdromReloads(s, "hp"); n != 1 {
		t.Errorf("a paused domain's seed cdrom was reloaded %d times, want 1", n)
	}
}

// Review C-1 (migration): where the source cannot tell its NICs from the
// spec, it sends the target its own seed's network-config and vendor-data
// exactly; the target writes what it is sent, including no vendor-data.
//
// Mutation: send "" for an ambiguous network-config — red; let the target
// derive the vendor-data when the source sent it — red.
func TestEnsureCloudInit_AmbiguousSourceSendsItsSeed(t *testing.T) {
	useSeedISOWriter(t)
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	const macX, macA = "52:54:00:6d:00:01", "52:54:00:6d:00:02"
	nc := cloudinit.BuildV1([]cloudinit.StaticIface{{MAC: macX, Address: "10.0.0.10/24"}, {MAC: macA, Address: "10.1.0.50/24"}})
	r2VM(t, s, legacySpec(), []corrosion.InterfaceRecord{
		{VMName: "lg", NetworkName: "lan0", Ordinal: 0, MAC: macX, IP: "10.0.0.77"},
		{VMName: "lg", NetworkName: "lan1", Ordinal: 1, MAC: macA, IP: "10.1.0.50"},
	}, "running", cloudinit.Config{UserData: "#cloud-config\n{}\n", NetworkConfig: nc}, "uuid-lg")
	vm, err := corrosion.GetVM(adminCtx(), s.db, "lg")
	if err != nil || vm == nil {
		t.Fatal(err)
	}
	req := s.ensureCloudInitRequest(adminCtx(), vm)
	if req == nil || req.Networkconfig != nc || req.Vendordata == nil || *req.Vendordata != "" {
		t.Fatalf("request = %+v, want the source seed's network-config and its (empty) vendor-data", req)
	}

	// The target writes the vendor-data it is sent, not one of its own.
	tgt := hotplugDiskServer(t)
	insertTestVMWithSpec(t, adminCtx(), tgt.db, "lg", "test-host", "running", seedSpecJSON(t, &pb.VMSpec{Name: "lg", Uuid: "uuid-lg"}))
	if _, err := tgt.EnsureCloudInit(diskPeerCtx(t, tgt), req); err != nil {
		t.Fatalf("EnsureCloudInit: %v", err)
	}
	sd := mustReadSeed(t, lv.CloudInitISOPath(tgt.dataDir, "lg"))
	if sd.NetworkConfig != nc || sd.VendorData != "" {
		t.Errorf("target seed: network-config %q vendor-data %q", sd.NetworkConfig, sd.VendorData)
	}
}
