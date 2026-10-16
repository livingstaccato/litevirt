package grpcapi

import (
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/cloudinit"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
)

// T2 N6: a migration target that holds the VM's own seed from an earlier
// stay (a failover left it there) reused it as it was and dropped the
// source's request. Since the guest applies a seed's network-config on every
// boot, the first boot back there lost every NIC attached since. The seed
// takes the source's network-config and vendor-data and keeps its meta-data
// and user-data byte for byte. A source from before it sent vendor-data
// derives its network-config another way: the seed is then kept.
//
// Mutation: keep the early return for the VM's own seed (the round-5 code) —
// red.
func TestEnsureCloudInit_RewritesTheVMsStaleSeed(t *testing.T) {
	useSeedISOWriter(t)
	s := testServer(t)
	s.dataDir = t.TempDir()
	insertTestVMWithSpec(t, adminCtx(), s.db, "st", "elsewhere", "running", `{"name":"st","uuid":"st-1","image":"ubuntu"}`)
	iso := lv.CloudInitISOPath(s.dataDir, "st")
	stale := cloudinit.Config{InstanceID: "st-next", LocalHostname: "st", UserData: "#cloud-config\nhostname: st\n",
		NetworkConfig: "version: 2\nethernets:\n  eth0:\n    match:\n      macaddress: \"52:54:00:00:0a:0a\"\n    set-name: eth0\n    dhcp4: true\n"}
	if err := cloudinit.GenerateISO(stale, iso); err != nil {
		t.Fatal(err)
	}
	if err := cloudinit.StampSeed(iso, "st-1"); err != nil {
		t.Fatal(err)
	}
	before := mustReadSeed(t, iso)
	peer := diskPeerCtx(t, s)

	// A source from before the field: kept.
	if _, err := s.EnsureCloudInit(peer, &pb.EnsureCloudInitRequest{VmName: "st", Networkconfig: "version: 2\nethernets: {}\n"}); err != nil {
		t.Fatalf("EnsureCloudInit: %v", err)
	}
	if got := mustReadSeed(t, iso); got != before {
		t.Fatalf("a source that sent no vendor-data changed the seed: %+v", got)
	}

	nc := "version: 2\nethernets:\n  eth0:\n    match:\n      macaddress: \"52:54:00:00:0a:0a\"\n    set-name: eth0\n    dhcp4: true\n" +
		"  eth1:\n    match:\n      macaddress: \"52:54:00:00:0b:0b\"\n    set-name: eth1\n    addresses:\n      - 10.9.0.7/24\n"
	vd := cloudinit.NetworkUpdatesVendorData
	if _, err := s.EnsureCloudInit(peer, &pb.EnsureCloudInitRequest{VmName: "st", Userdata: "#cloud-config\nother\n",
		Networkconfig: nc, Vendordata: &vd}); err != nil {
		t.Fatalf("EnsureCloudInit: %v", err)
	}
	got := mustReadSeed(t, iso)
	if got.NetworkConfig != nc || got.VendorData != vd {
		t.Errorf("the VM's own seed kept its stale network-config: %q %q", got.NetworkConfig, got.VendorData)
	}
	if got.MetaData != before.MetaData || got.UserData != before.UserData {
		t.Errorf("the seed's identity or user-data changed: %q %q", got.MetaData, got.UserData)
	}
	if !cloudinit.SeedIsFor(iso, "st-1") {
		t.Error("the seed is no longer stamped for the VM")
	}
}

// T2 fix round 1, m1: a migration target whose own stale seed cannot take the
// source's network-config (here it is not an ISO the reader understands)
// says so with a seed.rebuild_failed warning naming the seed and the host,
// not only a log line on the source.
//
// Mutation: drop the event — red.
func TestEnsureCloudInit_AStaleSeedItCannotRewriteIsReported(t *testing.T) {
	s := testServer(t)
	s.dataDir = t.TempDir()
	insertTestVMWithSpec(t, adminCtx(), s.db, "st", "elsewhere", "running", `{"name":"st","uuid":"st-1","image":"ubuntu"}`)
	iso, _ := liveISO(t, s, "st")
	if err := cloudinit.StampSeed(iso, "st-1"); err != nil {
		t.Fatal(err)
	}
	vd := cloudinit.NetworkUpdatesVendorData
	if _, err := s.EnsureCloudInit(diskPeerCtx(t, s), &pb.EnsureCloudInitRequest{VmName: "st", Networkconfig: "version: 2\nethernets: {}\n", Vendordata: &vd}); err == nil {
		t.Fatal("EnsureCloudInit succeeded on a seed it cannot read")
	}
	if !cloudinit.SeedMarkedStale(iso) {
		t.Error("the seed it could not rewrite is not marked stale (round 2, R1)")
	}
	evs := vmEventsOf(t, s, "st", "seed.rebuild_failed")
	if len(evs) != 1 || evs[0].Severity != "warning" || !strings.Contains(evs[0].Detail, iso) || !strings.Contains(evs[0].Detail, s.hostName) {
		t.Errorf("want one seed.rebuild_failed warning naming %s and %s: %+v", iso, s.hostName, evs)
	}
}

// T2 fix round 2, R1, the attach path: a NIC attach whose seed rebuild fails
// (here no ISO writer) leaves the NIC attached and the seed without it, and
// marks the seed stale. The next attach's rebuild reads that seed's names as
// possibly stale: B, which it does not list, is eth1 (its ordinal, as every
// host derives it), not left unnamed. The rebuild clears the mark.
//
// Mutation: do not mark on a failed rebuild, or ignore the mark in the
// rebuild — B is unnamed.
func TestNICHotplug_AFailedRebuildMarksTheSeedStale(t *testing.T) {
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	spec := &pb.VMSpec{Name: "x", Uuid: "uuid-x", Image: "ubuntu", Cpu: 2, MemoryMib: 4096,
		Network: []*pb.NetworkAttachment{{Name: "lan", Mac: "52:54:00:75:00:01"}}}
	var iso string
	t.Run("write the seed", func(t *testing.T) {
		useSeedISOWriter(t)
		iso = r2VM(t, s, spec, []corrosion.InterfaceRecord{{VMName: "x", NetworkName: "lan", MAC: "52:54:00:75:00:01"}}, "running",
			cloudinit.Config{InstanceID: "x", LocalHostname: "x", UserData: cloudinit.SpecUserData(spec)}, "uuid-x")
	})
	t.Setenv("PATH", t.TempDir())
	if _, err := s.AttachDevice(adminCtx(), &pb.AttachDeviceRequest{VmName: "x", Nic: &pb.NetworkAttachment{Name: "lan2", Mac: "52:54:00:75:00:02"}}); err != nil {
		t.Fatalf("attach B: %v", err)
	}
	if len(vmEventsOf(t, s, "x", "seed.rebuild_failed")) != 1 || !cloudinit.SeedMarkedStale(iso) {
		t.Fatal("setup: the failed rebuild was not reported, or left no stale mark")
	}
	t.Run("attach C", func(t *testing.T) {
		useSeedISOWriter(t)
		if _, err := s.AttachDevice(adminCtx(), &pb.AttachDeviceRequest{VmName: "x", Nic: &pb.NetworkAttachment{Name: "lan3", Mac: "52:54:00:75:00:03"}}); err != nil {
			t.Fatalf("attach C: %v", err)
		}
	})
	nc := mustReadSeed(t, iso).NetworkConfig
	if !strings.Contains(nc, "macaddress: \"52:54:00:75:00:02\"\n    set-name: eth1\n") || !strings.Contains(nc, "macaddress: \"52:54:00:75:00:03\"\n    set-name: eth2\n") {
		t.Errorf("want B eth1 and C eth2:\n%s", nc)
	}
	if cloudinit.SeedMarkedStale(iso) {
		t.Error("the successful rebuild left the stale mark")
	}
}

// T2 fix round 2, R1, the migration source: a source whose own seed is marked
// stale sends the target names read as possibly stale — B, which the seed does
// not list, is eth1 — and one whose seed is not marked keeps B unnamed (an
// earlier release's attach, which its seed never named).
//
// Mutation: ignore the mark in ensureCloudInitRequest — the marked case
// leaves B unnamed.
func TestEnsureCloudInitRequest_AStaleMarkedSeedNamesWhatItDoesNotList(t *testing.T) {
	useSeedISOWriter(t)
	for _, marked := range []bool{true, false} {
		s := hotplugDiskServer(t)
		enableHardwareV2(t, s)
		spec := &pb.VMSpec{Name: "x", Uuid: "uuid-x", Image: "ubuntu", Cpu: 2, MemoryMib: 4096,
			Network: []*pb.NetworkAttachment{{Name: "lan", Mac: "52:54:00:76:00:01"}}}
		iso := r2VM(t, s, spec, []corrosion.InterfaceRecord{
			{VMName: "x", NetworkName: "lan", MAC: "52:54:00:76:00:01"},
			{VMName: "x", NetworkName: "lan2", Ordinal: 1, MAC: "52:54:00:76:00:02"}}, "running",
			cloudinit.Config{InstanceID: "x", LocalHostname: "x", UserData: cloudinit.SpecUserData(spec)}, "uuid-x")
		if marked {
			if err := cloudinit.MarkSeedStale(iso); err != nil {
				t.Fatal(err)
			}
		}
		vm, err := corrosion.GetVM(adminCtx(), s.db, "x")
		if err != nil || vm == nil {
			t.Fatalf("GetVM: %v", err)
		}
		req := s.ensureCloudInitRequest(adminCtx(), vm)
		if req == nil {
			t.Fatal("no request")
		}
		named := strings.Contains(req.Networkconfig, "macaddress: \"52:54:00:76:00:02\"\n    set-name: eth1\n")
		if named != marked {
			t.Errorf("marked=%v: B named=%v:\n%s", marked, named, req.Networkconfig)
		}
	}
}
