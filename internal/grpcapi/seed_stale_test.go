package grpcapi

import (
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/cloudinit"
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
