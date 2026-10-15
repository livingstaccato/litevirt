package grpcapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/cloudinit"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/qcow2"
	"github.com/litevirt/litevirt/internal/testkit/golden"
)

// noNetworkConfig is what the staged genisoimage writes for a seed that
// carries no network-config file at all.
const noNetworkConfig = "<no network-config>"

// stageNetcfgGenisoimage stages a genisoimage whose "ISO" is the seed's
// network-config file verbatim, or noNetworkConfig when the seed has none, so
// a test reads back exactly what the guest's cloud-init would be given.
func stageNetcfgGenisoimage(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	script := `#!/bin/sh
out=""; src=""
while [ $# -gt 0 ]; do
  case "$1" in
    -output) out="$2"; shift ;;
    -volid) shift ;;
    -*) ;;
    *) src="$1" ;;
  esac
  shift
done
if [ -f "$src/network-config" ]; then cat "$src/network-config" > "$out"; else printf '` + noNetworkConfig + `' > "$out"; fi
`
	if err := os.WriteFile(filepath.Join(dir, "genisoimage"), []byte(script), 0o755); err != nil {
		t.Fatalf("stage genisoimage: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// netcfgServer is a create server whose networks are the given definitions,
// provisioned by a fake that touches no host device.
func netcfgServer(t *testing.T, defs map[string]compose.NetworkDef) *Server {
	t.Helper()
	stageNetcfgGenisoimage(t)
	s, _ := provableCreateServer(t)
	// Scan host-isolated subnets from the bottom, so addresses are
	// predictable; TestHostIsolatedAddress_HostsStartApart covers the
	// default.
	s.isoOffset = func(string) uint64 { return 0 }
	s.netProvisioner = &bridgeRemovalProv{}
	s.bridgeEnsure = func(string) error { return nil }
	for name, def := range defs {
		cfg, err := json.Marshal(def)
		if err != nil {
			t.Fatal(err)
		}
		if err := corrosion.UpsertNetwork(adminCtx(), s.db, corrosion.NetworkRecord{
			Name: name, Type: def.Type, Config: string(cfg),
		}); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

// createSeeded creates image VM name with nics and returns its seed's
// network-config as the guest would read it.
func createSeeded(t *testing.T, s *Server, name string, nics ...*pb.NetworkAttachment) string {
	t.Helper()
	req := seedCreateRequest(t, s, name, "")
	req.Spec.Network = nics
	if _, err := s.CreateVM(adminCtx(), req); err != nil {
		t.Fatalf("CreateVM %s: %v", name, err)
	}
	b, err := os.ReadFile(lv.CloudInitISOPath(s.dataDir, name))
	if err != nil {
		t.Fatalf("read seed of %s: %v", name, err)
	}
	return string(b)
}

// nicIPs is the address each of vm's NIC rows records, by network.
func nicIPs(t *testing.T, s *Server, vm string) map[string]string {
	t.Helper()
	ifaces, err := corrosion.GetVMInterfaces(context.Background(), s.db, vm)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, f := range ifaces {
		out[f.NetworkName] = f.IP
	}
	return out
}

var (
	defHostIsolated = compose.NetworkDef{Type: "vxlan", VNI: 5079, Subnet: "10.212.0.0/24", DHCP: true, HostIsolation: true}
	defBridgeDHCP   = compose.NetworkDef{Type: "bridge", Subnet: "172.40.0.0/24", DHCP: true}
	defIsolatedDHCP = compose.NetworkDef{Type: "isolated", Subnet: "10.201.0.0/24", DHCP: true}
)

// Lab 2 (guest-agent run), LBAndSNAT: a VM on a host-isolated network got no
// address at all. Such a network runs no DHCP server by design, and the docs
// promise the address through cloud-init instead ("IPAM still allocates IPs,
// but they are delivered via cloud-init"), but nothing allocated one for a VM
// NIC that named none, so the network-config builder skipped the NIC and the
// guest fell back to DHCP on NIC 0, which nothing answers.
//
// Each such NIC now gets the next free address in the subnet, recorded on its
// NIC row and delivered in the seed; a second VM gets a different one; an
// explicit address is kept exactly as before.
//
// Mutation: drop the hostIsolatedAddress branch from CreateVM — the seed has
// no network-config and the row no address.
func TestCreateVM_HostIsolatedNICIsGivenAStaticAddress(t *testing.T) {
	s := netcfgServer(t, map[string]compose.NetworkDef{"hinet": defHostIsolated})

	seed := createSeeded(t, s, "a", &pb.NetworkAttachment{Name: "hinet", Model: "virtio", Mac: "52:54:00:00:0a:01"})
	if got := nicIPs(t, s, "a")["hinet"]; got != "10.212.0.2" {
		t.Errorf("NIC row address = %q, want 10.212.0.2", got)
	}
	if !strings.Contains(seed, "address: 10.212.0.2/24") {
		t.Fatalf("the seed does not give the guest its address:\n%s", seed)
	}
	golden.Assert(t, "testdata/seed_host_isolated.golden", seed)

	seed = createSeeded(t, s, "b", &pb.NetworkAttachment{Name: "hinet", Model: "virtio", Mac: "52:54:00:00:0b:01"})
	if !strings.Contains(seed, "address: 10.212.0.3/24") || strings.Contains(seed, "10.212.0.2/") {
		t.Errorf("second VM's seed does not carry the next free address:\n%s", seed)
	}

	seed = createSeeded(t, s, "c", &pb.NetworkAttachment{Name: "hinet", Model: "virtio", Mac: "52:54:00:00:0c:01", Ip: "10.212.0.50"})
	if !strings.Contains(seed, "address: 10.212.0.50/24") {
		t.Errorf("an explicit address on a host-isolated NIC was not kept:\n%s", seed)
	}
	if got := nicIPs(t, s, "c")["hinet"]; got != "10.212.0.50" {
		t.Errorf("explicit NIC row address = %q, want 10.212.0.50", got)
	}
}

// The network's gateway, reserved addresses and load balancer VIPs (a live
// LB's, and the one the workload being created brings) are never handed to a
// guest, and an address taken by a create still in flight on this host is
// not handed out twice until that create lets it go.
//
// Mutation: drop the Gateway/ReservedAddresses lines from hostIsolatedAddress
// — the first pick is the gateway; drop the lb_configs VIPs — .5 is picked;
// drop the vips argument — .6 is picked; drop the isoPending record — the
// two picks collide; make releaseHostIsolatedPicks a no-op — the released
// address is not reused.
func TestHostIsolatedAddress_SkipsReservedVIPsAndInFlight(t *testing.T) {
	def := compose.NetworkDef{Type: "bridge", Subnet: "10.213.0.0/24", HostIsolation: true,
		Gateway: "10.213.0.2", ReservedAddresses: []string{"10.213.0.3/24", "10.213.0.4"}}
	s := netcfgServer(t, map[string]compose.NetworkDef{"hi2": def})
	if err := corrosion.UpsertLBConfig(adminCtx(), s.db, corrosion.LBConfigRecord{
		Name: "web", VIP: "10.213.0.5", Algorithm: "roundrobin", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	pick := func() string {
		t.Helper()
		ip, err := s.hostIsolatedAddress(adminCtx(), "hi2", &def, []string{"10.213.0.6"})
		if err != nil {
			t.Fatal(err)
		}
		return ip
	}
	a, b := pick(), pick()
	if a != "10.213.0.7" || b != "10.213.0.8" {
		t.Fatalf("picks = %s, %s; want 10.213.0.7, 10.213.0.8 (gateway, reserved, LB and spec VIPs skipped, no double hand-out)", a, b)
	}
	s.releaseHostIsolatedPicks([]isoPick{{network: "hi2", ip: a}})
	if c := pick(); c != a {
		t.Errorf("after its create let %s go, the next pick is %s", a, c)
	}
}

// Review I-1(b): two hosts picking from the same replica state at once start
// their scans at different, host-hashed points of the subnet, so they rarely
// pick alike; every pick is still a usable host address of the subnet.
//
// Mutation: return 0 from isoScanOffset — both hosts pick .2.
func TestHostIsolatedAddress_HostsStartApart(t *testing.T) {
	def := compose.NetworkDef{Type: "vxlan", VNI: 9, Subnet: "10.214.0.0/24", HostIsolation: true}
	picks := map[string]bool{}
	for _, host := range []string{"node-1", "node-2", "node-3"} {
		s := netcfgServer(t, map[string]compose.NetworkDef{"hi": def})
		s.isoOffset = nil
		s.hostName = host
		ip, err := s.hostIsolatedAddress(adminCtx(), "hi", &def, nil)
		if err != nil {
			t.Fatal(err)
		}
		a, perr := netip.ParseAddr(ip)
		if perr != nil || !netip.MustParsePrefix(def.Subnet).Contains(a) ||
			ip == "10.214.0.0" || ip == "10.214.0.1" || ip == "10.214.0.255" {
			t.Errorf("host %s picked %q, not a usable host address of %s", host, ip, def.Subnet)
		}
		picks[ip] = true
	}
	if len(picks) != 3 {
		t.Errorf("three hosts picked %v from an empty subnet: their scans start together", picks)
	}
}

// Review m-4: a create's host-isolated picks leave the in-flight set when
// the create returns — its rows hold the address on success, and on failure
// nothing does, so the address is free again at once rather than for ten
// minutes.
//
// Mutation: drop the deferred releaseHostIsolatedPicks from CreateVM — red.
func TestCreateVM_LetsItsPicksGo(t *testing.T) {
	s := netcfgServer(t, map[string]compose.NetworkDef{"hinet": defHostIsolated})
	createSeeded(t, s, "ok", &pb.NetworkAttachment{Name: "hinet", Model: "virtio", Mac: "52:54:00:00:0d:01"})
	fake := s.virt.(*libvirtfake.Fake)
	fake.FailStartDomain = func(string) error { return errors.New("qemu refused") }
	req := seedCreateRequest(t, s, "bad", "")
	req.Spec.Network = []*pb.NetworkAttachment{{Name: "hinet", Model: "virtio", Mac: "52:54:00:00:0d:02"}}
	if _, err := s.CreateVM(adminCtx(), req); err == nil {
		t.Fatal("the create was meant to fail at its start")
	}
	s.dhcpResMu.Lock()
	left := len(s.isoPending["hinet"])
	s.dhcpResMu.Unlock()
	if left != 0 {
		t.Errorf("%d picks still in flight after both creates returned", left)
	}
}

// Review I-2: the VIP a VM's own load balancer brings is not handed to it,
// though the LB's row is written only after the VMs of its stack.
func TestCreateVM_HostIsolatedPickSkipsItsOwnVIP(t *testing.T) {
	s := netcfgServer(t, map[string]compose.NetworkDef{"hinet": defHostIsolated})
	req := seedCreateRequest(t, s, "lbvm", "")
	req.Spec.Network = []*pb.NetworkAttachment{{Name: "hinet", Model: "virtio", Mac: "52:54:00:00:0e:01"}}
	req.Spec.Loadbalancer = &pb.LBSpec{Enabled: true, Vip: "10.212.0.2"}
	if _, err := s.CreateVM(adminCtx(), req); err != nil {
		t.Fatal(err)
	}
	if got := nicIPs(t, s, "lbvm")["hinet"]; got != "10.212.0.3" {
		t.Errorf("NIC address = %q, want 10.212.0.3 (.2 is its LB's VIP)", got)
	}
}

// Review m-5: a container claiming on a host-isolated network passes over
// an address a VM create on this host has picked but not yet written.
//
// Mutation: drop req.Exclude in resolveContainerNICs — the container gets
// the VM's address.
func TestContainerClaim_PassesOverAVMsPickInFlight(t *testing.T) {
	s := netcfgServer(t, map[string]compose.NetworkDef{"hinet": defHostIsolated})
	ip, err := s.hostIsolatedAddress(adminCtx(), "hinet", &defHostIsolated, nil)
	if err != nil || ip != "10.212.0.2" {
		t.Fatalf("VM pick = %q, %v", ip, err)
	}
	plan, err := s.resolveContainerNICs(adminCtx(), "", "ct1",
		[]*pb.ContainerNetwork{{Name: "eth0", NetworkName: "hinet"}})
	if err != nil {
		t.Fatal(err)
	}
	if got := plan.ifaces[0].IP; got == "10.212.0.2" || got == "" {
		t.Errorf("container address = %q, want one other than the VM's in-flight .2", got)
	}
}

// Review I-3: a seed rebuilt where the VM's ISO is missing (failover,
// migration) is derived from what the cluster records — the spec, the NIC
// rows, the networks — and equals the seed CreateVM wrote, for every shape:
// one DHCP NIC (none), all static (V1), several NICs with a host-isolated
// pick (V2). A DHCP NIC whose row the IP scanner has since filled stays DHCP.
//
// Mutation: read every recorded address as static in cloudinit.NetworkConfig
// — the rebuilt multi-NIC seed differs once the scanner has written the DHCP
// NIC's address.
func TestCreateVM_SeedIsRebuiltAlike(t *testing.T) {
	s := netcfgServer(t, map[string]compose.NetworkDef{
		"brnet": defBridgeDHCP, "isonet": defIsolatedDHCP, "hinet": defHostIsolated,
	})
	for _, tc := range []struct {
		name string
		nics []*pb.NetworkAttachment
	}{
		{"one", []*pb.NetworkAttachment{{Name: "brnet", Model: "virtio", Mac: "52:54:00:00:10:01"}}},
		{"static", []*pb.NetworkAttachment{
			{Name: "brnet", Model: "virtio", Mac: "52:54:00:00:11:01", Ip: "172.40.0.30"},
			{Name: "hinet", Model: "virtio", Mac: "52:54:00:00:11:02"}}},
		{"multi", []*pb.NetworkAttachment{
			{Name: "brnet", Model: "virtio", Mac: "52:54:00:00:12:01"},
			{Name: "isonet", Model: "virtio", Mac: "52:54:00:00:12:02"},
			{Name: "hinet", Model: "virtio", Mac: "52:54:00:00:12:03"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			seed := createSeeded(t, s, tc.name, tc.nics...)
			// The IP scanner records the DHCP NIC's lease.
			if err := s.db.Execute(adminCtx(), `UPDATE vm_interfaces SET ip = '172.40.0.99' WHERE vm_name = ? AND network_name = 'brnet' AND (ip IS NULL OR ip = '')`, tc.name); err != nil {
				t.Fatal(err)
			}
			vm, err := corrosion.GetVM(adminCtx(), s.db, tc.name)
			if err != nil || vm == nil {
				t.Fatalf("GetVM: %v", err)
			}
			var spec pb.VMSpec
			if err := json.Unmarshal([]byte(vm.Spec), &spec); err != nil {
				t.Fatal(err)
			}
			rebuilt, err := cloudinit.SeedNetworkConfig(adminCtx(), s.db, tc.name, &spec)
			if err != nil {
				t.Fatal(err)
			}
			if rebuilt == "" {
				rebuilt = noNetworkConfig
			}
			if rebuilt != seed {
				t.Errorf("rebuilt seed differs from the created one\ncreated:\n%s\nrebuilt:\n%s", seed, rebuilt)
			}
		})
	}
}

// Review I-3: a clone's NIC on a host-isolated network is given its own
// address, and the clone's seed configures it, where before the clone booted
// on cloud-init's fallback with no address.
//
// Mutation: drop the host-isolated branch from cloneVMOnSource — red.
func TestCloneVM_HostIsolatedNICGetsItsOwnAddress(t *testing.T) {
	s := netcfgServer(t, map[string]compose.NetworkDef{"hinet": defHostIsolated})
	ctx := adminCtx()
	srcDisk := s.images.DiskPath("src", "root")
	if err := os.MkdirAll(filepath.Dir(srcDisk), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := qcow2.Create(srcDisk, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	specJSON, _ := json.Marshal(&pb.VMSpec{Name: "src", Cpu: 1, MemoryMib: 512, Image: "ubuntu",
		Network: []*pb.NetworkAttachment{{Name: "hinet", Mac: "52:54:00:00:13:01"}}})
	if err := corrosion.InsertVM(ctx, s.db,
		corrosion.VMRecord{Name: "src", HostName: "test-host", State: "stopped", Spec: string(specJSON)},
		[]corrosion.InterfaceRecord{{VMName: "src", NetworkName: "hinet", MAC: "52:54:00:00:13:01", IP: "10.212.0.2"}},
		[]corrosion.DiskRecord{{VMName: "src", DiskName: "root", HostName: "test-host", Path: srcDisk, SizeBytes: 1 << 20, StorageType: "local"}},
	); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CloneVM(ctx, &pb.CloneVMRequest{Source: "src", Target: "c1", Mode: "full"}); err != nil {
		t.Fatalf("CloneVM: %v", err)
	}
	got := nicIPs(t, s, "c1")["hinet"]
	if got == "" || got == nicIPs(t, s, "src")["hinet"] {
		t.Fatalf("clone NIC address = %q, want its own (source has %q)", got, nicIPs(t, s, "src")["hinet"])
	}
	b, err := os.ReadFile(lv.CloudInitISOPath(s.dataDir, "c1"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "address: "+got+"/24") {
		t.Errorf("the clone's seed does not give it %s:\n%s", got, b)
	}
}

// Rolling-upgrade and "don't change working guests" pin: a VM whose only NIC
// asks DHCP gets a seed with NO network-config file, exactly as before, so
// cloud-init's own fallback (DHCP on that NIC) applies unchanged. A VM whose
// NICs are all static gets the same V1 document as before.
//
// Mutation: make cloudinit.GuestNetworkConfig render a single DHCP NIC — the first
// check goes red; render the all-static case through the V2 writer — the
// golden goes red.
func TestCreateVM_SeedsThatWorkedAreUnchanged(t *testing.T) {
	s := netcfgServer(t, map[string]compose.NetworkDef{"brnet": defBridgeDHCP, "isonet": defIsolatedDHCP})

	if seed := createSeeded(t, s, "one", &pb.NetworkAttachment{Name: "brnet", Model: "virtio", Mac: "52:54:00:00:01:01"}); seed != noNetworkConfig {
		t.Errorf("a single DHCP NIC's seed changed; want no network-config, got:\n%s", seed)
	}
	if seed := createSeeded(t, s, "flat", &pb.NetworkAttachment{Name: "lo", Model: "virtio", Mac: "52:54:00:00:02:01"}); seed != noNetworkConfig {
		t.Errorf("a single flat-bridge NIC's seed changed; want no network-config, got:\n%s", seed)
	}

	seed := createSeeded(t, s, "static2",
		&pb.NetworkAttachment{Name: "brnet", Model: "virtio", Mac: "52:54:00:00:03:01", Ip: "172.40.0.10"},
		&pb.NetworkAttachment{Name: "isonet", Model: "virtio", Mac: "52:54:00:00:03:02", Ip: "10.201.0.10", Ipv6: "fd00::10"})
	golden.Assert(t, "testdata/seed_all_static.golden", seed)
	want := buildIsolatedNetworkConfig([]isolatedIface{
		{MAC: "52:54:00:00:03:01", Address: "172.40.0.10/24", Gateway: "172.40.0.1", DNS: []string{"1.1.1.1", "8.8.8.8"}},
		{MAC: "52:54:00:00:03:02", Address: "10.201.0.10/24", Gateway: "10.201.0.1", DNS: []string{"1.1.1.1", "8.8.8.8"}, Address6: "fd00::10/64"},
	})
	if seed != want {
		t.Errorf("an all-static seed is not the V1 document it was:\n got:\n%s\nwant:\n%s", seed, want)
	}
}

// Lab 2 (guest-agent run), Overlay: a VM with a NIC on each of three
// networks came up with only NIC 0 configured. litevirt passed no
// network-config for DHCP NICs, so cloud-init's fallback configured the first
// NIC alone; enp2s0 and enp3s0 stayed DOWN and the isolated network's dnsmasq
// never saw a DISCOVER. The docs promise addressing per NIC ("ip: optional,
// DHCP if omitted").
//
// A VM with more than one NIC now gets a network-config naming every NIC by
// MAC: DHCP where it names no address, static where it has one.
//
// Mutation: return "" from cloudinit.GuestNetworkConfig when no NIC is static — the
// all-DHCP VM (the lab's own shape) gets no network-config. Treat a
// host-isolated NIC with no address as DHCP — the subnet-less one appears in
// the seed.
func TestCreateVM_EveryDHCPNICIsConfigured(t *testing.T) {
	s := netcfgServer(t, map[string]compose.NetworkDef{
		"brnet": defBridgeDHCP, "isonet": defIsolatedDHCP, "hinet": defHostIsolated,
		"hinosub": {Type: "bridge", HostIsolation: true},
	})

	// The lab's shape: a NIC on each of two DHCP networks, none static.
	seed := createSeeded(t, s, "alldhcp",
		&pb.NetworkAttachment{Name: "brnet", Model: "virtio", Mac: "52:54:00:00:06:01"},
		&pb.NetworkAttachment{Name: "isonet", Model: "virtio", Mac: "52:54:00:00:06:02"})
	golden.Assert(t, "testdata/seed_all_dhcp.golden", seed)

	// A host-isolated network with no subnet serves no DHCP and gives no
	// address: its NIC is left out rather than told to ask DHCP of nobody.
	seed = createSeeded(t, s, "nosub",
		&pb.NetworkAttachment{Name: "brnet", Model: "virtio", Mac: "52:54:00:00:07:01"},
		&pb.NetworkAttachment{Name: "hinosub", Model: "virtio", Mac: "52:54:00:00:07:02"})
	if !strings.Contains(seed, "52:54:00:00:07:01") || strings.Contains(seed, "52:54:00:00:07:02") {
		t.Errorf("want the DHCP NIC configured and the unaddressable host-isolated one left out:\n%s", seed)
	}
	seed = createSeeded(t, s, "multi",
		&pb.NetworkAttachment{Name: "brnet", Model: "virtio", Mac: "52:54:00:00:04:01"},
		&pb.NetworkAttachment{Name: "isonet", Model: "virtio", Mac: "52:54:00:00:04:02"},
		&pb.NetworkAttachment{Name: "hinet", Model: "virtio", Mac: "52:54:00:00:04:03"})
	for _, mac := range []string{"52:54:00:00:04:01", "52:54:00:00:04:02", "52:54:00:00:04:03"} {
		if !strings.Contains(seed, mac) {
			t.Fatalf("NIC %s is not configured in the seed:\n%s", mac, seed)
		}
	}
	golden.Assert(t, "testdata/seed_multi_nic.golden", seed)

	// A static NIC beside a DHCP one: before, the static NIC's V1 document
	// was the whole network-config and the DHCP NIC was left DOWN.
	seed = createSeeded(t, s, "mixed",
		&pb.NetworkAttachment{Name: "brnet", Model: "virtio", Mac: "52:54:00:00:05:01"},
		&pb.NetworkAttachment{Name: "isonet", Model: "virtio", Mac: "52:54:00:00:05:02", Ip: "10.201.0.20"})
	golden.Assert(t, "testdata/seed_mixed.golden", seed)
}
