package grpcapi

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
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

// The network's gateway and reserved addresses are never handed to a guest,
// and an address taken by a create still in flight on this host is not handed
// out twice.
//
// Mutation: drop the Gateway/ReservedAddresses lines from hostIsolatedAddress
// — the first pick is the reserved address; drop the isoPending record — the
// two picks collide.
func TestHostIsolatedAddress_SkipsReservedAndInFlight(t *testing.T) {
	def := compose.NetworkDef{Type: "bridge", Subnet: "10.213.0.0/24", HostIsolation: true,
		Gateway: "10.213.0.2", ReservedAddresses: []string{"10.213.0.3/24"}}
	s := netcfgServer(t, map[string]compose.NetworkDef{"hi2": def})
	a, err := s.hostIsolatedAddress(adminCtx(), "hi2", &def)
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.hostIsolatedAddress(adminCtx(), "hi2", &def)
	if err != nil {
		t.Fatal(err)
	}
	if a != "10.213.0.4" || b != "10.213.0.5" {
		t.Errorf("picks = %s, %s; want 10.213.0.4, 10.213.0.5 (gateway .2 and reserved .3 skipped, no double hand-out)", a, b)
	}
}

// Which networks litevirt addresses this way: host-isolated IPv4 subnets on
// the types it owns the L2 of. Not a network that serves DHCP, not a
// NetBox-bound one (NetBox allocates there), not hardware it does not address.
func TestHostIsolatedAddressable(t *testing.T) {
	for _, tc := range []struct {
		def  *compose.NetworkDef
		want bool
	}{
		{nil, false},
		{&defHostIsolated, true},
		{&compose.NetworkDef{Type: "bridge", Subnet: "10.0.0.0/24", HostIsolation: true}, true},
		{&compose.NetworkDef{Type: "isolated", Subnet: "10.0.0.0/24", HostIsolation: true}, true},
		{&defBridgeDHCP, false},
		{&compose.NetworkDef{Type: "bridge", HostIsolation: true}, false},
		{&compose.NetworkDef{Type: "bridge", Subnet: "fd00::/64", HostIsolation: true}, false},
		{&compose.NetworkDef{Type: "sriov", Subnet: "10.0.0.0/24", HostIsolation: true}, false},
		{&compose.NetworkDef{Type: "direct", Subnet: "10.0.0.0/24", HostIsolation: true}, false},
		{&compose.NetworkDef{Type: "bridge", Subnet: "10.0.0.0/24", HostIsolation: true, NetBoxPrefixID: 7}, false},
	} {
		if got := hostIsolatedAddressable(tc.def); got != tc.want {
			t.Errorf("hostIsolatedAddressable(%+v) = %v, want %v", tc.def, got, tc.want)
		}
	}
}

// Rolling-upgrade and "don't change working guests" pin: a VM whose only NIC
// asks DHCP gets a seed with NO network-config file, exactly as before, so
// cloud-init's own fallback (DHCP on that NIC) applies unchanged. A VM whose
// NICs are all static gets the same V1 document as before.
//
// Mutation: make guestNetworkConfig render a single DHCP NIC — the first
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
// Mutation: return "" from guestNetworkConfig when no NIC is static — the
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
