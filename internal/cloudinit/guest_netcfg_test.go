package cloudinit

import (
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/testkit/golden"
)

// GuestNetworkConfig keeps the two shapes guests boot on today and writes V2
// for the rest. The CreateVM tests in internal/grpcapi pin the common cases
// end to end; these pin the edges of the choice and of the V2 writer.
//
// Mutation: drop `len(nics) <= 1` (return V2 for a lone DHCP NIC) — "one
// DHCP NIC" goes red; drop the `continue` for a NIC that is neither static
// nor DHCP — the golden of "dhcp beside an unaddressable NIC" goes red; drop
// the IPv6 test on Address — the golden of "static v6 ip" routes ::/0 via an
// IPv4 default; make `optional` follow the ordinal instead of the first NIC
// written — the "unaddressable" golden goes red.
func TestGuestNetworkConfig(t *testing.T) {
	v4 := &StaticIface{MAC: "52:54:00:00:00:02", Address: "10.0.0.10/24", Gateway: "10.0.0.1", DNS: []string{"1.1.1.1"}}

	if got := GuestNetworkConfig(nil); got != "" {
		t.Errorf("no NICs: %q", got)
	}
	if got := GuestNetworkConfig([]GuestNIC{{Ordinal: 0, MAC: "52:54:00:00:00:01", DHCP: true, DHCP6: true}}); got != "" {
		t.Errorf("one DHCP NIC: want no network-config (cloud-init's fallback), got:\n%s", got)
	}
	if got := GuestNetworkConfig([]GuestNIC{{Ordinal: 0, MAC: "52:54:00:00:00:01"}}); got != "" {
		t.Errorf("one NIC litevirt can give nothing: want no network-config, got:\n%s", got)
	}
	if got, want := GuestNetworkConfig([]GuestNIC{{Ordinal: 0, MAC: v4.MAC, Static: v4}, {Ordinal: 1, MAC: "52:54:00:00:00:03"}}),
		BuildV1([]StaticIface{*v4}); got != want {
		t.Errorf("static beside an unaddressable NIC: want the V1 document as before, got:\n%s", got)
	}

	for _, tc := range []struct {
		name, path string
		nics       []GuestNIC
	}{
		{
			name: "dhcp beside an unaddressable NIC",
			path: "testdata/netconfig_v2_dhcp_and_unaddressed.golden",
			nics: []GuestNIC{{Ordinal: 0, MAC: "52:54:00:00:00:01"}, {Ordinal: 1, MAC: "52:54:00:00:00:04", DHCP: true, DHCP6: true}},
		},
		{
			name: "static v6 ip and dual stack beside dhcp",
			path: "testdata/netconfig_v2_static_v6.golden",
			nics: []GuestNIC{
				{Ordinal: 0, MAC: "52:54:00:00:00:01", DHCP: true, DHCP6: true},
				{Ordinal: 1, MAC: "52:54:00:00:00:05", Static: &StaticIface{Address: "fd00::10/64", Gateway: "fd00::1", DNS: []string{"2606:4700::1111"}}},
				{Ordinal: 2, MAC: "52:54:00:00:00:06", Static: &StaticIface{Address: "10.0.0.10/24", Gateway: "10.0.0.1",
					Address6: "fd01::10/64", Gateway6: "fd01::1"}},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			golden.Assert(t, tc.path, GuestNetworkConfig(tc.nics))
		})
	}
}

// Review C-1: cloud-init's non-netplan renderers (networkd, sysconfig, ENI)
// name a V2 entry's device by its key and rename a NIC only for an entry with
// set-name, so an entry keyed eth1 with no set-name configures a device the
// guest (which calls it enp2s0) does not have. Every V2 entry carries
// set-name eth<ordinal>, as the V1 document names every NIC eth<n>.
//
// Mutation: drop the set-name line from guestNetworkConfigV2 — red.
func TestGuestNetworkConfigV2_EveryEntryIsRenamed(t *testing.T) {
	doc := GuestNetworkConfig([]GuestNIC{
		{Ordinal: 0, MAC: "52:54:00:00:00:01", DHCP: true},
		{Ordinal: 1, MAC: "52:54:00:00:00:02", Static: &StaticIface{Address: "10.0.0.10/24"}},
		{Ordinal: 2, MAC: "52:54:00:00:00:03", DHCP: true},
	})
	for _, want := range []string{
		"  eth0:\n    match:\n      macaddress: \"52:54:00:00:00:01\"\n    set-name: eth0\n",
		"  eth1:\n    match:\n      macaddress: \"52:54:00:00:00:02\"\n    set-name: eth1\n",
		"  eth2:\n    match:\n      macaddress: \"52:54:00:00:00:03\"\n    set-name: eth2\n",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("entry not renamed; want\n%s\nin:\n%s", want, doc)
		}
	}
}

// Review m-3: a DHCP NIC asks DHCPv6 only where its network has an IPv6
// subnet, or where litevirt has no record of the network (cloud-init's
// fallback asks both): sysconfig's DHCPV6C=yes on an IPv4-only network can
// stall ifup.
//
// Mutation: set DHCP6 for every DHCP NIC in NetworkConfig — red; drop the
// Subnet == "" case — the flat-bridge check goes red.
func TestNetworkConfig_DHCPv6OnlyWhereTheNetworkHasIPv6(t *testing.T) {
	doc := NetworkConfig([]NIC{
		{Ordinal: 0, MAC: "52:54:00:00:00:01", Net: &compose.NetworkDef{Type: "bridge", Subnet: "10.0.0.0/24", DHCP: true}},
		{Ordinal: 1, MAC: "52:54:00:00:00:02", Net: &compose.NetworkDef{Type: "isolated", Subnet: "fd00:1::/64", DHCP: true}},
		{Ordinal: 2, MAC: "52:54:00:00:00:03"},
	})
	golden.Assert(t, "testdata/netconfig_v2_dhcp6.golden", doc)
	if strings.Count(doc, "dhcp6: true") != 2 {
		t.Errorf("want dhcp6 on the IPv6 and the unrecorded network only:\n%s", doc)
	}
	// Re-review R1-m4: a recorded network with no subnet (a flat bridge to
	// an external LAN) is the fallback's case too.
	flat := NetworkConfig([]NIC{
		{Ordinal: 0, MAC: "52:54:00:00:00:01", Net: &compose.NetworkDef{Type: "bridge", Subnet: "10.0.0.0/24", DHCP: true}},
		{Ordinal: 1, MAC: "52:54:00:00:00:02", Net: &compose.NetworkDef{Type: "bridge"}},
	})
	if strings.Count(flat, "dhcp6: true") != 1 || !strings.Contains(flat, "route-metric: 101\n    dhcp6: true") {
		t.Errorf("a recorded network with no subnet: want dhcp6 on it:\n%s", flat)
	}
}

// Re-review R1-I1: a NIC whose MAC is not known cannot be matched in the
// guest; a set with one gets no network-config, never an entry with an
// empty MAC.
//
// Mutation: drop the empty-MAC guard — red.
func TestNetworkConfig_NoMACWritesNone(t *testing.T) {
	for _, nics := range [][]NIC{
		{{Ordinal: 0, MAC: "52:54:00:00:00:01"}, {Ordinal: 1}},
		{{Ordinal: 0, IP: "10.0.0.10"}, {Ordinal: 1, MAC: "52:54:00:00:00:02", IP: "10.0.0.11"}},
	} {
		if got := NetworkConfig(nics); got != "" {
			t.Errorf("a NIC with no MAC: want no network-config, got:\n%s", got)
		}
	}
}

// Review m-2: a network that names its router (`gateway:`) says the subnet's
// first host is not one; a static NIC's default route goes to the router.
// The NIC's own gateway still wins, and a network without one keeps the
// first host, as before.
//
// Mutation: drop the netDef.Gateway fallback from StaticAddress — red.
func TestStaticAddress_UsesTheNetworkGateway(t *testing.T) {
	routed := &compose.NetworkDef{Subnet: "10.0.0.0/24", Gateway: "10.0.0.254"}
	for _, tc := range []struct {
		ip, gw       string
		def          *compose.NetworkDef
		wantAddr, gW string
	}{
		{"10.0.0.10", "", routed, "10.0.0.10/24", "10.0.0.254"},
		{"10.0.0.10", "10.0.0.9", routed, "10.0.0.10/24", "10.0.0.9"},
		{"10.0.0.10", "", &compose.NetworkDef{Subnet: "10.0.0.0/24", Gateway: "10.0.0.254/24"}, "10.0.0.10/24", "10.0.0.254"},
		{"10.0.0.10", "", &compose.NetworkDef{Subnet: "10.0.0.0/24"}, "10.0.0.10/24", "10.0.0.1"},
		{"10.0.0.10", "", nil, "10.0.0.10/24", ""},
	} {
		addr, gw := StaticAddress(tc.ip, tc.gw, tc.def)
		if addr != tc.wantAddr || gw != tc.gW {
			t.Errorf("StaticAddress(%q, %q, %+v) = %q, %q; want %q, %q", tc.ip, tc.gw, tc.def, addr, gw, tc.wantAddr, tc.gW)
		}
	}
}

// A recorded address is static only where litevirt itself gave it: a NetBox
// claim, or a host-isolated pick. Elsewhere it is a DHCP lease, a DHCP
// reservation or what the IP scanner saw, and the NIC asks DHCP — so a seed
// rebuilt from the rows matches the one written at create.
//
// Mutation: read every recorded address as static — the DHCP NIC turns
// static and the document changes.
func TestNetworkConfig_RecordedAddressIsStaticOnlyWhereLitevirtGaveIt(t *testing.T) {
	dhcpNet := &compose.NetworkDef{Type: "bridge", Subnet: "10.0.0.0/24", DHCP: true}
	hiNet := &compose.NetworkDef{Type: "vxlan", Subnet: "10.9.0.0/24", HostIsolation: true}
	doc := NetworkConfig([]NIC{
		{Ordinal: 0, MAC: "52:54:00:00:00:01", RecordedIP: "10.0.0.77", Net: dhcpNet},
		{Ordinal: 1, MAC: "52:54:00:00:00:02", RecordedIP: "10.9.0.5", Net: hiNet},
		{Ordinal: 2, MAC: "52:54:00:00:00:03", RecordedIP: "10.0.0.88", Net: dhcpNet, Bound: true},
	})
	if strings.Contains(doc, "10.0.0.77") {
		t.Errorf("a DHCP NIC's recorded lease was written as static:\n%s", doc)
	}
	for _, want := range []string{"10.9.0.5/24", "10.0.0.88/24"} {
		if !strings.Contains(doc, want) {
			t.Errorf("litevirt-given address %s not static:\n%s", want, doc)
		}
	}
}

// Which networks litevirt addresses itself: host-isolated IPv4 subnets on the
// types it owns the L2 of. Not a network that serves DHCP, not a NetBox-bound
// one (NetBox allocates there), not hardware it does not address.
func TestHostIsolatedAddressable(t *testing.T) {
	for _, tc := range []struct {
		def  *compose.NetworkDef
		want bool
	}{
		{nil, false},
		{&compose.NetworkDef{Type: "vxlan", VNI: 5, Subnet: "10.0.0.0/24", HostIsolation: true}, true},
		{&compose.NetworkDef{Type: "bridge", Subnet: "10.0.0.0/24", HostIsolation: true}, true},
		{&compose.NetworkDef{Type: "isolated", Subnet: "10.0.0.0/24", HostIsolation: true}, true},
		{&compose.NetworkDef{Type: "bridge", Subnet: "10.0.0.0/24", DHCP: true}, false},
		{&compose.NetworkDef{Type: "bridge", HostIsolation: true}, false},
		{&compose.NetworkDef{Type: "bridge", Subnet: "fd00::/64", HostIsolation: true}, false},
		{&compose.NetworkDef{Type: "sriov", Subnet: "10.0.0.0/24", HostIsolation: true}, false},
		{&compose.NetworkDef{Type: "direct", Subnet: "10.0.0.0/24", HostIsolation: true}, false},
		{&compose.NetworkDef{Type: "bridge", Subnet: "10.0.0.0/24", HostIsolation: true, NetBoxPrefixID: 7}, false},
	} {
		if got := HostIsolatedAddressable(tc.def); got != tc.want {
			t.Errorf("HostIsolatedAddressable(%+v) = %v, want %v", tc.def, got, tc.want)
		}
	}
}
