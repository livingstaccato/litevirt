package grpcapi

import (
	"testing"

	"github.com/litevirt/litevirt/internal/testkit/golden"
)

// guestNetworkConfig keeps the two shapes guests boot on today and writes V2
// for the rest. The CreateVM tests in guest_netcfg_create_test.go pin the
// common cases end to end; these pin the edges of the choice and of the V2
// writer.
//
// Mutation: drop `len(nics) <= 1` (return V2 for a lone DHCP NIC) — "one
// DHCP NIC" goes red; drop the `continue` for a NIC that is neither static
// nor DHCP — the golden of "dhcp beside an unaddressable NIC" goes red; drop
// the IPv6 test on Address — the golden of "static v6 ip" routes ::/0 via an
// IPv4 default.
func TestGuestNetworkConfig(t *testing.T) {
	v4 := &isolatedIface{MAC: "52:54:00:00:00:02", Address: "10.0.0.10/24", Gateway: "10.0.0.1", DNS: []string{"1.1.1.1"}}

	if got := guestNetworkConfig(nil); got != "" {
		t.Errorf("no NICs: %q", got)
	}
	if got := guestNetworkConfig([]guestNIC{{Ordinal: 0, MAC: "52:54:00:00:00:01", DHCP: true}}); got != "" {
		t.Errorf("one DHCP NIC: want no network-config (cloud-init's fallback), got:\n%s", got)
	}
	if got := guestNetworkConfig([]guestNIC{{Ordinal: 0, MAC: "52:54:00:00:00:01"}}); got != "" {
		t.Errorf("one NIC litevirt can give nothing: want no network-config, got:\n%s", got)
	}
	if got, want := guestNetworkConfig([]guestNIC{{Ordinal: 0, MAC: v4.MAC, Static: v4}, {Ordinal: 1, MAC: "52:54:00:00:00:03"}}),
		buildIsolatedNetworkConfig([]isolatedIface{*v4}); got != want {
		t.Errorf("static beside an unaddressable NIC: want the V1 document as before, got:\n%s", got)
	}

	for _, tc := range []struct {
		name, path string
		nics       []guestNIC
	}{
		{
			name: "dhcp beside an unaddressable NIC",
			path: "testdata/netconfig_v2_dhcp_and_unaddressed.golden",
			nics: []guestNIC{{Ordinal: 0, MAC: "52:54:00:00:00:01"}, {Ordinal: 1, MAC: "52:54:00:00:00:04", DHCP: true}},
		},
		{
			name: "static v6 ip and dual stack beside dhcp",
			path: "testdata/netconfig_v2_static_v6.golden",
			nics: []guestNIC{
				{Ordinal: 0, MAC: "52:54:00:00:00:01", DHCP: true},
				{Ordinal: 1, MAC: "52:54:00:00:00:05", Static: &isolatedIface{Address: "fd00::10/64", Gateway: "fd00::1", DNS: []string{"2606:4700::1111"}}},
				{Ordinal: 2, MAC: "52:54:00:00:00:06", Static: &isolatedIface{Address: "10.0.0.10/24", Gateway: "10.0.0.1",
					Address6: "fd01::10/64", Gateway6: "fd01::1"}},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			golden.Assert(t, tc.path, guestNetworkConfig(tc.nics))
		})
	}
}
