package grpcapi

import (
	"testing"

	"github.com/litevirt/litevirt/internal/compose"
)

// TestRoutedNetwork: which of a VM's NICs make its isolated NICs lose the
// router — any NIC that can carry its default route, a host-isolated one
// (its seed gives it the bridge as gateway) included; never an isolated NIC
// or one on a network with no record.
func TestRoutedNetwork(t *testing.T) {
	for _, tc := range []struct {
		name string
		def  *compose.NetworkDef
		want bool
	}{
		{"no record", nil, false},
		{"isolated", &compose.NetworkDef{Type: "isolated", Subnet: "10.1.0.0/24"}, false},
		{"isolated v6", &compose.NetworkDef{Type: "isolated", Subnet: "2001:db8::/64"}, false},
		{"isolated host-isolated", &compose.NetworkDef{Type: "isolated", Subnet: "10.1.0.0/24", HostIsolation: true}, true},
		{"bridge", &compose.NetworkDef{Type: "bridge", Subnet: "10.2.0.0/24"}, true},
		{"bridge host-isolated", &compose.NetworkDef{Type: "bridge", HostIsolation: true}, true},
		{"vxlan", &compose.NetworkDef{Type: "vxlan", VNI: 5}, true},
		{"direct", &compose.NetworkDef{Type: "direct", Interface: "eth0"}, true},
	} {
		if got := routedNetwork(tc.def); got != tc.want {
			t.Errorf("%s: routedNetwork = %v, want %v", tc.name, got, tc.want)
		}
	}
}
