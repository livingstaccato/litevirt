package network

import (
	"testing"

	"github.com/litevirt/litevirt/internal/compose"
)

// TestLitevirtGatewayCoversDHCP (re-review I-9): the subnet's first host is
// the network's router only where litevirt puts it on the bridge — every
// network some host serves DHCP for, and a vxlan network's anycast gateway —
// never on a VLAN or external bridge, nor where a configured gateway names
// another address.
func TestLitevirtGatewayCoversDHCP(t *testing.T) {
	for _, c := range []struct {
		name string
		def  compose.NetworkDef
		want string
	}{
		{"managed bridge", compose.NetworkDef{Type: "bridge", Subnet: "10.1.0.0/24"}, "10.1.0.1"},
		{"isolated", compose.NetworkDef{Type: "isolated", Subnet: "10.2.0.0/24"}, "10.2.0.1"},
		{"vxlan", compose.NetworkDef{Type: "vxlan", VNI: 5, Subnet: "10.3.0.0/24"}, "10.3.0.1"},
		{"external bridge", compose.NetworkDef{Type: "bridge", External: true, Subnet: "10.4.0.0/24"}, ""},
		{"VLAN bridge", compose.NetworkDef{Type: "bridge", VLAN: 20, Subnet: "10.5.0.0/24"}, ""},
		{"configured router elsewhere", compose.NetworkDef{Type: "bridge", Subnet: "10.6.0.0/24", Gateway: "10.6.0.254"}, ""},
		{"host-isolated", compose.NetworkDef{Type: "bridge", Subnet: "10.7.0.0/24", HostIsolation: true}, ""},
	} {
		if got := c.def.LitevirtGateway(); got != c.want {
			t.Errorf("%s: LitevirtGateway = %q, want %q", c.name, got, c.want)
		}
		for _, f := range []DHCPHostFacts{{BridgePreExisted: c.def.External}, {IsGatewayHost: true, BridgePreExisted: c.def.External}} {
			if DHCPWouldServe(c.def, f) && c.def.LitevirtGateway() == "" && c.def.Gateway == "" {
				t.Errorf("%s: dnsmasq serves (%+v) but the gateway is not litevirt's", c.name, f)
			}
		}
	}
}
