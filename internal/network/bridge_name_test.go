package network

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// BridgeName and Provision must name the same device for every network type.
// A NIC resolved through BridgeName (hot attach, restart, containers) lands on
// whatever it answers, and a bridge Provision never creates carries no
// traffic, no gateway and no DHCP.
//
// Each def carries interface=<name>, as `lv network create` stores it, since
// that field is what a naive resolver would wrongly prefer.
func TestBridgeName_AgreesWithProvision(t *testing.T) {
	execCommand = func(name string, args ...string) ([]byte, error) { return nil, nil }
	defer func() { execCommand = defaultExec }()
	startDHCPFunc = func(bridge, gw, rangeStart, rangeEnd, mask, pidFile string) error { return nil }
	defer func() { startDHCPFunc = StartDHCP }()

	db, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	ctx := context.Background()
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}

	lo := testLoopbackInterface(t)
	long := "a-rather-long-isolated-name"
	cases := []struct {
		name string
		def  compose.NetworkDef
		want string
	}{
		{"lan", compose.NetworkDef{Type: "bridge", Interface: "br-lan"}, "br-lan"},
		{"ov", compose.NetworkDef{Type: "vxlan", Interface: "ov", VNI: 500, Underlay: lo}, "br-vni500"},
		{"hc", compose.NetworkDef{Type: "isolated", Interface: "hc", Subnet: "172.16.50.0/24", DHCP: true}, "br-iso-hc"},
		{long, compose.NetworkDef{Type: "isolated", Interface: long}, IsolatedBridgeName(long)},
		{"fast", compose.NetworkDef{Type: "sriov", Interface: "fast", PF: "ens1f0"}, "ens1f0"},
		{"mgmt", compose.NetworkDef{Type: "direct", Interface: lo}, "direct:" + lo},
	}
	for _, tc := range cases {
		t.Run(tc.def.Type+"/"+tc.name, func(t *testing.T) {
			provisioned, err := Provision(ctx, db, tc.name, tc.def, "10.0.0.1", "host1")
			if err != nil {
				t.Fatalf("Provision: %v", err)
			}
			if provisioned != tc.want {
				t.Fatalf("Provision returned %q, want %q", provisioned, tc.want)
			}
			if got := BridgeName(tc.name, tc.def); got != provisioned {
				t.Errorf("BridgeName = %q, Provision created %q", got, provisioned)
			}
		})
	}
}
