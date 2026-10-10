package network

import (
	"testing"

	"github.com/litevirt/litevirt/internal/compose"
)

func TestFlatBridgeName(t *testing.T) {
	// A name that fits keeps its name: existing bridges survive an upgrade.
	for _, n := range []string{"web", "hc_a", "123456789012345"} {
		if got := FlatBridgeName(n); got != n {
			t.Errorf("FlatBridgeName(%q) = %q, want unchanged", n, got)
		}
	}
	long1 := "mystack_frontend_net"
	long2 := "mystack_frontend_nex"
	a, b := FlatBridgeName(long1), FlatBridgeName(long2)
	if len(a) > maxIfaceName || len(b) > maxIfaceName {
		t.Errorf("hashed names exceed IFNAMSIZ: %q %q", a, b)
	}
	if a == b {
		t.Errorf("distinct long names collide on %q", a)
	}
	if a != FlatBridgeName(long1) {
		t.Errorf("not deterministic")
	}
	if err := validLinkName(a); err != nil {
		t.Errorf("hashed name is not a valid link name: %v", err)
	}
}

func TestBridgeName_FlatFallbackUsesFlatBridgeName(t *testing.T) {
	long := "mystack_frontend_net"
	if got := BridgeName(long, compose.NetworkDef{}); got != FlatBridgeName(long) || len(got) > maxIfaceName {
		t.Errorf("BridgeName = %q, want %q", got, FlatBridgeName(long))
	}
	if got := BridgeName("web", compose.NetworkDef{}); got != "web" {
		t.Errorf("short name changed: %q", got)
	}
}

func TestValidateBridgeNetworkName(t *testing.T) {
	long := "a-very-long-network-name"
	for _, tc := range []struct {
		typ, name, iface string
		bad              bool
	}{
		{"bridge", "web", "", false},
		{"", long, "", true},
		{"bridge", long, "br0", false},
		{"bridge", "web", long, true},
		{"vxlan", long, "", false},
		{"isolated", long, "", false},
	} {
		if err := ValidateBridgeNetworkName(tc.typ, tc.name, tc.iface); (err != nil) != tc.bad {
			t.Errorf("%+v: err = %v, want error=%v", tc, err, tc.bad)
		}
	}
}
