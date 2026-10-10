package network

import "testing"

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
