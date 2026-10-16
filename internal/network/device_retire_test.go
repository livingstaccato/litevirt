package network

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// Re-review NC1: the network's firewall intent (net:<name>) is keyed by the
// network, and after a move it describes the NEW device. Retiring the device
// the network moved off must leave it; Deprovision, which takes the whole
// network down, removes it.
//
// Mutation: make RetireDevice delete the network's intent — red.
func TestRetireDevice_KeepsTheNetworksFirewallIntent(t *testing.T) {
	privateDeviceFiles(t)
	execCommand = func(string, ...string) ([]byte, error) { return nil, nil }
	t.Cleanup(func() { execCommand = defaultExec })
	db := corrosion.NewTestClientT(t)
	ctx := context.Background()
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	intent := func() *corrosion.HostFWIntent {
		all, err := corrosion.ListHostFWIntent(ctx, db, "h1")
		if err != nil {
			t.Fatal(err)
		}
		for i := range all {
			if all[i].ScopeKey == "net:st_lan" {
				return &all[i]
			}
		}
		return nil
	}
	if err := corrosion.UpsertHostFWIntent(ctx, db, "h1", corrosion.HostFWIntent{
		ScopeKey: "net:st_lan", Bridge: "lvnewbr", MasqueradeSubnet: "172.46.0.0/24",
	}); err != nil {
		t.Fatal(err)
	}
	old := compose.NetworkDef{Type: "bridge", Interface: "lvoldbr", Subnet: "172.46.0.0/24"}

	if err := RetireDevice(ctx, db, "st_lan", old, "h1"); err != nil {
		t.Fatalf("RetireDevice: %v", err)
	}
	if in := intent(); in == nil || in.Bridge != "lvnewbr" {
		t.Fatalf("after retiring lvoldbr the network's intent is %+v, want it kept on lvnewbr", in)
	}

	if err := Deprovision(ctx, db, "st_lan", old, "h1"); err != nil {
		t.Fatalf("Deprovision: %v", err)
	}
	if in := intent(); in != nil {
		t.Errorf("Deprovision left the network's intent %+v", in)
	}
}

// Re-review R2-m3: a move refuses on overlapping subnets, not only on equal
// gateways — a /16 and a /24 inside it leave two connected routes.
func TestSubnetsOverlap(t *testing.T) {
	d := func(s string) compose.NetworkDef { return compose.NetworkDef{Subnet: s} }
	for _, tc := range []struct {
		a, b string
		want bool
	}{
		{"172.46.0.0/24", "172.46.0.0/24", true},
		{"172.46.0.0/16", "172.46.9.0/24", true},
		{"172.46.0.0/24", "172.47.0.0/24", false},
		{"", "172.46.0.0/24", false},
	} {
		if got := SubnetsOverlap(d(tc.a), d(tc.b)); got != tc.want {
			t.Errorf("SubnetsOverlap(%s, %s) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}
