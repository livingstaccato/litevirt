package network

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// Deprovisioning a network's dnsmasq removes its lease file. A file left
// behind is read by every later lookup on the host, and a lease in it for a
// MAC now served elsewhere names an address the guest no longer has.
func TestDeprovision_RemovesTheDnsmasqLeaseFile(t *testing.T) {
	execCommand = func(string, ...string) ([]byte, error) { return nil, nil }
	defer func() { execCommand = defaultExec }()

	cases := []struct {
		name   string
		def    compose.NetworkDef
		bridge string
	}{
		{"bridge", compose.NetworkDef{Type: "bridge", Interface: "br-app", Subnet: "10.0.1.0/24"}, "br-app"},
		{"isolated", compose.NetworkDef{Type: "isolated", Subnet: "10.0.2.0/24"}, IsolatedBridgeName("iso")},
		{"vxlan", compose.NetworkDef{Type: "vxlan", VNI: 500, Subnet: "10.0.3.0/24"}, vxlanBridgeName(500)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			old := dnsmasqLeaseDir
			dnsmasqLeaseDir = dir
			defer func() { dnsmasqLeaseDir = old }()

			mine := dnsmasqLeaseFile(c.bridge)
			other := dnsmasqLeaseFile("br-other")
			for _, f := range []string{mine, other} {
				if err := os.WriteFile(f, []byte("0 52:54:00:aa:bb:01 10.0.1.5 web *\n"), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if filepath.Dir(mine) != dir {
				t.Fatalf("lease file %s is not under the lease dir %s", mine, dir)
			}

			if err := Deprovision(context.Background(), nil, "iso", c.def, "host-a"); err != nil {
				t.Fatalf("Deprovision: %v", err)
			}
			if _, err := os.Stat(mine); !os.IsNotExist(err) {
				t.Errorf("lease file %s survived deprovisioning its network (stat err %v)", mine, err)
			}
			if _, err := os.Stat(other); err != nil {
				t.Errorf("another network's lease file was touched: %v", err)
			}
		})
	}
}

// LeaseBridge is the device the network's dnsmasq leases on, and "" when the
// network is unknown here (the lookup then must not be restricted).
func TestLeaseBridge(t *testing.T) {
	db := corrosion.NewTestClientT(t)
	ctx := context.Background()
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	put := func(name, typ string, def compose.NetworkDef) {
		cfg, _ := json.Marshal(def)
		if err := corrosion.UpsertNetwork(ctx, db, corrosion.NetworkRecord{Name: name, Type: typ, Config: string(cfg)}); err != nil {
			t.Fatal(err)
		}
	}
	put("lan", "bridge", compose.NetworkDef{Interface: "br-lan"})
	put("ov", "vxlan", compose.NetworkDef{VNI: 700})
	put("iso", "isolated", compose.NetworkDef{})
	for net, want := range map[string]string{
		"lan":     "br-lan",
		"ov":      vxlanBridgeName(700),
		"iso":     IsolatedBridgeName("iso"),
		"missing": "",
	} {
		if got := LeaseBridge(ctx, db, net); got != want {
			t.Errorf("LeaseBridge(%s) = %q, want %q", net, got, want)
		}
	}
}
