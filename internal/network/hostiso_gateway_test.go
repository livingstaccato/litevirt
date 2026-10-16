package network

import (
	"context"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// A host-isolated bridge network gets the guests' gateway on a bridge
// litevirt made, as a vxlan network's IRB gateway does, so the host can route
// for its guests (an LB's SNAT). A bridge litevirt did not make, or one on a
// physical VLAN, has its router upstream and gets no address.
//
// Mutation: drop the address, or drop the created-here gate — red.
func TestProvision_HostIsolatedBridgeGetsTheGateway(t *testing.T) {
	for _, tc := range []struct {
		name    string
		def     compose.NetworkDef
		created bool
		want    bool
	}{
		{"created here", compose.NetworkDef{Type: "bridge", Interface: "lvhitest0", Subnet: "10.202.0.0/24", HostIsolation: true}, true, true},
		{"not created here", compose.NetworkDef{Type: "bridge", Interface: "lvhitest0", Subnet: "10.202.0.0/24", HostIsolation: true}, false, false},
		{"physical VLAN", compose.NetworkDef{Type: "bridge", Interface: "lvhitest0", Subnet: "10.202.0.0/24", HostIsolation: true, VLAN: 209, Underlay: "lvund0"}, true, false},
		{"no subnet", compose.NetworkDef{Type: "bridge", Interface: "lvhitest0", HostIsolation: true}, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls []string
			execCommand = func(name string, args ...string) ([]byte, error) {
				calls = append(calls, strings.Join(append([]string{name}, args...), " "))
				return nil, nil
			}
			created := tc.created
			bridgeCreatedHere = func(string) bool { return created }
			defer func() {
				execCommand = defaultExec
				bridgeCreatedHere = defaultBridgeCreatedHere
			}()
			db := corrosion.NewTestClientT(t)
			if err := corrosion.InitSchema(context.Background(), db); err != nil {
				t.Fatal(err)
			}
			if _, err := Provision(context.Background(), db, "hinet", tc.def, "", "host1"); err != nil {
				t.Fatalf("Provision: %v", err)
			}
			got := false
			for _, c := range calls {
				if c == "ip addr add 10.202.0.1/24 dev lvhitest0" {
					got = true
				}
			}
			if got != tc.want {
				t.Errorf("gateway added = %v, want %v; commands:\n%s", got, tc.want, strings.Join(calls, "\n"))
			}
		})
	}
}
