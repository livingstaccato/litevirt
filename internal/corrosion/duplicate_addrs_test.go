package corrosion

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/litevirt/litevirt/internal/compose"
)

// HostIsolatedDuplicateAddrs finds an address that live NIC rows of two
// workloads hold on a host-isolated network — VM against VM across hosts,
// VM against container — counts a VM whose NIC both VM tables hold once, and leaves
// other networks (where a stale lease row would be a false alarm) alone.
//
// Mutation: drop the isolated filter — the DHCP network's pair is reported;
// accept any host-isolation network — the subnet-less one's pair is.
func TestHostIsolatedDuplicateAddrs(t *testing.T) {
	ctx := context.Background()
	c := NewTestClientT(t)
	if err := InitSchema(ctx, c); err != nil {
		t.Fatal(err)
	}
	for name, def := range map[string]compose.NetworkDef{
		"hi": {Type: "vxlan", Subnet: "10.9.0.0/24", HostIsolation: true},
		"br": {Type: "bridge", Subnet: "10.8.0.0/24", DHCP: true},
		// Host-isolated with no subnet: the scanner records what guests
		// lease from an external server there (re-review R1-m3).
		"hx": {Type: "bridge", HostIsolation: true},
	} {
		cfg, _ := json.Marshal(def)
		if err := UpsertNetwork(ctx, c, NetworkRecord{Name: name, Type: def.Type, Config: string(cfg)}); err != nil {
			t.Fatal(err)
		}
	}
	vm := func(name, host, mac, net, ip string) {
		t.Helper()
		if err := InsertVM(ctx, c, VMRecord{Name: name, HostName: host, Spec: "{}", State: "running"},
			[]InterfaceRecord{{VMName: name, NetworkName: net, MAC: mac, IP: ip}}, nil); err != nil {
			t.Fatal(err)
		}
		if err := UpsertNIC(ctx, c, NICRecord{VMName: name, ID: DeterministicNICID(name, mac), NetworkName: net, MAC: mac, IP: ip}); err != nil {
			t.Fatal(err)
		}
	}
	vm("a", "n1", "52:54:00:00:00:01", "hi", "10.9.0.5")
	vm("b", "n2", "52:54:00:00:00:02", "hi", "10.9.0.5/24")
	vm("c", "n1", "52:54:00:00:00:03", "hi", "10.9.0.6")
	vm("d", "n1", "52:54:00:00:00:04", "br", "10.8.0.7")
	vm("e", "n2", "52:54:00:00:00:05", "br", "10.8.0.7")
	vm("f", "n1", "52:54:00:00:00:07", "hx", "192.168.1.9")
	vm("g", "n2", "52:54:00:00:00:08", "hx", "192.168.1.9")
	if err := UpsertContainerInterface(ctx, c, ContainerInterfaceRecord{HostName: "n2", CtName: "ct", NetworkName: "hi",
		MAC: "52:54:00:00:00:06", IP: "10.9.0.6"}); err != nil {
		t.Fatal(err)
	}
	got, err := HostIsolatedDuplicateAddrs(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	want := []DuplicateAddress{
		{Network: "hi", IP: "10.9.0.5", Owners: []NICOwner{{"vm", "a", "n1"}, {"vm", "b", "n2"}}},
		{Network: "hi", IP: "10.9.0.6", Owners: []NICOwner{{"ct", "ct", "n2"}, {"vm", "c", "n1"}}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("duplicates =\n%+v\nwant\n%+v", got, want)
	}
}
