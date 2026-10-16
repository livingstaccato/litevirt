package firewall

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
)

func dupEvents(t *testing.T, db *corrosion.Client, vm string) int {
	t.Helper()
	evs, err := corrosion.ListVMEvents(context.Background(), db, vm, 100, "")
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range evs {
		if e.Type == "network.duplicate_address" {
			n++
		}
	}
	return n
}

// Review I-1(a): a duplicate address on a host-isolated network is made
// visible — an event on each of this host's VMs that hold it, once while it
// lasts, again if it comes back; another host's VMs are that host's to
// report.
//
// Mutation: drop the seen check — the second pass records a second event;
// drop the host filter — the remote VM gets an event from this host; never
// clear seen — the duplicate that comes back is not reported.
func TestDuplicateAddressReporter(t *testing.T) {
	ctx := context.Background()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	r := NewDuplicateAddressReporter(db, "n1")
	dup := []corrosion.DuplicateAddress{{Network: "hi", IP: "10.9.0.5",
		Owners: []corrosion.NICOwner{{Kind: "vm", Name: "a", Host: "n1"}, {Kind: "vm", Name: "b", Host: "n2"}}}}

	r.Report(ctx, dup)
	r.Report(ctx, dup)
	if n := dupEvents(t, db, "a"); n != 1 {
		t.Errorf("local VM a: %d events over two passes, want 1", n)
	}
	if n := dupEvents(t, db, "b"); n != 0 {
		t.Errorf("remote VM b: %d events from this host, want 0", n)
	}
	r.Report(ctx, nil)
	r.Report(ctx, dup)
	if n := dupEvents(t, db, "a"); n != 2 {
		t.Errorf("a duplicate that cleared and came back: %d events, want 2", n)
	}
}

// The firewall pass hands the duplicates to OnDuplicateAddresses.
//
// Mutation: drop the hook call from CorrosionPlanLoader — red.
func TestPlanLoader_ReportsDuplicateAddresses(t *testing.T) {
	ctx := context.Background()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	cfg, _ := json.Marshal(compose.NetworkDef{Type: "bridge", Subnet: "10.9.0.0/24", HostIsolation: true})
	if err := corrosion.UpsertNetwork(ctx, db, corrosion.NetworkRecord{Name: "hi", Type: "bridge", Config: string(cfg)}); err != nil {
		t.Fatal(err)
	}
	for _, v := range []struct{ name, mac string }{{"a", "52:54:00:00:00:01"}, {"b", "52:54:00:00:00:02"}} {
		if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{Name: v.name, HostName: "host-a", Spec: "{}", State: "stopped"},
			[]corrosion.InterfaceRecord{{VMName: v.name, NetworkName: "hi", MAC: v.mac, IP: "10.9.0.5"}}, nil); err != nil {
			t.Fatal(err)
		}
	}
	var got []corrosion.DuplicateAddress
	if _, err := CorrosionPlanLoader(db, "host-a", Plan{}, LoaderOptions{
		OnDuplicateAddresses: func(_ context.Context, d []corrosion.DuplicateAddress) { got = d },
	})(ctx); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].IP != "10.9.0.5" || len(got[0].Owners) != 2 {
		t.Errorf("duplicates handed to the hook: %+v", got)
	}
}
