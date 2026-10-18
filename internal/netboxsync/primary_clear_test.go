package netboxsync

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/netbox"
)

// NetBox refuses to detach an address that is its VM's primary_ip4 or
// primary_ip6 (IPAddress.clean). A stale owned address the mirror clears in
// phase 2 can still be the primary — the primary phase that would move it runs
// three phases later — so the clear has to null that primary first, or the
// pass aborts in phase 2 on every sweep.

func staleClear(actions []Action, ipID int) (Action, bool) {
	for _, a := range actions {
		if a.Kind == kindNIC && a.Op == "clear" && a.IPID == ipID {
			return a, true
		}
	}
	return Action{}, false
}

func TestDiffMarksAClearOfTheVMsPrimary(t *testing.T) {
	const mac = "52:54:00:00:00:01"
	d := DesiredVM{Name: "vm-1", UUID: "u1", NICs: []DesiredNIC{
		{Name: "eth0", MAC: mac, NetBoxIPID: 9, NetBoxIP: "10.0.5.9"},
	}}
	owned := netbox.IPAddress{AssignedObjectID: 21, Identity: nicIdent("u1", mac)}
	a4, a6, other := owned, owned, owned
	a4.ID, a6.ID, other.ID = 50, 60, 70
	got := Diff([]DesiredVM{d}, Actual{
		VMs: map[string]netbox.VirtualMachine{
			vmIdent("u1"): {ID: 11, Name: "vm-1", Identity: vmIdent("u1"), PrimaryIP4ID: 50, PrimaryIP6ID: 60},
		},
		NICs: map[string]netbox.VMInterface{
			nicIdent("u1", mac): {ID: 21, VMID: 11, Name: "eth0", MAC: mac, Identity: nicIdent("u1", mac)},
		},
		OwnedIPsByIface: map[int][]netbox.IPAddress{21: {{ID: 9, AssignedObjectID: 21}, a4, a6, other}},
	}, fp)
	for _, c := range []struct {
		id     int
		p4, p6 bool
	}{{50, true, false}, {60, false, true}, {70, false, false}} {
		a, ok := staleClear(got, c.id)
		if !ok {
			t.Fatalf("no clear for stale address %d in %+v", c.id, got)
		}
		if a.ClearsPrimary4 != c.p4 || a.ClearsPrimary6 != c.p6 {
			t.Errorf("clear %d: ClearsPrimary4=%v ClearsPrimary6=%v, want %v/%v",
				c.id, a.ClearsPrimary4, a.ClearsPrimary6, c.p4, c.p6)
		}
	}
}

func TestApplyClearNullsThePrimaryFirst(t *testing.T) {
	nb := &stubVirt{}
	r := newTestReconciler(t, nb)
	if err := r.apply(context.Background(), []Action{
		{Kind: kindNIC, Op: "clear", Key: nicIdent("u1", "52:54:00:00:00:01"),
			NetBoxID: 21, ParentNetBoxID: 11, IPID: 50, ClearsPrimary4: true},
	}, indexDesired(nil, fp), fp); err != nil {
		t.Fatal(err)
	}
	if len(nb.primaryIPs) != 1 || nb.primaryIPs[0] != [2]int{11, 0} {
		t.Fatalf("primary_ip4 writes = %v, want VM 11 nulled", nb.primaryIPs)
	}
	if len(nb.primaryIP6s) != 0 {
		t.Fatalf("primary_ip6 touched: %v", nb.primaryIP6s)
	}
	if len(nb.cleared) != 1 || nb.cleared[0] != 50 {
		t.Fatalf("cleared = %v, want 50", nb.cleared)
	}
	if nb.order[0] != "primary4" || nb.order[1] != "clear" {
		t.Fatalf("order = %v, want the primary nulled before the clear", nb.order)
	}
}
