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
	}{
		// 50 and 60 are its primaries, so each of their clears nulls both
		// (see TestDiffFlagsEveryPrimaryClearOfAVMWithBothFields); 70 is not a
		// primary and its clear touches neither.
		{50, true, true}, {60, true, true}, {70, false, false},
	} {
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
	if len(nb.primaryClears) != 1 || nb.primaryClears[0] != [3]int{11, 1, 0} {
		t.Fatalf("primary clears = %v, want VM 11's primary_ip4 only", nb.primaryClears)
	}
	if len(nb.cleared) != 1 || nb.cleared[0] != 50 {
		t.Fatalf("cleared = %v, want 50", nb.cleared)
	}
	if nb.order[0] != "primaries" || nb.order[1] != "clear" {
		t.Fatalf("order = %v, want the primary nulled before the clear", nb.order)
	}
}

// Two stale primaries on one VM — 50 its primary_ip4 on eth0, 60 its
// primary_ip6 on eth1 — are two clears, which the worker pool runs at once.
// NetBox saves a PATCHed VM as a whole row read at the start of the request, so
// two concurrent PATCHes each nulling one field can write the other field back.
// Every flagged clear of a VM therefore carries BOTH fields, and each one nulls
// both in a single PATCH: any interleaving then leaves both null.
func TestDiffFlagsEveryPrimaryClearOfAVMWithBothFields(t *testing.T) {
	const mac0, mac1 = "52:54:00:00:00:01", "52:54:00:00:00:02"
	d := DesiredVM{Name: "vm-1", UUID: "u1", NICs: []DesiredNIC{
		{Name: "eth0", MAC: mac0, NetBoxIPID: 9, NetBoxIP: "10.0.5.9"},
		{Name: "eth1", MAC: mac1, NetBoxIPID: 10, NetBoxIP: "10.0.5.10"},
	}}
	got := Diff([]DesiredVM{d}, Actual{
		VMs: map[string]netbox.VirtualMachine{
			vmIdent("u1"): {ID: 11, Name: "vm-1", Identity: vmIdent("u1"), PrimaryIP4ID: 50, PrimaryIP6ID: 60},
		},
		NICs: map[string]netbox.VMInterface{
			nicIdent("u1", mac0): {ID: 21, VMID: 11, Name: "eth0", MAC: mac0, Identity: nicIdent("u1", mac0)},
			nicIdent("u1", mac1): {ID: 22, VMID: 11, Name: "eth1", MAC: mac1, Identity: nicIdent("u1", mac1)},
		},
		OwnedIPsByIface: map[int][]netbox.IPAddress{
			21: {{ID: 9, AssignedObjectID: 21}, {ID: 50, AssignedObjectID: 21}},
			22: {{ID: 10, AssignedObjectID: 22}, {ID: 60, AssignedObjectID: 22}},
		},
	}, fp)
	for _, id := range []int{50, 60} {
		a, ok := staleClear(got, id)
		if !ok || !a.ClearsPrimary4 || !a.ClearsPrimary6 {
			t.Errorf("clear %d = %+v (present %v), want both primary fields flagged", id, a, ok)
		}
	}
}

func TestApplyClearNullsBothFlaggedPrimariesInOnePatch(t *testing.T) {
	nb := &stubVirt{}
	r := newTestReconciler(t, nb)
	if err := r.apply(context.Background(), []Action{
		{Kind: kindNIC, Op: "clear", Key: nicIdent("u1", "52:54:00:00:00:01"),
			NetBoxID: 21, ParentNetBoxID: 11, IPID: 50, ClearsPrimary4: true, ClearsPrimary6: true},
	}, indexDesired(nil, fp), fp); err != nil {
		t.Fatal(err)
	}
	if len(nb.primaryClears) != 1 || nb.primaryClears[0] != [3]int{11, 1, 1} {
		t.Fatalf("primary clears = %v, want ONE request nulling both of VM 11's primaries", nb.primaryClears)
	}
	if len(nb.primaryIPs)+len(nb.primaryIP6s) != 0 {
		t.Fatalf("separate per-field writes %v %v, want none", nb.primaryIPs, nb.primaryIP6s)
	}
}
