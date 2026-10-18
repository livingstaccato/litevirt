package netboxsync

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/netbox"
)

// A VM's primary address is chosen PER FAMILY. NetBox keeps primary_ip4 and
// primary_ip6 apart and refuses an address of the wrong family in either, so a
// mirror that took "the first NIC's address" whatever its family sent an IPv6
// address as primary_ip4 for any VM whose first NIC sat on an IPv6 network, and
// NetBox then refused every sweep.

func primaryActions(actions []Action) map[string]Action {
	out := map[string]Action{}
	for _, a := range actions {
		if a.Kind == kindVM && (a.Op == opPrimaryIP || a.Op == opPrimaryIP6) {
			out[a.Op] = a
		}
	}
	return out
}

func dualStackVM() (DesiredVM, netbox.VirtualMachine) {
	d := DesiredVM{Name: "vm-1", UUID: "u1", NICs: []DesiredNIC{
		// eth0 is the IPv6 one: the case that used to be sent as primary_ip4.
		{Name: "eth0", MAC: "52:54:00:00:00:01", NetBoxIPID: 7, NetBoxIP: "2001:db8::5"},
		{Name: "eth1", MAC: "52:54:00:00:00:02", NetBoxIPID: 9, NetBoxIP: "10.0.5.9"},
	}}
	return d, netbox.VirtualMachine{ID: 11, Name: "vm-1", Identity: vmIdent("u1")}
}

func TestDiffPicksEachPrimaryByAddressFamily(t *testing.T) {
	d, a := dualStackVM()
	got := primaryActions(Diff([]DesiredVM{d}, Actual{
		VMs: map[string]netbox.VirtualMachine{vmIdent("u1"): a},
	}, fp))
	if v4 := got[opPrimaryIP]; v4.IPID != 9 {
		t.Errorf("primary_ip4 action = %+v, want address 9 (the IPv4 one on eth1), never "+
			"the IPv6 address on eth0", v4)
	}
	if v6, ok := got[opPrimaryIP6]; !ok || v6.IPID != 7 {
		t.Errorf("primary_ip6 action = %+v (present %v), want address 7", v6, ok)
	}
}

func TestDiffNeverSendsAnIPv6AddressAsPrimaryIPv4(t *testing.T) {
	d := DesiredVM{Name: "vm-1", UUID: "u1", NICs: []DesiredNIC{
		{Name: "eth0", MAC: "52:54:00:00:00:01", NetBoxIPID: 7, NetBoxIP: "2001:db8::5"},
	}}
	got := primaryActions(Diff([]DesiredVM{d}, Actual{
		VMs: map[string]netbox.VirtualMachine{
			vmIdent("u1"): {ID: 11, Name: "vm-1", Identity: vmIdent("u1")},
		},
	}, fp))
	if v4, ok := got[opPrimaryIP]; ok {
		t.Errorf("an IPv6-only VM got a primary_ip4 action %+v; its primary_ip4 is already none", v4)
	}
	if v6 := got[opPrimaryIP6]; v6.IPID != 7 {
		t.Errorf("primary_ip6 action = %+v, want address 7", v6)
	}
}

func TestDiffConvergedDualStackPrimariesWriteNothing(t *testing.T) {
	d, a := dualStackVM()
	a.PrimaryIP4ID, a.PrimaryIP6ID = 9, 7
	if got := primaryActions(Diff([]DesiredVM{d}, Actual{
		VMs: map[string]netbox.VirtualMachine{vmIdent("u1"): a},
	}, fp)); len(got) != 0 {
		t.Fatalf("a converged dual-stack VM emitted %+v", got)
	}
}

func TestDiffClearsAPrimaryOfTheWrongFamily(t *testing.T) {
	// What the old mirror managed to write wherever NetBox did not refuse it:
	// primary_ip4 pointing at the IPv6 object. It converges back.
	d, a := dualStackVM()
	a.PrimaryIP4ID, a.PrimaryIP6ID = 7, 0
	got := primaryActions(Diff([]DesiredVM{d}, Actual{
		VMs: map[string]netbox.VirtualMachine{vmIdent("u1"): a},
	}, fp))
	if got[opPrimaryIP].IPID != 9 || got[opPrimaryIP6].IPID != 7 {
		t.Fatalf("got %+v, want primary_ip4 -> 9 and primary_ip6 -> 7", got)
	}
}

func TestDiffNeverMakesAnAddressOfUnknownFamilyPrimary(t *testing.T) {
	d := DesiredVM{Name: "vm-1", UUID: "u1", NICs: []DesiredNIC{
		{Name: "eth0", MAC: "52:54:00:00:00:01", NetBoxIPID: 7, NetBoxIP: ""},
		{Name: "eth1", MAC: "52:54:00:00:00:02", NetBoxIPID: 8, NetBoxIP: "not-an-ip"},
	}}
	if got := primaryActions(Diff([]DesiredVM{d}, Actual{
		VMs: map[string]netbox.VirtualMachine{
			vmIdent("u1"): {ID: 11, Name: "vm-1", Identity: vmIdent("u1")},
		},
	}, fp)); len(got) != 0 {
		t.Fatalf("an address whose family is unknown was made primary: %+v", got)
	}
}

func TestPrimaryIP6RunsInThePrimaryPhase(t *testing.T) {
	if p := Phase(Action{Kind: kindVM, Op: opPrimaryIP6}); p != PhaseVMPrimaryIP {
		t.Fatalf("vm/%s is in phase %d, want %d (after both interface phases)",
			opPrimaryIP6, p, PhaseVMPrimaryIP)
	}
}

func TestApplyPrimaryIP6SetsPrimaryIP6(t *testing.T) {
	nb := &stubVirt{}
	r := newTestReconciler(t, nb)
	if err := r.apply(context.Background(),
		[]Action{{Kind: kindVM, Op: opPrimaryIP6, Key: vmIdent("u1"), ParentNetBoxID: 11, IPID: 7}},
		indexDesired(nil, fp), fp); err != nil {
		t.Fatal(err)
	}
	if len(nb.primaryIP6s) != 1 || nb.primaryIP6s[0] != [2]int{11, 7} {
		t.Fatalf("SetPrimaryIP6 calls = %v, want [[11 7]]", nb.primaryIP6s)
	}
	if len(nb.primaryIPs) != 0 {
		t.Fatalf("a primary_ip6 action wrote primary_ip4: %v", nb.primaryIPs)
	}
}

func TestDesiredNICsCarryTheLeasedAddress(t *testing.T) {
	// The family is the LEASE's, not vm_interfaces.ip's: the lease is what names
	// the NetBox object, and the NIC row's address can disagree with it.
	leases := []corrosion.LeaseRecord{{
		Network: "bound", IP: "2001:db8::5", MAC: "52:54:00:00:00:01", NetBoxIPID: 7,
	}}
	byLease, _ := indexLeases(leases)
	nics, _ := desiredNICs([]corrosion.NICRecord{{
		VMName: "vm-1", MAC: "52:54:00:00:00:01", NetworkName: "bound", IP: "10.9.9.9",
	}}, byLease)
	if len(nics) != 1 || nics[0].NetBoxIPID != 7 || nics[0].NetBoxIP != "2001:db8::5" {
		t.Fatalf("desired NICs = %+v, want address 7 carrying the leased 2001:db8::5", nics)
	}
}

func TestDiffNeverClearsAnOperatorsPrimaryIP6WithoutALeasedIPv6(t *testing.T) {
	// The mirror manages primary_ip6 only for a VM holding a leased IPv6
	// address. An operator who set one by hand on an IPv4-only VM keeps it.
	d := DesiredVM{Name: "vm-1", UUID: "u1", NICs: []DesiredNIC{
		{Name: "eth0", MAC: "52:54:00:00:00:01", NetBoxIPID: 9, NetBoxIP: "10.0.5.9"},
	}}
	got := primaryActions(Diff([]DesiredVM{d}, Actual{
		VMs: map[string]netbox.VirtualMachine{
			vmIdent("u1"): {ID: 11, Name: "vm-1", Identity: vmIdent("u1"), PrimaryIP4ID: 9, PrimaryIP6ID: 55},
		},
	}, fp))
	if v6, ok := got[opPrimaryIP6]; ok {
		t.Fatalf("the mirror rewrote an operator's primary_ip6 on a VM with no leased IPv6: %+v", v6)
	}
}

func TestDiffClearsAPrimaryIP6ThisClusterOwnsOnceItsLeaseIsGone(t *testing.T) {
	// The mirror set primary_ip6 = 60 while the VM held an IPv6 lease. The
	// lease is gone, but address 60 — carrying this cluster's identity — is
	// still on the VM's interface. Leaving the primary naming it would have
	// NetBox refuse every later write of the VM once 60 is detached.
	const mac = "52:54:00:00:00:01"
	d := DesiredVM{Name: "vm-1", UUID: "u1", NICs: []DesiredNIC{
		{Name: "eth0", MAC: mac, NetBoxIPID: 9, NetBoxIP: "10.0.5.9"},
	}}
	got := primaryActions(Diff([]DesiredVM{d}, Actual{
		VMs: map[string]netbox.VirtualMachine{
			vmIdent("u1"): {ID: 11, Name: "vm-1", Identity: vmIdent("u1"), PrimaryIP4ID: 9, PrimaryIP6ID: 60},
		},
		NICs: map[string]netbox.VMInterface{
			nicIdent("u1", mac): {ID: 21, VMID: 11, Name: "eth0", MAC: mac, Identity: nicIdent("u1", mac)},
		},
		OwnedIPsByIface: map[int][]netbox.IPAddress{
			21: {{ID: 9, AssignedObjectID: 21, Identity: nicIdent("u1", mac)},
				{ID: 60, AssignedObjectID: 21, Identity: nicIdent("u1", mac)}},
		},
	}, fp))
	if v6, ok := got[opPrimaryIP6]; !ok || v6.IPID != 0 {
		t.Fatalf("primary_ip6 action = %+v (present %v), want a clear of the owned address 60", v6, ok)
	}
}
