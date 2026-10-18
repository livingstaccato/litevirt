// Deleting a NetBox interface deletes the addresses assigned to it.
//
// A vminterface carries its addresses through a generic relation, and NetBox
// cascades that relation on delete — so an interface the mirror removes takes
// every address on it along, not merely its assignment. The mirror detaches
// them first. These scenarios plant an OPERATOR's address on a mirrored
// interface, which no litevirt release path will ever delete, and require it
// to survive each way the mirror removes an interface.

package fleet

import (
	"testing"
	"time"
)

// operatorAddressOn seeds an address with no litevirt identity and attaches it
// to the named interface, as an operator editing NetBox by hand would.
func operatorAddressOn(t *testing.T, nb *NetBoxFake, vmName, ifaceName, address string) int {
	t.Helper()
	iface := nb.InterfaceID(vmName, ifaceName)
	if iface == 0 {
		t.Fatalf("precondition: %s has no mirrored %s", vmName, ifaceName)
	}
	id := nb.SeedIP(address, orphanVRF, "", time.Now().Add(-time.Hour))
	nb.AssignDirect(id, iface)
	return id
}

func requireAddressSurvivesUnassigned(t *testing.T, nb *NetBoxFake, id int, what string) {
	t.Helper()
	assigned, exists := nb.Address(id)
	if !exists {
		t.Fatalf("the operator's address %d was destroyed when %s; NetBox cascades an "+
			"interface delete to its addresses, so the mirror must detach them first "+
			"(cascaded: %v)", id, what, nb.Cascaded())
	}
	if assigned != 0 {
		t.Fatalf("the operator's address %d is still assigned to %d after %s", id, assigned, what)
	}
}

// TestMirrorNICDeleteKeepsTheAddressesOnIt: a hotplug detach makes the mirror
// delete that interface.
func TestMirrorNICDeleteKeepsTheAddressesOnIt(t *testing.T) {
	nb, c, gates := boundMirrorClusterGated(t, 1)
	latchOperationProtocol(t, c, gates)
	n := c.Nodes[0]

	mustCreateVM(t, n, "vm-1", orphanNetwork)
	mustSyncAllNodes(t, c)
	id := operatorAddressOn(t, nb, "vm-1", "eth0", "192.0.2.50/32")

	mustDetachNIC(t, c, n, "vm-1", nb.InterfaceMAC("vm-1", "eth0"))
	mustSyncAllNodes(t, c)

	if nb.InterfaceID("vm-1", "eth0") != 0 {
		t.Fatal("precondition: the mirror did not delete the detached interface")
	}
	requireAddressSurvivesUnassigned(t, nb, id, "the NIC was detached")
}

// TestMirrorVMDeleteKeepsTheAddressesOnIt: deleting the VM makes the mirror
// remove its interfaces and then the VM itself.
func TestMirrorVMDeleteKeepsTheAddressesOnIt(t *testing.T) {
	nb, c := boundMirrorCluster(t, 1)
	n := c.Nodes[0]

	mustCreateVM(t, n, "vm-1", orphanNetwork)
	mustSyncAllNodes(t, c)
	id := operatorAddressOn(t, nb, "vm-1", "eth0", "192.0.2.51/32")

	mustDeleteVM(t, n, "vm-1")
	mustSyncAllNodes(t, c)

	if nb.VMCount("vm-1") != 0 {
		t.Fatal("precondition: the mirror did not delete the VM")
	}
	requireAddressSurvivesUnassigned(t, nb, id, "the VM was deleted")
}

// TestMirrorReplaceKeepsTheAddressesOnIt: a superseded same-name incarnation is
// removed with ONE VM delete and no interface deletes of its own, so the VM
// delete is the only place its addresses can be detached.
func TestMirrorReplaceKeepsTheAddressesOnIt(t *testing.T) {
	nb, c := boundMirrorCluster(t, 1)
	n := c.Nodes[0]

	mustCreateVM(t, n, "vm-1", orphanNetwork)
	mustSyncAllNodes(t, c)
	id := operatorAddressOn(t, nb, "vm-1", "eth0", "192.0.2.52/32")

	mustDeleteVM(t, n, "vm-1")
	mustCreateVM(t, n, "vm-1", orphanNetwork)
	for i := 0; i < 3; i++ {
		if err := n.SyncNetBoxMirror(); err != nil {
			t.Fatalf("mirror pass %d: %v", i, err)
		}
	}

	if got := nb.VMCount("vm-1"); got != 1 {
		t.Fatalf("precondition: virtual_machine objects named vm-1 = %d, want 1", got)
	}
	requireAddressSurvivesUnassigned(t, nb, id, "the superseded incarnation was replaced")
}

// operatorPrimaryIP6On plants an operator's IPv6 address on the interface and
// makes it the VM's primary_ip6 by hand — a value the mirror keeps, since the
// VM holds no leased IPv6. NetBox refuses to detach a primary, so a delete
// that does not clear it first is refused on every sweep.
func operatorPrimaryIP6On(t *testing.T, nb *NetBoxFake, vmName, ifaceName, address string) int {
	t.Helper()
	id := operatorAddressOn(t, nb, vmName, ifaceName, address)
	if err := nb.SetVMPrimaryIP6Direct(vmName, id); err != nil {
		t.Fatalf("precondition: hand-set primary_ip6: %v", err)
	}
	return id
}

// TestMirrorNICDeleteDetachesAPrimaryAddress: the detached NIC carries the
// VM's primary_ip6.
func TestMirrorNICDeleteDetachesAPrimaryAddress(t *testing.T) {
	nb, c, gates := boundMirrorClusterGated(t, 1)
	latchOperationProtocol(t, c, gates)
	n := c.Nodes[0]

	mustCreateVM(t, n, "vm-1", orphanNetwork)
	mustSyncAllNodes(t, c)
	id := operatorPrimaryIP6On(t, nb, "vm-1", "eth0", "2001:db8::50/64")
	mustSyncAllNodes(t, c) // the mirror keeps a hand-set primary_ip6

	mustDetachNIC(t, c, n, "vm-1", nb.InterfaceMAC("vm-1", "eth0"))
	mustSyncAllNodes(t, c)

	if nb.InterfaceID("vm-1", "eth0") != 0 {
		t.Fatal("the detached interface is still in NetBox")
	}
	requireAddressSurvivesUnassigned(t, nb, id, "the NIC holding the primary was detached")
}

// TestMirrorVMDeleteDetachesAPrimaryAddress: the deleted VM's primary_ip6 is an
// address on its interface.
func TestMirrorVMDeleteDetachesAPrimaryAddress(t *testing.T) {
	nb, c := boundMirrorCluster(t, 1)
	n := c.Nodes[0]

	mustCreateVM(t, n, "vm-1", orphanNetwork)
	mustSyncAllNodes(t, c)
	id := operatorPrimaryIP6On(t, nb, "vm-1", "eth0", "2001:db8::51/64")
	mustSyncAllNodes(t, c)

	mustDeleteVM(t, n, "vm-1")
	mustSyncAllNodes(t, c)

	if nb.VMCount("vm-1") != 0 {
		t.Fatal("the deleted VM is still in NetBox")
	}
	requireAddressSurvivesUnassigned(t, nb, id, "the VM holding it as primary was deleted")
}

// TestMirrorReplaceDetachesAPrimaryAddress: a superseded incarnation goes with
// one VM delete and no interface deletes, so DeleteVM itself must clear the
// primary before it detaches.
func TestMirrorReplaceDetachesAPrimaryAddress(t *testing.T) {
	nb, c := boundMirrorCluster(t, 1)
	n := c.Nodes[0]

	mustCreateVM(t, n, "vm-1", orphanNetwork)
	mustSyncAllNodes(t, c)
	id := operatorPrimaryIP6On(t, nb, "vm-1", "eth0", "2001:db8::52/64")

	mustDeleteVM(t, n, "vm-1")
	mustCreateVM(t, n, "vm-1", orphanNetwork)
	for i := 0; i < 3; i++ {
		if err := n.SyncNetBoxMirror(); err != nil {
			t.Fatalf("mirror pass %d: %v", i, err)
		}
	}
	if got := nb.VMCount("vm-1"); got != 1 {
		t.Fatalf("virtual_machine objects named vm-1 = %d, want 1", got)
	}
	requireAddressSurvivesUnassigned(t, nb, id, "the superseded incarnation holding it as primary was replaced")
}
