// A stale owned address that is still the VM's primary.
//
// The mirror clears every litevirt-owned address on a NIC that is not that
// NIC's lease, in phase 2. NetBox refuses to detach an address while it is its
// VM's primary_ip4 or primary_ip6, and the primary phase that would move the
// primary runs three phases later — so without nulling the primary first the
// clear is refused and the whole pass aborts, on every sweep.

package fleet

import (
	"context"
	"testing"
	"time"
)

// staleOwnedPrimary plants an address carrying vm-1 eth0's own identity — so
// the mirror owns it — attaches it to eth0, records a released lease for it
// (the evidence a clear needs), and makes it the VM's primary of its family.
func staleOwnedPrimary(t *testing.T, nb *NetBoxFake, n *Node, address string, six bool) int {
	t.Helper()
	ids := nb.InterfaceIdentities()
	if len(ids) != 1 {
		t.Fatalf("precondition: want vm-1's one interface, have %v", ids)
	}
	id := nb.SeedIP(address, orphanVRF, ids[0], time.Now().Add(-time.Hour))
	nb.AssignDirect(id, nb.InterfaceID("vm-1", "eth0"))
	host := address[:len(address)-3]
	if err := n.DB.Execute(context.Background(),
		`INSERT INTO ip_allocations
		   (network, ip, mac, vm_name, owner_kind, owner_host,
		    netbox_ip_id, netbox_prefix_id, allocated_at, updated_at, deleted_at)
		 VALUES (?, ?, '52:54:00:ff:ff:ff', 'vm-1', 'vm', '', ?, ?, ?, ?, ?)`,
		orphanNetwork, host, id, orphanPrefixID, n.DB.NowWall(), n.DB.NowTS(), n.DB.NowWall()); err != nil {
		t.Fatalf("seed the released lease: %v", err)
	}
	set := nb.SetVMPrimaryIP4Direct
	if six {
		set = nb.SetVMPrimaryIP6Direct
	}
	if err := set("vm-1", id); err != nil {
		t.Fatalf("precondition: make %d the primary: %v", id, err)
	}
	return id
}

func TestMirrorClearsAStaleOwnedPrimaryIP4(t *testing.T) {
	nb, c := boundMirrorCluster(t, 1)
	n := c.Nodes[0]
	mustCreateVM(t, n, "vm-1", orphanNetwork)
	mustSyncAllNodes(t, c)
	leased := nb.InterfaceAddressID("vm-1", "eth0")

	stale := staleOwnedPrimary(t, nb, n, "10.0.5.201/24", false)
	mustSyncAllNodes(t, c)

	if assigned, exists := nb.Address(stale); !exists || assigned != 0 {
		t.Fatalf("stale address %d: exists=%v assigned=%d, want kept and detached", stale, exists, assigned)
	}
	if got := nb.VMPrimaryIP4("vm-1"); got != leased {
		t.Fatalf("primary_ip4 = %d, want the leased %d", got, leased)
	}
}

func TestMirrorClearsAStaleOwnedPrimaryIP6(t *testing.T) {
	nb, c := boundMirrorCluster(t, 1)
	n := c.Nodes[0]
	mustCreateVM(t, n, "vm-1", orphanNetwork)
	mustSyncAllNodes(t, c)

	stale := staleOwnedPrimary(t, nb, n, "2001:db8::60/64", true)
	mustSyncAllNodes(t, c)

	if assigned, exists := nb.Address(stale); !exists || assigned != 0 {
		t.Fatalf("stale address %d: exists=%v assigned=%d, want kept and detached", stale, exists, assigned)
	}
	if got := nb.VMPrimaryIP6("vm-1"); got != 0 {
		t.Fatalf("primary_ip6 = %d, want cleared with the address it named", got)
	}
}
