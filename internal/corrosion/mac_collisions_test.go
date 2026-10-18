package corrosion

import (
	"context"
	"testing"
)

func seedMACVM(t *testing.T, c *Client, name, host, network, mac string) {
	t.Helper()
	ctx := context.Background()
	if err := InsertVM(ctx, c, VMRecord{Name: name, HostName: host, State: "running"},
		[]InterfaceRecord{{VMName: name, NetworkName: network, MAC: mac}}, nil); err != nil {
		t.Fatalf("InsertVM %s: %v", name, err)
	}
	if err := UpsertNIC(ctx, c, NICRecord{VMName: name, ID: DeterministicNICID(name, mac), NetworkName: network, MAC: mac}); err != nil {
		t.Fatalf("UpsertNIC %s: %v", name, err)
	}
}

func TestListMACCollisions(t *testing.T) {
	ctx := context.Background()
	c := NewTestClientT(t)
	if err := InitSchema(ctx, c); err != nil {
		t.Fatal(err)
	}
	const dup, own, ctDup = "52:54:00:aa:bb:01", "52:54:00:aa:bb:02", "52:54:00:aa:bb:03"

	// One VM's NIC, on both tables: not a collision.
	seedMACVM(t, c, "solo", "h1", "lan", own)
	if cols, err := ListMACCollisions(ctx, c); err != nil || len(cols) != 0 {
		t.Fatalf("one VM's dual-written NIC: got %v, %v; want none", cols, err)
	}

	// Two VMs on two hosts, one MAC (upper case on one side): a collision
	// naming both.
	seedMACVM(t, c, "a", "h1", "lan", dup)
	seedMACVM(t, c, "b", "h2", "lan", "52:54:00:AA:BB:01")
	cols, err := ListMACCollisions(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	if len(cols) != 1 || cols[0].MAC != dup || len(cols[0].Holders) != 2 ||
		cols[0].Holders[0].Name != "a" || cols[0].Holders[0].Host != "h1" ||
		cols[0].Holders[1].Name != "b" || cols[0].Holders[1].Host != "h2" {
		t.Fatalf("two VMs on one MAC: got %+v", cols)
	}

	// A container's NIC on a VM's MAC.
	seedMACVM(t, c, "v", "h1", "lan", ctDup)
	if err := UpsertContainer(ctx, c, ContainerRecord{HostName: "h3", Name: "ct1", State: "running"}); err != nil {
		t.Fatal(err)
	}
	if err := UpsertContainerInterface(ctx, c, ContainerInterfaceRecord{HostName: "h3", CtName: "ct1", NetworkName: "lan", MAC: ctDup}); err != nil {
		t.Fatal(err)
	}
	cols, err = ListMACCollisions(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	if len(cols) != 2 || cols[1].MAC != ctDup || cols[1].Holders[0].Owner != ContainerGuardOwner("h3", "ct1") ||
		cols[1].Holders[0].Kind != "ct" || cols[1].Holders[1].Name != "v" {
		t.Fatalf("a container and a VM on one MAC: got %+v", cols)
	}

	// b's NIC detached on a latched cluster: only vm_nics is tombstoned, the
	// legacy row stays live. The overlay says b holds no such NIC.
	if err := TombstoneNIC(ctx, c, "b", DeterministicNICID("b", "52:54:00:AA:BB:01")); err != nil {
		t.Fatal(err)
	}
	cols, err = ListMACCollisions(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	if len(cols) != 1 || cols[0].MAC != ctDup {
		t.Fatalf("after b's NIC is detached: got %+v; want only the container collision", cols)
	}

	// A deleted VM holds nothing.
	if err := DeleteVM(ctx, c, "v"); err != nil {
		t.Fatal(err)
	}
	if cols, err := ListMACCollisions(ctx, c); err != nil || len(cols) != 0 {
		t.Fatalf("after v is deleted: got %+v, %v; want none", cols, err)
	}
}
