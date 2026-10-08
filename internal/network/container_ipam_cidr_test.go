package network

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

func cidrTestDB(t *testing.T) *corrosion.Client {
	t.Helper()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(context.Background(), db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	return db
}

// One address is one lease, whatever spelling the operator used. A static
// ip=172.16.77.50/24 and a later bare ip=172.16.77.50 name the same host
// address, so the second reserve must lose (the lab 6c alias), in either
// order, and the lease is keyed on the bare host address.
func TestReserveContainerIP_CIDRAndBareAreOneAddress(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct{ first, second string }{
		{"172.16.77.50/24", "172.16.77.50"},
		{"172.16.77.50", "172.16.77.50/24"},
		{"172.16.77.50/24", "172.16.77.50/16"},
	} {
		db := cidrTestDB(t)
		if ok, err := ReserveContainerIP(ctx, db, "lxtnet", tc.first, "mac-3", "node-3", "lxt3"); err != nil || !ok {
			t.Fatalf("%q: first reserve: ok=%v err=%v", tc.first, ok, err)
		}
		if ok, err := ReserveContainerIP(ctx, db, "lxtnet", tc.second, "mac-4", "node-3", "lxt4"); err != nil || ok {
			t.Fatalf("%q after %q: second reserve of the same host address must lose: ok=%v err=%v",
				tc.second, tc.first, ok, err)
		}
		al, _ := GetAllocationFor(ctx, db, "lxtnet", "ct", "node-3", "lxt3")
		if al == nil || al.IP != "172.16.77.50" {
			t.Fatalf("lease must be keyed on the bare host address, got %+v", al)
		}
		// The same owner re-reserving in the other spelling is still idempotent.
		if ok, err := ReserveContainerIP(ctx, db, "lxtnet", tc.second, "mac-3", "node-3", "lxt3"); err != nil || !ok {
			t.Fatalf("owner re-reserve in another spelling: ok=%v err=%v", ok, err)
		}
	}
}

// A lease written before normalisation still holds its address: rows keyed
// "172.16.77.50/24" exist on upgraded clusters and are compared normalised at
// read time, never backfilled.
func TestReserveContainerIP_LegacyCIDRRowStillHoldsItsAddress(t *testing.T) {
	ctx := context.Background()
	db := cidrTestDB(t)
	insertLegacyLease(t, db, "lxtnet", "172.16.77.50/24", "lxt3")

	if ok, err := ReserveContainerIP(ctx, db, "lxtnet", "172.16.77.50", "mac-4", "node-3", "lxt4"); err != nil || ok {
		t.Fatalf("bare reserve over a legacy CIDR lease must lose: ok=%v err=%v", ok, err)
	}
	// Its owner still reserves it (a restore or relocate of lxt3).
	if ok, err := ReserveContainerIP(ctx, db, "lxtnet", "172.16.77.50/24", "mac-3", "node-3", "lxt3"); err != nil || !ok {
		t.Fatalf("legacy owner re-reserve: ok=%v err=%v", ok, err)
	}
	ok, err := ContainerLeasesOwnedBy(ctx, db, "node-3", "lxt3", []corrosion.ContainerInterfaceRecord{
		{NetworkName: "lxtnet", IP: "172.16.77.50"},
	})
	if err != nil || !ok {
		t.Fatalf("legacy CIDR lease must count as held for its bare NIC address: ok=%v err=%v", ok, err)
	}
}

// Auto-allocation must skip an address held by a legacy CIDR-keyed lease.
func TestComputeCandidateIP_SkipsLegacyCIDRLease(t *testing.T) {
	ctx := context.Background()
	db := cidrTestDB(t)
	insertLegacyLease(t, db, "lxtnet", "172.16.77.2/24", "lxt3")
	ip, err := ComputeCandidateIP(ctx, db, "lxtnet", "172.16.77.0/24")
	if err != nil {
		t.Fatalf("ComputeCandidateIP: %v", err)
	}
	if ip != "172.16.77.3" {
		t.Fatalf("candidate %s aliases the legacy lease 172.16.77.2/24; want 172.16.77.3", ip)
	}
}

// A NIC row whose IP carries a prefix is held by the bare lease written for it.
func TestContainerLeasesOwnedBy_CIDRNICAddress(t *testing.T) {
	ctx := context.Background()
	db := cidrTestDB(t)
	if ok, err := ReserveContainerIP(ctx, db, "lxtnet", "172.16.77.50/24", "mac-3", "node-3", "lxt3"); err != nil || !ok {
		t.Fatalf("reserve: ok=%v err=%v", ok, err)
	}
	ok, err := ContainerLeasesOwnedBy(ctx, db, "node-3", "lxt3", []corrosion.ContainerInterfaceRecord{
		{NetworkName: "lxtnet", IP: "172.16.77.50/24"},
	})
	if err != nil || !ok {
		t.Fatalf("CIDR NIC address must match its bare lease: ok=%v err=%v", ok, err)
	}
}

func insertLegacyLease(t *testing.T, db *corrosion.Client, netName, ip, owner string) {
	t.Helper()
	if err := db.Execute(context.Background(),
		`INSERT INTO ip_allocations (network, ip, mac, vm_name, owner_kind, owner_host, allocated_at, updated_at)
		 VALUES (?, ?, 'mac-legacy', ?, 'ct', 'node-3', '2026-10-01T00:00:00Z', ?)`,
		netName, ip, owner, db.NowTS()); err != nil {
		t.Fatalf("insert legacy lease: %v", err)
	}
}
