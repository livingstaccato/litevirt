package netboxsync

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/netbox"
)

// TestAProvenClearNeverNullsAPrimaryWhoseOwnClearWasWithheld: vm-1's
// primary_ip4 names 50 and its primary_ip6 names 60, both stale owned
// addresses on eth0. 60's lease was released here, so its clear is proven;
// 50 has no local record at all, so its clear is withheld as unproven. The
// per-VM union of primary flags must be taken over what the evidence gate
// KEPT — otherwise 60's clear nulls primary_ip4 too, on the strength of
// evidence about a different address.
func TestAProvenClearNeverNullsAPrimaryWhoseOwnClearWasWithheld(t *testing.T) {
	nb, r := addressJoinReconciler(t, leasedIP)
	fingerprint := mustFingerprint(t, r)
	owned := netbox.Identity(fingerprint, "uuid-1", macGuard)
	nb.listIPs = append(nb.listIPs,
		netbox.IPAddress{ID: 50, Address: "10.0.5.202/24", AssignedObjectID: 21, Identity: owned},
		netbox.IPAddress{ID: 60, Address: "2001:db8::60/64", AssignedObjectID: 21, Identity: owned},
	)
	nb.listVMs[0].PrimaryIP4ID, nb.listVMs[0].PrimaryIP6ID = 50, 60
	seedReleasedJoinLease(t, r, "2001:db8::60", 60)

	if err := r.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := cleared(nb); len(got) != 1 || got[0] != 60 {
		t.Fatalf("cleared %v, want only the proven 60", got)
	}
	nb.mu.Lock()
	defer nb.mu.Unlock()
	for _, pc := range nb.primaryClears {
		if pc[1] != 0 {
			t.Fatalf("primary clears %v: primary_ip4 (naming the unproven 50) was nulled", nb.primaryClears)
		}
	}
	if len(nb.primaryClears) != 1 || nb.primaryClears[0] != [3]int{11, 0, 1} {
		t.Fatalf("primary clears = %v, want VM 11's primary_ip6 only", nb.primaryClears)
	}
}

// TestBlockedRemovalsAreNotReportedFromAPassThatWithheldItsRemovals: a pass in
// which a gate withheld destructive actions never attempted the removal a
// finding is about, so it may not report an empty set — that would count as a
// clean pass and clear a block that is still there.
func TestBlockedRemovalsAreNotReportedFromAPassThatWithheldItsRemovals(t *testing.T) {
	nb, r := addressJoinReconciler(t, leasedIP)
	fingerprint := mustFingerprint(t, r)
	// An interface of ours this node holds no record of, tombstone included:
	// its delete is unproven, so the evidence gate withholds it.
	nb.listIfaces = append(nb.listIfaces, netbox.VMInterface{
		ID: 29, VMID: 11, Name: "eth9", MAC: "52:54:00:99:99:99",
		Identity: netbox.Identity(fingerprint, "uuid-1", "52:54:00:99:99:99"),
	})
	var reports int
	r.blockedSink = func(context.Context, map[string]string) { reports++ }

	if err := r.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if reports != 0 {
		t.Fatalf("the blocked-removal set was reported %d time(s) from a pass whose removals were withheld", reports)
	}
}

// TestBlockedRemovalsAreReportedFromAWholePass is the control: a pass with
// nothing withheld reports, so a resolved block can clear.
func TestBlockedRemovalsAreReportedFromAWholePass(t *testing.T) {
	_, r := addressJoinReconciler(t, leasedIP)
	var reports int
	r.blockedSink = func(context.Context, map[string]string) { reports++ }
	if err := r.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if reports != 1 {
		t.Fatalf("reports = %d, want 1 from a pass that withheld nothing", reports)
	}
}

// TestTheSweepUnionsProvenPrimaryClears: with both stale primaries proven,
// every clear the sweep sends for the VM nulls both, in one request each.
func TestTheSweepUnionsProvenPrimaryClears(t *testing.T) {
	nb, r := addressJoinReconciler(t, leasedIP)
	fingerprint := mustFingerprint(t, r)
	owned := netbox.Identity(fingerprint, "uuid-1", macGuard)
	nb.listIPs = append(nb.listIPs,
		netbox.IPAddress{ID: 50, Address: "10.0.5.202/24", AssignedObjectID: 21, Identity: owned},
		netbox.IPAddress{ID: 60, Address: "2001:db8::60/64", AssignedObjectID: 21, Identity: owned},
	)
	nb.listVMs[0].PrimaryIP4ID, nb.listVMs[0].PrimaryIP6ID = 50, 60
	seedReleasedJoinLease(t, r, "10.0.5.202", 50)
	seedReleasedJoinLease(t, r, "2001:db8::60", 60)

	if err := r.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	nb.mu.Lock()
	defer nb.mu.Unlock()
	if len(nb.primaryClears) != 2 {
		t.Fatalf("primary clears = %v, want one per clear", nb.primaryClears)
	}
	for _, pc := range nb.primaryClears {
		if pc != [3]int{11, 1, 1} {
			t.Fatalf("primary clears = %v, want every one to null both of VM 11's primaries", nb.primaryClears)
		}
	}
}
