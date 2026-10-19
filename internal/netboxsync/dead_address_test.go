package netboxsync

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/netbox"
)

// A NetBox address deleted by hand while a lease still names it 404s on every
// assignment. One such object must cost only its own assignment — not the pass.

type deadAddressVirt struct {
	*stubVirt
	dead map[int]bool
	// assignErr, when set, is returned for every assignment that is not dead.
	assignErr error
	// afterClaim runs once an address is created, standing in for what
	// happens between the create and the re-point.
	afterClaim func(netbox.IPAddress)
	// afterLookup runs after every identity lookup has answered, standing in
	// for what happens between that read and whatever the caller does next.
	afterLookup func()
}

func (d *deadAddressVirt) LookupByIdentity(ctx context.Context, identity string, vrfID int, cidr string) ([]netbox.IPAddress, error) {
	found, err := d.stubVirt.LookupByIdentity(ctx, identity, vrfID, cidr)
	if d.afterLookup != nil {
		d.afterLookup()
	}
	return found, err
}

func (d *deadAddressVirt) ClaimSpecificIP(ctx context.Context, address string, vrfID int, identity string) (netbox.IPAddress, error) {
	ip, err := d.stubVirt.ClaimSpecificIP(ctx, address, vrfID, identity)
	if err == nil && d.afterClaim != nil {
		d.afterClaim(ip)
	}
	return ip, err
}

// assignInNetBox records ip as assigned to ifaceID in what an identity lookup
// returns.
func (d *deadAddressVirt) assignInNetBox(identity string, ipID, ifaceID int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for i, ip := range d.byIdentityIPs[identity] {
		if ip.ID == ipID {
			d.byIdentityIPs[identity][i].AssignedObjectID = ifaceID
			d.byIdentityIPs[identity][i].AssignedObjectType = "virtualization.vminterface"
		}
	}
}

func (d *deadAddressVirt) AssignIPToInterface(ctx context.Context, ipID, ifaceID int) error {
	if d.dead[ipID] {
		return &netbox.APIError{Status: http.StatusNotFound, Body: `{"detail":"Not found."}`}
	}
	if d.assignErr != nil {
		return d.assignErr
	}
	return d.stubVirt.AssignIPToInterface(ctx, ipID, ifaceID)
}

func TestApplyDeadAddressAssignmentDoesNotFailThePass(t *testing.T) {
	nb := &deadAddressVirt{stubVirt: &stubVirt{}, dead: map[int]bool{41: true}}
	r := newTestReconciler(t, nb)
	err := r.apply(context.Background(), []Action{
		{Kind: kindNIC, Op: "assign", Key: nicIdent("u1", "52:54:00:00:00:01"), NetBoxID: 21, IPID: 41},
	}, indexDesired(nil, fp), fp)
	if err != nil {
		t.Fatalf("an assignment of a hand-deleted address failed the pass: %v", err)
	}
	if !r.isDeadAddress(41) {
		t.Fatal("the dead address was not recorded, so the pass would report itself converged")
	}
}

func TestApplyOtherAssignmentRefusalsStillFailThePass(t *testing.T) {
	nb := &deadAddressVirt{stubVirt: &stubVirt{},
		assignErr: &netbox.APIError{Status: http.StatusBadRequest, Body: `{"assigned_object_id":["no"]}`}}
	r := newTestReconciler(t, nb)
	err := r.apply(context.Background(), []Action{
		{Kind: kindNIC, Op: "assign", Key: nicIdent("u1", "52:54:00:00:00:01"), NetBoxID: 21, IPID: 41},
	}, indexDesired(nil, fp), fp)
	if err == nil {
		t.Fatal("a 400 on an assignment was swallowed; only a 404 says the address is gone")
	}
	if r.isDeadAddress(41) {
		t.Fatal("a 400 was recorded as a dead address")
	}
}

func TestApplyPrimaryIsNotPointedAtADeadAddress(t *testing.T) {
	nb := &deadAddressVirt{stubVirt: &stubVirt{}, dead: map[int]bool{41: true}}
	r := newTestReconciler(t, nb)
	r.markDeadAddress(41, nicIdent("u1", "52:54:00:00:00:01"))
	if err := r.apply(context.Background(), []Action{
		{Kind: kindVM, Op: opPrimaryIP, Key: vmIdent("u1"), ParentNetBoxID: 11, IPID: 41},
	}, indexDesired(nil, fp), fp); err != nil {
		t.Fatal(err)
	}
	if len(nb.primaryIPs) != 0 {
		t.Fatalf("primary_ip4 was pointed at a dead address: %v", nb.primaryIPs)
	}
}

// ── the repair, once netbox_ip_repoint_v1 has latched ───────────────────────

const (
	repairMAC = "52:54:00:00:00:01"
	repairIP  = "10.0.5.9"
)

// repairFixture is a reconciler over a database holding one bound network and
// one live lease naming address 41, and the desired NIC that lease belongs to.
func repairFixture(t *testing.T, nb *deadAddressVirt) (*Reconciler, desiredIndex, string) {
	t.Helper()
	ctx := context.Background()
	r := newTestReconciler(t, nb)
	if ok, err := corrosion.ClaimBinding(ctx, r.db, corrosion.BindingRecord{
		PrefixID: 7, Network: "bound", ObservedCIDR: "10.0.5.0/24", VRFID: 3, ClusterFingerprint: fp,
	}); err != nil || !ok {
		t.Fatalf("seed binding: ok=%v err=%v", ok, err)
	}
	if err := r.db.Execute(ctx,
		`INSERT INTO ip_allocations
		   (network, ip, mac, vm_name, owner_kind, owner_host,
		    netbox_ip_id, netbox_prefix_id, allocated_at, updated_at)
		 VALUES ('bound', ?, ?, 'vm-1', 'vm', '', 41, 7, ?, ?)`,
		repairIP, repairMAC, r.db.NowWall(), r.db.NowTS()); err != nil {
		t.Fatalf("seed lease: %v", err)
	}
	idx := indexDesired([]DesiredVM{{Name: "vm-1", UUID: "u1", NICs: []DesiredNIC{{
		Name: "eth0", MAC: repairMAC, NetBoxIPID: 41, NetBoxIP: repairIP,
		LeaseNetwork: "bound", LeasePrefixID: 7,
	}}}}, fp)
	return r, idx, nicIdent("u1", repairMAC)
}

func leaseAddressID(t *testing.T, r *Reconciler) int {
	t.Helper()
	leases, err := corrosion.ListNetBoxLeases(context.Background(), r.db)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range leases {
		if l.Network == "bound" && l.IP == repairIP {
			return l.NetBoxIPID
		}
	}
	t.Fatal("the lease is gone")
	return 0
}

func TestRepairWaitsForTheLatch(t *testing.T) {
	// A previous-release peer is listening: no address is created and the
	// lease is not touched — the re-point is a shape that peer cannot decode.
	nb := &deadAddressVirt{stubVirt: &stubVirt{}, dead: map[int]bool{41: true}}
	r, idx, key := repairFixture(t, nb)
	if err := r.apply(context.Background(), []Action{
		{Kind: kindNIC, Op: "assign", Key: key, NetBoxID: 21, IPID: 41},
	}, idx, fp); err != nil {
		t.Fatal(err)
	}
	if len(nb.claimed) != 0 {
		t.Fatalf("an address was re-created before netbox_ip_repoint_v1 latched: %v", nb.claimed)
	}
	if got := leaseAddressID(t, r); got != 41 {
		t.Fatalf("the lease was re-pointed to %d before the latch", got)
	}
	if !r.isDeadAddress(41) {
		t.Fatal("unlatched, the dead address must still be reported")
	}
}

func TestRepairRecreatesAndRepointsOnceLatched(t *testing.T) {
	nb := &deadAddressVirt{stubVirt: &stubVirt{}, dead: map[int]bool{41: true}}
	r, idx, key := repairFixture(t, nb)
	r.db.SetNetBoxRepointGate(func() bool { return true })
	if err := r.apply(context.Background(), []Action{
		{Kind: kindNIC, Op: "assign", Key: key, NetBoxID: 21, IPID: 41},
	}, idx, fp); err != nil {
		t.Fatal(err)
	}
	if len(nb.claimed) != 1 || nb.claimed[0] != [2]string{repairIP + "/24", key} {
		t.Fatalf("re-created %v, want the leased %s/24 under the NIC's identity", nb.claimed, repairIP)
	}
	newID := leaseAddressID(t, r)
	if newID == 41 || newID == 0 {
		t.Fatalf("the lease still names %d after the repair", newID)
	}
	var assigned bool
	for _, a := range nb.ipAssignments {
		if a.IPID == newID && a.IfaceID == 21 {
			assigned = true
		}
	}
	if !assigned {
		t.Fatalf("the re-created address %d was not assigned to interface 21: %v", newID, nb.ipAssignments)
	}
	if r.isDeadAddress(41) {
		t.Fatal("a repaired address was still reported dead")
	}

	// The primary phase follows the repair rather than skipping it.
	if err := r.apply(context.Background(), []Action{
		{Kind: kindVM, Op: opPrimaryIP, Key: vmIdent("u1"), ParentNetBoxID: 11, IPID: 41},
	}, idx, fp); err != nil {
		t.Fatal(err)
	}
	if len(nb.primaryIPs) != 1 || nb.primaryIPs[0] != [2]int{11, newID} {
		t.Fatalf("primary_ip4 writes = %v, want [[11 %d]]", nb.primaryIPs, newID)
	}
}

func TestRepairAdoptsAnObjectAnInterruptedRepairCreated(t *testing.T) {
	nb := &deadAddressVirt{stubVirt: &stubVirt{}, dead: map[int]bool{41: true}}
	r, idx, key := repairFixture(t, nb)
	nb.byIdentityIPs = map[string][]netbox.IPAddress{
		key: {{ID: 77, Address: repairIP + "/24", Identity: key, VRFID: 3}},
	}
	r.db.SetNetBoxRepointGate(func() bool { return true })
	if err := r.apply(context.Background(), []Action{
		{Kind: kindNIC, Op: "assign", Key: key, NetBoxID: 21, IPID: 41},
	}, idx, fp); err != nil {
		t.Fatal(err)
	}
	if len(nb.claimed) != 0 {
		t.Fatalf("created %v although an object with this identity exists", nb.claimed)
	}
	if got := leaseAddressID(t, r); got != 77 {
		t.Fatalf("lease names %d, want the adopted 77", got)
	}
}

func TestRepairKeepsWhatItCreatedWhenTheLeaseMoved(t *testing.T) {
	// The lease no longer names the dead id by the time the re-point runs —
	// released and re-claimed elsewhere. Nothing here names the object this
	// call made, but another leader may yet adopt it, so it is kept for the
	// orphan sweep, and the lease is left as it is.
	nb := &deadAddressVirt{stubVirt: &stubVirt{}, dead: map[int]bool{41: true}}
	r, idx, key := repairFixture(t, nb)
	r.db.SetNetBoxRepointGate(func() bool { return true })
	if err := r.db.Execute(context.Background(),
		`UPDATE ip_allocations SET netbox_ip_id = 55, updated_at = ? WHERE network = 'bound' AND ip = ?`,
		r.db.NowTS(), repairIP); err != nil {
		t.Fatal(err)
	}
	if err := r.apply(context.Background(), []Action{
		{Kind: kindNIC, Op: "assign", Key: key, NetBoxID: 21, IPID: 41},
	}, idx, fp); err != nil {
		t.Fatal(err)
	}
	if got := leaseAddressID(t, r); got != 55 {
		t.Fatalf("lease names %d, want 55 left alone", got)
	}
	if len(nb.claimed) != 1 || len(nb.releasedIPs) != 0 {
		t.Fatalf("claimed %v released %v, want the one created object kept", nb.claimed, nb.releasedIPs)
	}
	if !r.isDeadAddress(41) {
		t.Fatal("an unrepaired address must still be reported dead")
	}
}

func TestRepairCreatesNothingWhereAnyObjectHoldsTheAddress(t *testing.T) {
	// A 404 is not proof the address is free: NetBox also answers it for an
	// object outside the API token's permissions, and a VRF that does not
	// enforce uniqueness would take a second object at the same address. So
	// the address is looked up before the create, and any object there —
	// here an operator's — refuses the repair.
	nb := &deadAddressVirt{stubVirt: &stubVirt{}, dead: map[int]bool{41: true}}
	r, idx, key := repairFixture(t, nb)
	nb.byAddressIPs = map[string][]netbox.IPAddress{
		repairIP: {{ID: 88, Address: repairIP + "/24", VRFID: 3}},
	}
	r.db.SetNetBoxRepointGate(func() bool { return true })
	if err := r.apply(context.Background(), []Action{
		{Kind: kindNIC, Op: "assign", Key: key, NetBoxID: 21, IPID: 41},
	}, idx, fp); err != nil {
		t.Fatal(err)
	}
	if len(nb.claimed) != 0 {
		t.Fatalf("created %v at an address another object holds", nb.claimed)
	}
	if got := leaseAddressID(t, r); got != 41 {
		t.Fatalf("lease re-pointed to %d", got)
	}
	if !r.isDeadAddress(41) {
		t.Fatal("an unrepaired address must still be reported dead")
	}
}

func TestRepairFindsTheAddressUnderAnyMask(t *testing.T) {
	// An operator's 10.0.5.9/32 is the same host as the leased 10.0.5.9/24.
	// The lookup is by host, so it is found and nothing is created over it.
	nb := &deadAddressVirt{stubVirt: &stubVirt{}, dead: map[int]bool{41: true}}
	r, idx, key := repairFixture(t, nb)
	nb.byAddressIPs = map[string][]netbox.IPAddress{
		repairIP: {{ID: 88, Address: repairIP + "/32", VRFID: 3}},
	}
	r.db.SetNetBoxRepointGate(func() bool { return true })
	if err := r.apply(context.Background(), []Action{
		{Kind: kindNIC, Op: "assign", Key: key, NetBoxID: 21, IPID: 41},
	}, idx, fp); err != nil {
		t.Fatal(err)
	}
	if len(nb.claimed) != 0 {
		t.Fatalf("created %v over the same host under another mask", nb.claimed)
	}
}

// A leader hands over while its repair is between the create and the
// re-point. The new leader adopts the created object by identity, re-points
// the lease at it and assigns it; that re-point reaches the old leader, whose
// guarded re-point then misses. A live lease now names the object it created,
// so it is not released.
func TestRepairKeepsWhatItCreatedOnceALeaseNamesIt(t *testing.T) {
	nb := &deadAddressVirt{stubVirt: &stubVirt{}, dead: map[int]bool{41: true}}
	r, idx, key := repairFixture(t, nb)
	r.db.SetNetBoxRepointGate(func() bool { return true })
	nb.afterClaim = func(ip netbox.IPAddress) {
		if err := r.db.Execute(context.Background(),
			`UPDATE ip_allocations SET netbox_ip_id = ?, updated_at = ? WHERE network = 'bound' AND ip = ?`,
			ip.ID, r.db.NowTS(), repairIP); err != nil {
			t.Error(err)
		}
		// Its NetBox assignment has not landed yet.
	}
	if err := r.apply(context.Background(), []Action{
		{Kind: kindNIC, Op: "assign", Key: key, NetBoxID: 21, IPID: 41},
	}, idx, fp); err != nil {
		t.Fatal(err)
	}
	if len(nb.claimed) != 1 {
		t.Fatalf("precondition: claimed %v, want one create", nb.claimed)
	}
	if len(nb.releasedIPs) != 0 {
		t.Fatalf("released %v, an address the live lease names", nb.releasedIPs)
	}
	if got := leaseAddressID(t, r); got == 41 {
		t.Fatal("precondition: the lease was not moved by the other leader")
	}
}

// The same handover seen before the other leader's re-point has replicated
// here: no local lease names the object yet, but NetBox has it assigned. That
// is not proof nothing references it, so it is kept for the orphan sweep.
func TestRepairKeepsWhatItCreatedWhileNetBoxHasItAssigned(t *testing.T) {
	nb := &deadAddressVirt{stubVirt: &stubVirt{}, dead: map[int]bool{41: true}}
	r, idx, key := repairFixture(t, nb)
	r.db.SetNetBoxRepointGate(func() bool { return true })
	nb.afterClaim = func(ip netbox.IPAddress) {
		// The guard misses: the lease moved off the dead id here.
		if err := r.db.Execute(context.Background(),
			`UPDATE ip_allocations SET netbox_ip_id = 55, updated_at = ? WHERE network = 'bound' AND ip = ?`,
			r.db.NowTS(), repairIP); err != nil {
			t.Error(err)
		}
		nb.assignInNetBox(key, ip.ID, 21)
	}
	if err := r.apply(context.Background(), []Action{
		{Kind: kindNIC, Op: "assign", Key: key, NetBoxID: 21, IPID: 41},
	}, idx, fp); err != nil {
		t.Fatal(err)
	}
	if len(nb.claimed) != 1 {
		t.Fatalf("precondition: claimed %v, want one create", nb.claimed)
	}
	if len(nb.releasedIPs) != 0 {
		t.Fatalf("released %v, an address NetBox has assigned", nb.releasedIPs)
	}
}

// The re-point committed, and the read that confirms it failed. The commit is
// not undone by that failure, so the object the lease now names is kept.
func TestRepairKeepsWhatItCreatedWhenTheRepointIsUncertain(t *testing.T) {
	nb := &deadAddressVirt{stubVirt: &stubVirt{}, dead: map[int]bool{41: true}}
	r, idx, key := repairFixture(t, nb)
	r.db.SetNetBoxRepointGate(func() bool { return true })
	r.repointLease = func(ctx context.Context, c *corrosion.Client, network, ip string, fromID, toID int) (bool, error) {
		if moved, err := corrosion.RepointNetBoxLease(ctx, c, network, ip, fromID, toID); err != nil || !moved {
			t.Errorf("precondition: the re-point did not commit: moved=%v err=%v", moved, err)
		}
		return false, fmt.Errorf("confirm re-point: %w", corrosion.ErrNetBoxRepointUnconfirmed)
	}
	if err := r.apply(context.Background(), []Action{
		{Kind: kindNIC, Op: "assign", Key: key, NetBoxID: 21, IPID: 41},
	}, idx, fp); err != nil {
		t.Fatal(err)
	}
	if len(nb.claimed) != 1 {
		t.Fatalf("precondition: claimed %v, want one create", nb.claimed)
	}
	if len(nb.releasedIPs) != 0 {
		t.Fatalf("released %v, the address the committed re-point names", nb.releasedIPs)
	}
	if got := leaseAddressID(t, r); got == 41 {
		t.Fatal("precondition: the lease does not name the new object")
	}
}

// The current leader adopts the object a stale repair created AFTER that
// repair's last read of it: its re-point and its assignment both land between
// the read and anything the stale repair does next. NetBox has no conditional
// delete, so no read can be the last word; the object is never released after
// a missed re-point.
func TestRepairNeverReleasesAfterAMissedRepoint(t *testing.T) {
	nb := &deadAddressVirt{stubVirt: &stubVirt{}, dead: map[int]bool{41: true}}
	r, idx, key := repairFixture(t, nb)
	r.db.SetNetBoxRepointGate(func() bool { return true })
	var created netbox.IPAddress
	nb.afterClaim = func(ip netbox.IPAddress) {
		created = ip
		// The lease moved on: the stale repair's guarded re-point misses.
		if err := r.db.Execute(context.Background(),
			`UPDATE ip_allocations SET netbox_ip_id = 55, updated_at = ? WHERE network = 'bound' AND ip = ?`,
			r.db.NowTS(), repairIP); err != nil {
			t.Error(err)
		}
	}
	lookups := 0
	nb.afterLookup = func() {
		// The first lookup is the repair's adopt-or-create; any after it is a
		// read of the created object, and the adoption lands just after it.
		if lookups++; lookups < 2 || created.ID == 0 {
			return
		}
		nb.assignInNetBox(key, created.ID, 21)
		if err := r.db.Execute(context.Background(),
			`UPDATE ip_allocations SET netbox_ip_id = ?, updated_at = ? WHERE network = 'bound' AND ip = ?`,
			created.ID, r.db.NowTS(), repairIP); err != nil {
			t.Error(err)
		}
	}
	if err := r.apply(context.Background(), []Action{
		{Kind: kindNIC, Op: "assign", Key: key, NetBoxID: 21, IPID: 41},
	}, idx, fp); err != nil {
		t.Fatal(err)
	}
	if len(nb.claimed) != 1 {
		t.Fatalf("precondition: claimed %v, want one create", nb.claimed)
	}
	if len(nb.releasedIPs) != 0 {
		t.Fatalf("released %v, which the current leader adopted", nb.releasedIPs)
	}
}
