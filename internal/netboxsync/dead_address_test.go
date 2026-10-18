package netboxsync

import (
	"context"
	"net/http"
	"testing"

	"github.com/litevirt/litevirt/internal/netbox"
)

// A NetBox address deleted by hand while a lease still names it 404s on every
// assignment. One such object must cost only its own assignment — not the pass.

type deadAddressVirt struct {
	*stubVirt
	dead map[int]bool
	// assignErr, when set, is returned for every assignment that is not dead.
	assignErr error
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
